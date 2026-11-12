package filtering

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/domainhash"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

// domainHashDirName is the subdirectory of DataDir that holds the built
// domain-hash blocklist and the complex-rule leftovers that still go through
// urlfilter.
const domainHashDirName = "domainhash"

// domainHashComplexPrefix is the filename prefix of the complex-rule leftovers.
const domainHashComplexPrefix = "complex-"

// domainHashHitRule is the static ResultRule text used for domain-hash hits so
// matchDomainHashHost does not allocate a per-query "domainhash:"+host string.
const domainHashHitRule = "domainhash"

// buildDomainHashIndex streams blockFilters, diverts simple hosts / ||domain^
// rules into a disk-backed hash index, and returns the leftover complex rules
// as a new filter slice for urlfilter.  When domain-hash indexing is disabled,
// it returns the original filters and a nil index.
func (d *DNSFilter) buildDomainHashIndex(
	ctx context.Context,
	blockFilters []Filter,
) (complexFilters []Filter, idx *domainhash.Index, err error) {
	if d == nil || d.conf == nil || !d.conf.DomainHashEnabled {
		return blockFilters, nil, nil
	}

	dataDir := filepath.Join(d.conf.DataDir, domainHashDirName)
	if err = os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating domainhash directory: %w", err)
	}

	margin := d.conf.DomainHashMemMarginBytes
	if margin <= 0 {
		margin = domainhash.DefaultMemBudgetBytes
	}

	budget := domainhash.ResolveMemBudget(margin, d.conf.DomainHashMemBudgetBytes)
	hashBytes := d.conf.DomainHashBytes

	b, err := domainhash.NewBuilder(domainhash.DomainHashConfig{
		Enabled:        true,
		HashBytes:      hashBytes,
		DataDir:        dataDir,
		MemBudgetBytes: budget,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating domainhash builder: %w", err)
	}
	defer func() { _ = b.Close() }()

	workers := domainhash.RebuildWorkers()
	complexFilters, diverted, err := d.splitFiltersForDomainHash(ctx, b, dataDir, blockFilters, workers)
	if err != nil {
		return nil, nil, err
	}

	stats, err := b.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("building domainhash index: %w", err)
	}

	idx, err = domainhash.Open(b.Path(), hashBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("opening domainhash index: %w", err)
	}

	d.logger.InfoContext(
		ctx,
		"domainhash index ready",
		"hashes", stats.Hashes,
		"domains", stats.Domains,
		"diverted_lines", diverted,
		"collisions", stats.Collisions,
		"runs", stats.Runs,
		"peak_batch_bytes", stats.PeakBatchBytes,
		"mem_budget_bytes", budget,
		"workers", workers,
		"complex_filters", len(complexFilters),
	)

	if stats.Collisions > 0 {
		d.logger.WarnContext(
			ctx,
			"domainhash collisions (over-block risk)",
			"collisions", stats.Collisions,
			"samples", b.CollisionSamples(),
		)
	}

	return complexFilters, idx, nil
}

// splitFiltersForDomainHash splits blockFilters into the shared builder using
// up to workers goroutines.  Each filter's complex leftovers are written to a
// dedicated file.
func (d *DNSFilter) splitFiltersForDomainHash(
	ctx context.Context,
	b *domainhash.Builder,
	dataDir string,
	blockFilters []Filter,
	workers int,
) (complexFilters []Filter, diverted int, err error) {
	if len(blockFilters) == 0 {
		return nil, 0, nil
	}

	if workers < 1 {
		workers = 1
	}
	if workers > len(blockFilters) {
		workers = len(blockFilters)
	}

	type result struct {
		cf  *Filter
		n   int
		err error
	}

	results := make([]result, len(blockFilters))
	jobs := make(chan int, len(blockFilters))
	for i := range blockFilters {
		jobs <- i
	}
	close(jobs)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := workerCtx.Err(); err != nil {
					results[i] = result{err: err}

					continue
				}

				cf, n, splitErr := d.splitFilterForDomainHash(
					workerCtx,
					b,
					dataDir,
					blockFilters[i],
				)
				results[i] = result{cf: cf, n: n, err: splitErr}
				if splitErr != nil {
					cancel()
				}
			}
		}()
	}
	wg.Wait()

	complexFilters = make([]Filter, 0, len(blockFilters))
	var errs []error
	for i, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("filter %d: %w", blockFilters[i].ID, r.err))
			continue
		}
		diverted += r.n
		if r.cf != nil {
			complexFilters = append(complexFilters, *r.cf)
		}
	}
	if len(errs) > 0 {
		return nil, 0, errors.Join(errs...)
	}

	return complexFilters, diverted, nil
}

// splitFilterForDomainHash writes simple blocking rules from f into b and the
// remaining lines into a complex leftover file.  n is the number of lines
// diverted into the hash builder.  cf is nil when nothing remains for
// urlfilter.
func (d *DNSFilter) splitFilterForDomainHash(
	ctx context.Context,
	b *domainhash.Builder,
	dataDir string,
	f Filter,
) (cf *Filter, n int, err error) {
	r, closer, err := openFilterReader(f)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = closer.Close() }()

	complexPath := filepath.Join(
		dataDir,
		fmt.Sprintf("%s%d.txt", domainHashComplexPrefix, f.ID),
	)
	out, err := os.Create(complexPath)
	if err != nil {
		return nil, 0, fmt.Errorf("creating complex filter %q: %w", complexPath, err)
	}
	defer func() { _ = out.Close() }()

	bw := bufio.NewWriterSize(out, 64<<10)
	br := bufio.NewReaderSize(r, 64<<10)

	var complexLines int
	for {
		if err = ctx.Err(); err != nil {
			return nil, n, err
		}

		line, readErr := br.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			// Fall back to allocating for oversize lines.
			rest, restErr := br.ReadString('\n')
			lineStr := string(line) + rest
			readErr = restErr
			trimmed := strings.TrimRight(lineStr, "\r\n")
			added, keep, lineErr := d.consumeFilterLine(b, f.ID, trimmed, lineStr, bw)
			if lineErr != nil {
				return nil, n, lineErr
			}
			if added {
				n++
			}
			if keep {
				complexLines++
			}
		} else if len(line) > 0 {
			trimmed := string(bytes.TrimRight(line, "\r\n"))
			added, keep, lineErr := d.consumeFilterLine(b, f.ID, trimmed, string(line), bw)
			if lineErr != nil {
				return nil, n, lineErr
			}
			if added {
				n++
			}
			if keep {
				complexLines++
			}
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, n, fmt.Errorf("reading filter %d: %w", f.ID, readErr)
		}
	}

	if err = bw.Flush(); err != nil {
		return nil, n, fmt.Errorf("flushing complex filter: %w", err)
	}

	if complexLines == 0 {
		_ = os.Remove(complexPath)
		d.logger.DebugContext(ctx, "filter fully diverted to domainhash", "filter_id", f.ID, "lines", n)

		return nil, n, nil
	}

	return &Filter{ID: f.ID, FilePath: complexPath}, n, nil
}

// consumeFilterLine diverts a simple blocking line into b or writes a complex
// leftover.  added is true when the line was a simple blocking rule; keep is
// true when the original line was written to the complex leftover writer.
func (d *DNSFilter) consumeFilterLine(
	b *domainhash.Builder,
	filterID rules.ListID,
	trimmed string,
	rawLine string,
	bw *bufio.Writer,
) (added, keep bool, err error) {
	n, ok, addErr := b.AddBlockingLine(trimmed)
	if addErr != nil {
		return false, false, fmt.Errorf("adding domain from filter %d: %w", filterID, addErr)
	}
	if ok {
		_ = n

		return true, false, nil
	}

	if !keepComplexLine(trimmed) {
		return false, false, nil
	}

	if _, err = bw.WriteString(rawLine); err != nil {
		return false, false, fmt.Errorf("writing complex filter: %w", err)
	}
	if !strings.HasSuffix(rawLine, "\n") && !strings.HasSuffix(rawLine, "\r\n") {
		if err = bw.WriteByte('\n'); err != nil {
			return false, false, fmt.Errorf("writing complex filter newline: %w", err)
		}
	}

	return false, true, nil
}

// openFilterReader returns a reader over the filter contents.  closer must be
// closed by the caller.
func openFilterReader(f Filter) (r io.Reader, closer io.Closer, err error) {
	if len(f.Data) != 0 {
		br := bytes.NewReader(f.Data)

		return br, io.NopCloser(br), nil
	}

	if f.FilePath == "" {
		br := bytes.NewReader(nil)

		return br, io.NopCloser(br), nil
	}

	file, err := os.Open(f.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			br := bytes.NewReader(nil)

			return br, io.NopCloser(br), nil
		}

		return nil, nil, fmt.Errorf("opening filter %q: %w", f.FilePath, err)
	}

	return file, file, nil
}

// keepComplexLine reports whether line should stay in the urlfilter engine.
// Empty lines and comments are dropped; everything ParseLine rejected that is
// still a rule (including @@ allow exceptions and $modifier rules) is kept.
func keepComplexLine(line string) (ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}

	switch line[0] {
	case '#', '!', '[':
		return false
	}

	return true
}

// closeDomainHashIndex closes the current domain-hash index, if any.
func (d *DNSFilter) closeDomainHashIndex(ctx context.Context) {
	if d.domainHashIndex == nil {
		return
	}

	err := d.domainHashIndex.Close()
	if err != nil {
		d.logger.ErrorContext(ctx, "closing domainhash index", slogutil.KeyError, err)
	}

	d.domainHashIndex = nil
	d.domainHashOnlyBlocks = false
}

// logDomainHashDisabled emits a debug line when the feature is off.
func logDomainHashDisabled(ctx context.Context, l *slog.Logger) {
	if l == nil {
		return
	}

	l.DebugContext(ctx, "domainhash index disabled")
}

// matchDomainHashHost reports whether host is blocked by the domain-hash index.
func (d *DNSFilter) matchDomainHashHost(
	ctx context.Context,
	host string,
	setts *Settings,
) (res Result, ok bool) {
	if !setts.ProtectionEnabled || d.domainHashIndex == nil {
		return Result{}, false
	}

	if !d.domainHashIndex.ContainsDomain(host) {
		return Result{}, false
	}

	d.logger.DebugContext(ctx, "domainhash matched host", "host", host)

	return Result{
		Rules: []*ResultRule{{
			Text: domainHashHitRule,
		}},
		Reason:     FilteredBlockList,
		IsFiltered: true,
	}, true
}

// prepareDomainHashBlocks builds the domain-hash index when enabled and returns
// the leftover complex block filters for urlfilter.  When disabled, it returns
// the original filters unchanged.
func (d *DNSFilter) prepareDomainHashBlocks(
	ctx context.Context,
	blockFilters []Filter,
) (complexBlockFilters []Filter, domainIdx *domainhash.Index, err error) {
	if d.conf == nil || !d.conf.DomainHashEnabled {
		logDomainHashDisabled(ctx, d.logger)

		return blockFilters, nil, nil
	}

	complexBlockFilters, domainIdx, err = d.buildDomainHashIndex(ctx, blockFilters)
	if err != nil {
		return nil, nil, fmt.Errorf("domainhash: %w", err)
	}

	return complexBlockFilters, domainIdx, nil
}
