package domainhash

import (
	"bufio"
	"container/heap"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
)

const (
	// FileName is the name of the built blocklist file inside
	// [DomainHashConfig.DataDir].
	FileName = "blocklist.bin"

	// hashRecordSize is the size of a single intermediate run record: the
	// little-endian full FNV-1a-64 hash.  Domain names are not stored in runs;
	// truncated-hash collisions are detected from distinct full hashes.
	hashRecordSize = MaxHashBytes

	// recordOverhead is the number of bytes a single domain contributes to the
	// in-memory batch and to a run file.
	recordOverhead = hashRecordSize

	// runBufferSize is the size of the buffered I/O used for intermediate run
	// files.
	runBufferSize = 64 << 10

	// mergeBufferSize is the size of the buffered write used for the final
	// blocklist file.
	mergeBufferSize = 256 << 10

	// maxCollisionSamples is the maximum number of hash collisions kept for
	// reporting.
	maxCollisionSamples = 16
)

var (
	// ErrBadConfig is returned by [NewBuilder] when the configuration is
	// invalid.
	ErrBadConfig = errors.Error("bad domain hash config")

	// ErrBuilderClosed is returned by the methods of a [Builder] after it has
	// been closed.
	ErrBuilderClosed = errors.Error("domain hash builder is closed")

	// errBadRunFile is returned when an intermediate run file is malformed.
	errBadRunFile = errors.Error("malformed run file")
)

// DomainHashConfig is the configuration of the domain-hash blocklist.
type DomainHashConfig struct {
	// Enabled turns the domain-hash blocklist on.
	Enabled bool

	// HashBytes is the number of bytes of a single hash stored in the
	// blocklist.  Zero means [DefaultHashBytes].
	HashBytes int

	// DataDir is the directory that holds the built blocklist file and the
	// intermediate run files.  It must not be empty.
	DataDir string

	// MemBudgetBytes is the maximum number of bytes the builder may buffer in
	// memory before flushing a batch.  Zero means
	// [DefaultMemBudgetBytes].
	MemBudgetBytes int64
}

// batchBytes returns the number of buffered bytes that makes the builder flush
// the current batch into a run file.  The builder never buffers more than
// [defaultBatchBytes].
func (c DomainHashConfig) batchBytes() (n int64) {
	if c.MemBudgetBytes <= 0 {
		return defaultBatchBytes
	}

	return min(c.MemBudgetBytes, defaultBatchBytes)
}

// Stats contains the statistics of a blocklist built by a [Builder].
type Stats struct {
	// Domains is the number of valid domain names accepted by the builder,
	// duplicates included.
	Domains int

	// Skipped is the number of domain names and rules rejected by the
	// builder.
	Skipped int

	// Hashes is the number of unique hashes written to the blocklist file.
	Hashes int

	// Collisions is the number of distinct domain names that map to a hash
	// that another domain name also maps to.
	Collisions int

	// Runs is the number of intermediate run files written.
	Runs int

	// PeakBatchBytes is the peak number of bytes buffered in memory, which
	// gives the peak memory usage of the builder.
	PeakBatchBytes int64
}

// Collision is a truncated-hash collision found while merging runs.  Distinct
// full 64-bit hashes that share a truncated prefix count as a collision; the
// domain names themselves are not retained in the builder.
type Collision struct {
	// Hash is the truncated hash shared by the colliding full hashes.
	Hash uint64
}

// Builder builds a blocklist file from a stream of domain names and rules.
// Public methods are safe for concurrent use by multiple goroutines.
type Builder struct {
	// mu protects the mutable builder state below.
	mu sync.Mutex

	// cfg is the normalized configuration.
	cfg DomainHashConfig

	// dir is the directory that holds the intermediate run files.
	dir string

	// runFiles are the paths of the intermediate run files.
	runFiles []string

	// batch is the full FNV-1a-64 hashes buffered in memory until flushed into
	// a run file.  Capacity is reserved up to the memory budget.
	batch []uint64

	// batchBytes is the current size of the batch in bytes (8 × len(batch)).
	batchBytes int64

	// collisions are the samples of the hash collisions found by the last
	// merge.
	collisions []Collision

	// stats is the statistics of the builder.
	stats Stats

	// closed reports whether the builder has been closed.
	closed bool
}

// NewBuilder creates a new [Builder] that stores its intermediate files in
// cfg.DataDir and writes the final blocklist to FileName inside it.
func NewBuilder(cfg DomainHashConfig) (b *Builder, err error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("%w: empty data directory", ErrBadConfig)
	}

	cfg.HashBytes = ClampHashBytes(cfg.HashBytes)
	if cfg.MemBudgetBytes <= 0 {
		cfg.MemBudgetBytes = DefaultMemBudgetBytes
	}

	if err = os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	dir, err := os.MkdirTemp(cfg.DataDir, "domainhash-runs-")
	if err != nil {
		return nil, fmt.Errorf("creating run directory: %w", err)
	}

	capHint := int(cfg.batchBytes() / hashRecordSize)
	if capHint < 1 {
		capHint = 1
	}

	return &Builder{
		cfg:   cfg,
		dir:   dir,
		batch: make([]uint64, 0, capHint),
	}, nil
}

// Path returns the path to the blocklist file the builder writes to.
func (b *Builder) Path() (p string) {
	return filepath.Join(b.cfg.DataDir, FileName)
}

// AddDomain adds domain to the blocklist.  Invalid domain names are counted in
// [Stats.Skipped] and otherwise ignored.
func (b *Builder) AddDomain(domain string) (err error) {
	_, err = b.addDomain(domain)

	return err
}

// AddDomains adds each of domains to the blocklist.
func (b *Builder) AddDomains(domains []string) (err error) {
	for _, d := range domains {
		if err = b.AddDomain(d); err != nil {
			return err
		}
	}

	return nil
}

// AddLine parses line with [ParseLine] and adds the domain names found in it.
// It returns the number of domains added.  Lines without a supported blocking
// rule are counted in [Stats.Skipped].
func (b *Builder) AddLine(line string) (n int, err error) {
	n, ok, err := b.AddBlockingLine(line)
	if err != nil {
		return n, err
	}
	if !ok {
		b.mu.Lock()
		if !b.closed {
			b.stats.Skipped++
		}
		b.mu.Unlock()
	}

	return n, nil
}

// AddBlockingLine parses line and appends every simple blocking domain hash.
// ok is false when line is not a supported hosts / ||domain^ rule; Skipped is
// not modified in that case so callers can treat the line as complex.
// Valid domains are normalized once.
func (b *Builder) AddBlockingLine(line string) (n int, ok bool, err error) {
	var (
		hashes  [8]uint64
		invalid int
	)

	hs := hashes[:0]
	ok, invalid, hs = collectBlockingHashes(line, hs)
	if !ok {
		return 0, false, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return 0, true, ErrBuilderClosed
	}

	b.stats.Skipped += invalid
	for _, h := range hs {
		if err = b.appendHashLocked(h); err != nil {
			return n, true, err
		}
		n++
	}

	return n, true, nil
}

// collectBlockingHashes extracts full FNV-1a-64 hashes of the simple blocking
// domains in line.  ok is false when line is not a supported blocking rule.
// invalid counts host tokens that failed normalization.
func collectBlockingHashes(line string, dst []uint64) (ok bool, invalid int, hashes []uint64) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "\uFEFF")
	line = strings.TrimSpace(line)
	if line == "" {
		return false, 0, dst
	}

	switch line[0] {
	case '#', '!', '[':
		return false, 0, dst
	}

	if strings.HasPrefix(line, "@@") {
		return false, 0, dst
	}

	var buf [maxDomainLen]byte

	if rest, isAdblock := strings.CutPrefix(line, "||"); isAdblock {
		domain, isRule := parseAdblockDomain(rest)
		if !isRule {
			return false, 0, dst
		}
		norm, isValid := normalizeTo(buf[:], domain)
		if !isValid {
			return false, 0, dst
		}

		return true, 0, append(dst, sum(norm))
	}

	fields := strings.Fields(line)
	if len(fields) < 2 || !isBlockingAddr(fields[0]) {
		return false, 0, dst
	}

	start := len(dst)
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "#") {
			break
		}
		norm, isValid := normalizeTo(buf[:], f)
		if !isValid {
			invalid++
			continue
		}
		dst = append(dst, sum(norm))
	}

	if len(dst) == start && invalid == 0 {
		return false, 0, dst
	}

	return true, invalid, dst
}

// ParseLine extracts the domain names from a single line of a blocklist in
// hosts or adblock syntax.  ok is false if the line has no supported blocking
// rule.  The following kinds of lines are supported:
//
//	0.0.0.0 example.com
//	127.0.0.1	example.com www.example.com  # comment
//	||example.com^
//
// Adblock allowlist rules, rules with modifiers, regular expressions, and
// cosmetic rules are ignored, as are hosts rules for addresses other than
// unspecified and loopback ones.
func ParseLine(line string) (domains []string, ok bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "\uFEFF")
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, false
	}

	switch line[0] {
	case '#', '!', '[':
		return nil, false
	}

	if strings.HasPrefix(line, "@@") {
		return nil, false
	}

	if rest, isAdblock := strings.CutPrefix(line, "||"); isAdblock {
		return parseAdblockRule(rest)
	}

	return parseHostsLine(line)
}

// parseHostsLine extracts the domain names from a hosts-rule line.  ok is false
// if line is not a blocking hosts rule.  Valid domain names are normalized,
// while invalid ones are returned as written, so that the caller can count
// them as skipped.
func parseHostsLine(line string) (domains []string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !isBlockingAddr(fields[0]) {
		return nil, false
	}

	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "#") {
			break
		}

		var buf [maxDomainLen]byte
		if norm, isValid := normalizeTo(buf[:], f); isValid {
			f = string(norm)
		}

		domains = append(domains, f)
	}

	if len(domains) == 0 {
		return nil, false
	}

	return domains, true
}

// parseAdblockRule extracts the domain name from a plain adblock rule, which
// is a domain name optionally followed by the "^" separator.  ok is false if
// rest is not such a rule.
func parseAdblockRule(rest string) (domains []string, ok bool) {
	domain, ok := parseAdblockDomain(rest)
	if !ok {
		return nil, false
	}

	var buf [maxDomainLen]byte
	norm, ok := normalizeTo(buf[:], domain)
	if !ok {
		return nil, false
	}

	return []string{string(norm)}, true
}

// parseAdblockDomain returns the domain part of a plain ||domain[^] rule.
func parseAdblockDomain(rest string) (domain string, ok bool) {
	if strings.ContainsAny(rest, "$/|*#") {
		return "", false
	}

	if i := strings.IndexByte(rest, '^'); i >= 0 {
		if i != len(rest)-1 {
			return "", false
		}
		rest = rest[:i]
	}

	if rest == "" {
		return "", false
	}

	return rest, true
}

// isBlockingAddr reports whether s is an address that hosts files use to block
// domain names, that is, an unspecified or a loopback one.
func isBlockingAddr(s string) (ok bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}

	return addr.IsUnspecified() || addr.IsLoopback()
}

// addDomain adds domain to the batch, flushing the batch if it has grown to
// the configured memory budget.  added is false if domain is invalid.
func (b *Builder) addDomain(domain string) (added bool, err error) {
	var buf [maxDomainLen]byte

	norm, ok := normalizeTo(buf[:], domain)
	if !ok {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return false, ErrBuilderClosed
		}
		b.stats.Skipped++

		return false, nil
	}

	return b.addNormalized(norm)
}

// addNormalized appends the hash of an already-normalized domain to the batch.
func (b *Builder) addNormalized(norm []byte) (added bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return false, ErrBuilderClosed
	}

	if err = b.appendHashLocked(sum(norm)); err != nil {
		return false, err
	}

	return true, nil
}

// appendHashLocked appends a full hash to the batch and flushes when the budget
// is reached.  b.mu must be held.
func (b *Builder) appendHashLocked(h uint64) (err error) {
	b.batch = append(b.batch, h)
	b.batchBytes += recordOverhead
	if b.batchBytes > b.stats.PeakBatchBytes {
		b.stats.PeakBatchBytes = b.batchBytes
	}

	b.stats.Domains++

	if b.batchBytes >= b.cfg.batchBytes() {
		return b.flushBatchLocked()
	}

	return nil
}

// FlushBatch sorts the batch and writes it into a new intermediate run file.
// It is a no-op if the batch is empty.
func (b *Builder) FlushBatch() (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.flushBatchLocked()
}

// flushBatchLocked implements [Builder.FlushBatch].  b.mu must be held.
func (b *Builder) flushBatchLocked() (err error) {
	if b.closed {
		return ErrBuilderClosed
	}

	if len(b.batch) == 0 {
		return nil
	}

	mask := truncMask(b.cfg.HashBytes)
	slices.SortFunc(b.batch, func(a, c uint64) (res int) {
		switch at, ct := a&mask, c&mask; {
		case at < ct:
			return -1
		case at > ct:
			return 1
		case a < c:
			return -1
		case a > c:
			return 1
		default:
			return 0
		}
	})

	path := filepath.Join(b.dir, fmt.Sprintf("run-%06d", len(b.runFiles)))
	if err = writeRun(path, b.batch); err != nil {
		return err
	}

	b.runFiles = append(b.runFiles, path)
	b.batch = b.batch[:0]
	b.batchBytes = 0
	b.stats.Runs = len(b.runFiles)

	return nil
}

// writeRun writes the sorted batch into a new run file at path.
func writeRun(path string, batch []uint64) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating run file %q: %w", path, err)
	}

	err = writeRunRecords(f, batch)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
	}

	if err != nil {
		return err
	}

	if closeErr != nil {
		return fmt.Errorf("closing run file %q: %w", path, closeErr)
	}

	return nil
}

// writeRunRecords writes the batch to f as intermediate run records.
func writeRunRecords(f *os.File, batch []uint64) (err error) {
	w := bufio.NewWriterSize(f, runBufferSize)

	var h [hashRecordSize]byte
	for _, hash := range batch {
		binary.LittleEndian.PutUint64(h[:], hash)
		if _, err = w.Write(h[:]); err != nil {
			return fmt.Errorf("writing run record: %w", err)
		}
	}

	if err = w.Flush(); err != nil {
		return fmt.Errorf("flushing run file: %w", err)
	}

	return nil
}

// MergeRuns merges the intermediate run files into the blocklist file in a
// single pass and renames it over the previous one.  It flushes the remaining
// batch first.  It must not run concurrently with Add* methods.
func (b *Builder) MergeRuns() (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrBuilderClosed
	}

	if err = b.flushBatchLocked(); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(b.cfg.DataDir, FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary blocklist: %w", err)
	}

	tmpPath := tmp.Name()
	finalPath := b.Path()
	renamed := false
	defer func() {
		if renamed {
			return
		}

		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	hashes, collisions, err := b.mergeInto(tmp)
	if err != nil {
		return err
	}

	if err = tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("setting permissions of %q: %w", tmpPath, err)
	}

	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("syncing %q: %w", tmpPath, err)
	}

	if err = tmp.Close(); err != nil {
		return fmt.Errorf("closing %q: %w", tmpPath, err)
	}

	if err = os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("renaming %q to %q: %w", tmpPath, finalPath, err)
	}

	renamed = true

	b.stats.Hashes = hashes
	b.stats.Collisions = collisions

	return nil
}

// mergeInto merges the run files into dst in the order of their truncated
// hashes, deduplicating hashes and recording collisions.
func (b *Builder) mergeInto(dst *os.File) (hashes, collisions int, err error) {
	all := make(runHeap, 0, len(b.runFiles))
	defer func() {
		for _, c := range all {
			_ = c.close()
		}
	}()

	for _, p := range b.runFiles {
		var c *runCursor
		if c, err = openRunCursor(p, b.cfg.HashBytes); err != nil {
			return 0, 0, err
		}

		var ok bool
		if ok, err = c.next(); err != nil {
			_ = c.close()

			return 0, 0, err
		}

		if ok {
			all = append(all, c)
		} else if err = c.close(); err != nil {
			return 0, 0, err
		}
	}

	heap.Init(&all)

	w := bufio.NewWriterSize(dst, mergeBufferSize)

	b.collisions = nil

	var (
		havePrev  bool
		prevTrunc uint64
		prevHash  uint64
		buf       [MaxHashBytes]byte
		hb        = b.cfg.HashBytes
	)

	for all.Len() > 0 {
		c := all[0]
		switch {
		case !havePrev || c.trunc != prevTrunc:
			PutHash(buf[:], c.trunc, hb)
			if _, err = w.Write(buf[:hb]); err != nil {
				return 0, 0, fmt.Errorf("writing blocklist: %w", err)
			}

			hashes++
			havePrev = true
			prevTrunc, prevHash = c.trunc, c.hash
		case c.hash != prevHash:
			// Distinct full hashes that share a truncated prefix are
			// collisions.  Identical full hashes are duplicates of the same
			// domain (or a 2^-64 birthday collision) and are ignored.
			collisions++
			b.collisions = appendCollision(b.collisions, Collision{Hash: c.trunc})
			prevHash = c.hash
		}

		var ok bool
		if ok, err = c.next(); err != nil {
			return 0, 0, err
		}

		if ok {
			heap.Fix(&all, 0)
		} else if err = c.close(); err != nil {
			return 0, 0, err
		} else {
			heap.Pop(&all)
		}
	}

	if err = w.Flush(); err != nil {
		return 0, 0, fmt.Errorf("flushing blocklist: %w", err)
	}

	return hashes, collisions, nil
}

// Build flushes the remaining batch, merges the run files into the blocklist
// file, and removes the intermediate files.
func (b *Builder) Build() (stats Stats, err error) {
	if err = b.MergeRuns(); err != nil {
		return Stats{}, err
	}

	if err = b.Close(); err != nil {
		return Stats{}, err
	}

	return b.stats, nil
}

// Close removes the intermediate files.  It is safe to call it more than once.
func (b *Builder) Close() (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	b.batch = nil
	b.batchBytes = 0

	dir := b.dir
	b.dir = ""

	if dir == "" {
		return nil
	}

	if err = os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing run directory: %w", err)
	}

	return nil
}

// CollisionSamples returns up to maxCollisionSamples of the collisions found by
// the last merge.
func (b *Builder) CollisionSamples() (cs []Collision) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return slices.Clone(b.collisions)
}

// appendCollision appends c to cs unless it is already full.
func appendCollision(cs []Collision, c Collision) (res []Collision) {
	if len(cs) >= maxCollisionSamples {
		return cs
	}

	return append(cs, c)
}

// runCursor reads the records of a single intermediate run file.
type runCursor struct {
	// f is the open run file.
	f *os.File

	// r reads the records of f.
	r *bufio.Reader

	// mask is the mask of the truncated hash.
	mask uint64

	// hash is the full hash of the current record.
	hash uint64

	// trunc is the truncated hash of the current record.
	trunc uint64
}

// openRunCursor opens the run file at path for reading.
func openRunCursor(path string, hashBytes int) (c *runCursor, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening run file %q: %w", path, err)
	}

	return &runCursor{
		f:    f,
		r:    bufio.NewReaderSize(f, runBufferSize),
		mask: truncMask(ClampHashBytes(hashBytes)),
	}, nil
}

// next reads the next record of c.  ok is false if the run file is exhausted.
func (c *runCursor) next() (ok bool, err error) {
	var hdr [hashRecordSize]byte
	if _, err = io.ReadFull(c.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}

		return false, fmt.Errorf("%w: reading the hash: %w", errBadRunFile, err)
	}

	c.hash = binary.LittleEndian.Uint64(hdr[:])
	c.trunc = c.hash & c.mask

	return true, nil
}

// close closes the run file.  It is safe to call it more than once.
func (c *runCursor) close() (err error) {
	if c.f == nil {
		return nil
	}

	f := c.f
	c.f = nil

	return f.Close()
}

// runHeap is a min-heap of run cursors ordered by truncated hash, then full
// hash.
type runHeap []*runCursor

// type check
var _ heap.Interface = (*runHeap)(nil)

// Len implements the [heap.Interface] interface for runHeap.
func (h runHeap) Len() (n int) {
	return len(h)
}

// Less implements the [heap.Interface] interface for runHeap.
func (h runHeap) Less(i, j int) (less bool) {
	a, b := h[i], h[j]
	switch {
	case a.trunc != b.trunc:
		return a.trunc < b.trunc
	default:
		return a.hash < b.hash
	}
}

// Swap implements the [heap.Interface] interface for runHeap.
func (h runHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

// Push implements the [heap.Interface] interface for runHeap.
func (h *runHeap) Push(x any) {
	*h = append(*h, x.(*runCursor))
}

// Pop implements the [heap.Interface] interface for runHeap.
func (h *runHeap) Pop() (x any) {
	old := *h
	n := len(old)
	x = old[n-1]
	old[n-1] = nil
	*h = old[:n-1]

	return x
}
