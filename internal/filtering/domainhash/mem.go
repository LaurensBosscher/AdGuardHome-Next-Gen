package domainhash

import (
	"bytes"
	"math"
	"os"
	"runtime/debug"
	"strconv"
)

const (
	// DefaultMemBudgetBytes is the memory budget used when the amount of
	// available memory cannot be detected.
	DefaultMemBudgetBytes int64 = 32 << 20

	// MinMemBudgetBytes is the lowest memory budget returned by
	// [DetectMemBudget] and [ResolveMemBudget].
	MinMemBudgetBytes int64 = 8 << 20

	// defaultBatchBytes is the maximum number of bytes the builder buffers in
	// memory before flushing a batch.
	defaultBatchBytes int64 = 16 << 20

	// goMemLimitReserveBytes is left for the rest of the process (DNS caches,
	// urlfilter leftovers, goroutine stacks) when GOMEMLIMIT /
	// debug.SetMemoryLimit caps the builder budget.
	goMemLimitReserveBytes int64 = 32 << 20

	// meminfoPath is the path to the Linux memory information file.
	meminfoPath = "/proc/meminfo"
)

// DetectMemBudget returns the number of bytes that the blocklist builder may
// use for its in-memory batch.  marginBytes is the amount of memory the rest of
// the process is expected to need, and it is subtracted from the amount of
// memory currently available on the system.  If the available memory cannot be
// determined, [DefaultMemBudgetBytes] is returned.  The returned value is never
// less than [MinMemBudgetBytes].
//
// Prefer [ResolveMemBudget] when an absolute cap or [GOMEMLIMIT] should also
// apply.
func DetectMemBudget(marginBytes int64) (budget int64) {
	return ResolveMemBudget(marginBytes, 0)
}

// ResolveMemBudget sizes the builder batch from MemAvailable, an optional
// absolute cap, and the process soft memory limit ([GOMEMLIMIT] /
// [debug.SetMemoryLimit]).
//
//	budget = MemAvailable - marginBytes   (or DefaultMemBudgetBytes)
//	budget = min(budget, absoluteCapBytes) when absoluteCapBytes > 0
//	budget = min(budget, GOMEMLIMIT - reserve) when a memory limit is set
//	budget = max(budget, MinMemBudgetBytes)
//
// absoluteCapBytes is the optional filtering.domain_hash_mem_budget_bytes
// knob; zero means "no absolute cap".  The returned value is never less than
// [MinMemBudgetBytes].
func ResolveMemBudget(marginBytes, absoluteCapBytes int64) (budget int64) {
	if marginBytes < 0 {
		marginBytes = 0
	}

	available, ok := availableMemory()
	if !ok {
		budget = DefaultMemBudgetBytes
	} else {
		budget = available - marginBytes
	}

	if absoluteCapBytes > 0 {
		budget = minPositive(budget, absoluteCapBytes)
	}

	if lim, limited := processMemoryLimit(); limited {
		headroom := lim - goMemLimitReserveBytes
		if headroom < MinMemBudgetBytes {
			headroom = MinMemBudgetBytes
		}
		budget = minPositive(budget, headroom)
	}

	if budget < MinMemBudgetBytes {
		return MinMemBudgetBytes
	}

	return budget
}

// minPositive returns the smaller of a and b, ignoring non-positive a so that
// an absolute / GOMEMLIMIT cap can replace a negative MemAvailable-derived
// budget before the MinMemBudgetBytes floor is applied.
func minPositive(a, b int64) (n int64) {
	if a <= 0 || b < a {
		return b
	}

	return a
}

// processMemoryLimit reports the Go soft memory limit when one is configured
// via GOMEMLIMIT or debug.SetMemoryLimit.  ok is false when no limit is set.
func processMemoryLimit() (n int64, ok bool) {
	// SetMemoryLimit(-1) returns the current limit without changing it.
	lim := debug.SetMemoryLimit(-1)
	if lim < 0 || lim >= math.MaxInt64/2 {
		return 0, false
	}

	return lim, true
}

// availableMemory returns the amount of memory available for new allocations,
// in bytes, as reported by the operating system.  ok is false if it cannot be
// determined.
func availableMemory() (n int64, ok bool) {
	data, err := os.ReadFile(meminfoPath)
	if err != nil {
		return 0, false
	}

	return parseMemAvailable(data)
}

// parseMemAvailable parses the MemAvailable field of the contents of
// /proc/meminfo and returns it in bytes.  ok is false if there is no usable
// MemAvailable field in data.
func parseMemAvailable(data []byte) (n int64, ok bool) {
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}

		rest, found := bytes.CutPrefix(line, []byte("MemAvailable:"))
		if !found {
			continue
		}

		fields := bytes.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}

		kb, err := strconv.ParseInt(string(fields[0]), 10, 64)
		if err != nil || kb <= 0 {
			return 0, false
		}

		return kb * 1024, true
	}

	return 0, false
}
