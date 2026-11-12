package domainhash

import "runtime"

const (
	// MaxRebuildWorkers is the maximum number of goroutines used while
	// splitting filter files into the domain-hash builder.  Beyond this,
	// lock and I/O contention typically cancel further gains.
	MaxRebuildWorkers = 8
)

// RebuildWorkers returns how many goroutines should split filter files during
// a domain-hash rebuild: min(max(GOMAXPROCS-1, 1), MaxRebuildWorkers).
func RebuildWorkers() (n int) {
	n = runtime.GOMAXPROCS(0) - 1
	if n < 1 {
		n = 1
	}
	if n > MaxRebuildWorkers {
		n = MaxRebuildWorkers
	}

	return n
}
