package domainhash_test

import (
	"runtime"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/domainhash"
	"github.com/stretchr/testify/assert"
)

func TestRebuildWorkers(t *testing.T) {
	prev := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })

	runtime.GOMAXPROCS(1)
	assert.Equal(t, 1, domainhash.RebuildWorkers(), "single proc")

	runtime.GOMAXPROCS(4)
	assert.Equal(t, 3, domainhash.RebuildWorkers(), "four procs")

	runtime.GOMAXPROCS(32)
	assert.Equal(t, domainhash.MaxRebuildWorkers, domainhash.RebuildWorkers(), "capped")
}
