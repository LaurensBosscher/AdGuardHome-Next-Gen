# Benchmarks: upstream urlfilter vs Next-Gen domainhash

Synthetic `||domain^` lists (same shape as typical DNS blocklists). Harness:

```bash
go run ./scripts/bench-domainhash -n 100000,500000,1000000
```

Go microbenchmarks:

```bash
go test ./internal/filtering/domainhash/ -bench . -benchmem
go test ./internal/filtering/ -bench 'BenchmarkCompare' -benchmem
```

## Does every lookup hit the disk?

**No — not once the working set is warm.**

The index is opened with `mmap(PROT_READ, MAP_SHARED)`. Linux does **not**
eagerly copy the whole file into RAM. It maps the file into the process address
space and faults pages (~4 KiB) into the **page cache** on first access.

| Situation | What happens |
|---|---|
| Cold start / first lookups | Minor page faults; pages read from storage into page cache |
| Steady DNS load, RAM available | Binary search touches ~`log2(N)` cache lines; pages stay resident → **RAM-speed lookups, no syscall I/O** |
| Memory pressure | Kernel can reclaim clean mmap pages; next touch faults them back in |
| Full file warm (1M × 5 B ≈ 4.8 MiB) | Entire blob fits easily even on ~100 MiB routers |

So: storage-backed, **page-cache resident when the OS can afford it**, not a
`read()` per DNS query. Under reclaim, you pay occasional faults — still cheap
versus upstream RTT.

## Measured on a desktop (2026-11-12)

Host: AMD Ryzen AI MAX+ 395, linux/amd64, go1.27.3, `GOMAXPROCS=4`
(OpenStick-like core count; this CPU is far faster per core than an A53).

Comparison baseline: stock-style **urlfilter** path using
`github.com/AdguardTeam/urlfilter v0.23.4` (same module as AdGuard Home
[`master` @ `df45d7c0`](https://github.com/AdguardTeam/AdGuardHome/commit/df45d7c097dc172c19557ee29e605bf36b1cd62f)).
Next-Gen column is the hash-only builder after the 2026-11-12 work
(hash-only batches / runs, single-normalize ingest, mutex-safe builder).

Harness:

```bash
GOMAXPROCS=4 go run ./scripts/bench-domainhash -n 100000,500000,1000000 -lookups 20000
```

### Build + memory (engines measured separately)

| N | Engine | Build | RSS Δ | Heap Δ | On-disk file |
|---:|---|---:|---:|---:|---:|
| 100,000 | **urlfilter** (upstream path) | 57.2 ms | **22.7 MiB** | 2.1 MiB | — |
| 100,000 | **domainhash** (Next-Gen) | **24.7 ms** | 5.1 MiB* | ~0 | **488 KiB** |
| 500,000 | urlfilter | 358.6 ms | **84.2 MiB** | 10.5 MiB | — |
| 500,000 | domainhash | **108.0 ms** | 21.1 MiB* | ~0 | **2.4 MiB** |
| 1,000,000 | urlfilter | 921.8 ms | **149.3 MiB** | 21.0 MiB | — |
| 1,000,000 | domainhash | **242.3 ms** | 40.4 MiB* | ~0 | **4.8 MiB** |

* Domainhash RSS Δ right after `Build()` still includes transient builder
scratch the OS has not fully reclaimed. **True steady-state for lookups is the
mmap file size** (page cache), i.e. ~0.5 / 2.4 / 4.8 MiB — reclaimable under
pressure. Urlfilter RSS is live heap objects and is **not** reclaimable without
dropping the engine.

Vs 2026-11-01 Next-Gen on the same host: domainhash build **~3.7–6× faster**
(146/582/921 ms → 25/108/242 ms); post-build RSS Δ for 1M dropped **72 → 40 MiB**
(transient). File sizes unchanged.

### Warm lookup latency

| N | Engine | hit | miss | parent hit |
|---:|---|---:|---:|---:|
| 100,000 | urlfilter | 725 ns | 256 ns | 830 ns |
| 100,000 | domainhash | **125 ns** | **193 ns** | **205 ns** |
| 500,000 | urlfilter | 1461 ns | 255 ns | 2081 ns |
| 500,000 | domainhash | **131 ns** | **226 ns** | **222 ns** |
| 1,000,000 | urlfilter | 2384 ns | 245 ns | 3685 ns |
| 1,000,000 | domainhash | **141 ns** | **241 ns** | **237 ns** |

Domainhash stays well under a microsecond and almost flat with N (`O(log N)`).
Urlfilter hit/parent cost still grows with list size (shortcut index + rule
objects).

### Microbenchmarks (builder)

`go test ./internal/filtering/domainhash/ -bench BenchmarkBuilder -benchtime=3x -benchmem`
on the same host (`GOMAXPROCS=32`): peak batch for 1M / 16 MiB budget is exactly
**8 000 000 bytes** (1M × 8 B hashes) with a **single** run — confirming the
hash-only batch accounting.

## OpenStick estimates (4× Cortex-A53 @ ~1 GHz)

Not re-measured on-device after the 2026-11-12 builder changes. Scaled from the
`GOMAXPROCS=4` desktop numbers above with a **~12×** single-thread factor
(A53 @ 1 GHz vs this Zen desktop for Go/integer work). The synthetic harness
hashes one list serially; AGH filter divert can also use
`min(max(GOMAXPROCS-1, 1), 8)` workers across list files.

| N | domainhash build (estimate) | domainhash warm lookup (estimate) | urlfilter RSS (order of magnitude) | domainhash steady file |
|---:|---:|---:|---:|---:|
| 100,000 | **~0.3 s** | ~2–3 µs | ~23 MiB | 0.5 MiB |
| 500,000 | **~1.3 s** | ~2–3 µs | ~84 MiB | 2.4 MiB |
| 1,000,000 | **~3 s** | ~2–3 µs | ~150 MiB | 4.8 MiB |

Notes:

- Lookup estimates remain **≪ typical DNS upstream RTT** (milliseconds).
- Urlfilter at 500k–1M is why ~100 MiB routers OOM on rebuild (old+new engine
  ≈ 2× RSS, plus `GOGC` headroom → ~3× peak). Domainhash rebuild peak is
  bounded by `ResolveMemBudget` (`MemAvailable`, optional absolute cap,
  `GOMEMLIMIT`).
- Re-run on the OpenStick to replace estimates:

  ```bash
  GOMAXPROCS=4 go run ./scripts/bench-domainhash -n 100000,500000,1000000
  ```

## OpenStick live scale-up (2026-11-01)

Device: OpenStick aarch64, 465 MiB RAM, `adguardhome.service` with
`MemoryMax=250M` (raised from 150M for rebuild headroom). Next-Gen binary,
`domain_hash_enabled`.

Added HostlistsRegistry lists on top of the existing enabled filters:

| Stage | Added list | List lines (approx) |
|---|---|---:|
| 0 | (baseline only) | — |
| 1 | HaGeZi Normal (`filter_34`) | ~176k |
| 2 | + HaGeZi Pro (`filter_48`) | ~212k |
| 3 | + HaGeZi Ultimate (`filter_49`) | ~283k |
| 4 | + HaGeZi Threat Intelligence Feeds (`filter_44`) | ~1.85M |

### Measured on device

| Stage | Unique hashes | Diverted domains | `blocklist.bin` | Steady RSS | Rebuild peak RSS |
|---|---:|---:|---:|---:|---:|
| 0 baseline | **185,994** | 186,053 | 0.89 MiB | ~38 MiB | ~61 MiB |
| mid (TIF truncated*) | **1,379,839** | 1,867,394 | 6.6 MiB | ~41–62 MiB | ~139 MiB |
| 4 + full TIF | **2,184,149** | 2,708,009 | **11 MiB** | **~47 MiB** | **~122 MiB** |

* Mid-point while `filter_44` was only partially on disk; kept as a scale
sample. Full load collisions: **3** (40-bit). Complex urlfilter leftovers
stayed at **7** small files.

### Takeaway

Steady RSS barely moves (~38 → ~47 MiB) while hashes grow **~12×**
(186k → 2.18M). Rebuild peaks stay under ~140 MiB (16 MiB batch cap). The
same TIF-class load is what OOMs stock urlfilter here.

## How to reproduce

```bash
# Comparative RSS + lookup table (used above)
go run ./scripts/bench-domainhash -n 100000,500000,1000000 -lookups 20000

# Package microbenchmarks
go test ./internal/filtering/domainhash/ -bench BenchmarkBuilder -benchtime=3x -benchmem
go test ./internal/filtering/domainhash/ -bench BenchmarkContainsDomain -benchmem
go test ./internal/filtering/ -run TestCompareSteadyStateMemory -v
```
