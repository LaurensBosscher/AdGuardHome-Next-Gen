<!-- TODO(a.garipov):  Update the image and add alt text. -->

<!-- markdownlint-disable first-line-h1 no-alt-text no-inline-html -->

&nbsp;
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="doc/adguard_home_darkmode.svg">
    <img alt="AdGuard Home Next-Gen" src="doc/adguard_home_lightmode.svg" width="300px">
  </picture>
</p>
<h3 align="center">AdGuard Home Next-Gen — experimental, for routers &amp; SBCs</h3>
<p align="center">
  Experimental fork of AdGuard Home: leaner DNS blocklists for low-power devices
  (and faster on big boxes too). Homelab-grade — not for hospitals.
</p>
<p align="center">
  <a href="https://adguard.com/">AdGuard.com</a> |
  <a href="https://github.com/AdguardTeam/AdGuardHome/wiki">Wiki</a> |
  <a href="https://reddit.com/r/Adguard">Reddit</a> |
  <a href="https://twitter.com/AdGuard">Twitter</a> |
  <a href="https://t.me/adguard_en">Telegram</a>
  <br/><br/>
  <a href="https://codecov.io/github/AdguardTeam/AdGuardHome?branch=master">
    <img src="https://img.shields.io/codecov/c/github/AdguardTeam/AdGuardHome/master.svg" alt="Code Coverage"/>
  </a>
  <a href="https://goreportcard.com/report/AdguardTeam/AdGuardHome">
    <img src="https://goreportcard.com/badge/github.com/AdguardTeam/AdGuardHome" alt="Go Report Card"/>
  </a>
  <a href="https://hub.docker.com/r/adguard/adguardhome">
    <img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/adguard/adguardhome.svg?maxAge=604800"/>
  </a>
  <br/>
  <a href="https://github.com/AdguardTeam/AdGuardHome/releases">
    <img src="https://img.shields.io/github/release/AdguardTeam/AdGuardHome/all.svg" alt="Latest release"/>
  </a>
  <a href="https://snapcraft.io/adguard-home">
    <img alt="adguard-home" src="https://snapcraft.io/adguard-home/badge.svg"/>
  </a>
</p>
<br/>
<p align="center">
  <img src="https://cdn.adtidy.org/public/Adguard/Common/adguard_home.gif" width="800"/>
</p>
<hr/>

<!-- markdownlint-enable first-line-h1 no-alt-text no-inline-html -->

## AdGuard Home Next-Gen

> **Experimental fork.** This tree focuses on **low-cost / low-power** hardware
> (routers, OpenStick-class modems, SBCs with roughly **100–512 MiB** RAM) so
> large DNS blocklists (**500k–1M+** domains) stay usable without OOMing on
> filter rebuilds. The same work also **speeds up and shrinks memory use on
> larger machines**.
>
> **Reliability is untested** — here be dragons. Do **not** run this as the DNS
> server for a hospital, airline, or anything life-critical. It is aimed at
> **homelabs** and similar environments where you can recover from surprises.

Fork of upstream [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
(base tag `v1.0.0-b.1`). Domain-hash index inspired by
[esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)
(sorted truncated FNV-1a hashes + binary search).

Write-up:
[AdGuard Home: Next-Gen](https://blog.bosscher.ch/posts/adguard_home_next_gen/)
· Design notes: [docs/NEXTGEN.md](docs/NEXTGEN.md)
· Full tables: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

### Benchmarks (vs upstream urlfilter)

Headline numbers for **1 000 000** synthetic `||domain^` rules on a desktop
(AMD Ryzen AI MAX+ 395, linux/amd64, go1.27.3, `GOMAXPROCS=4`, **2026-11-12**):

| | **urlfilter** (upstream path) | **domainhash** (Next-Gen) |
|---|---:|---:|
| Build | 922 ms | **242 ms** (~3.8× faster) |
| Steady memory | **~149 MiB** RSS (live heap) | **~4.8 MiB** mmap / page cache |
| Warm hit lookup | 2384 ns | **141 ns** (~17× faster) |

Upstream path uses `github.com/AdguardTeam/urlfilter v0.23.4` (same module as
AdGuard Home
[`master` @ `df45d7c0`](https://github.com/AdguardTeam/AdGuardHome/commit/df45d7c097dc172c19557ee29e605bf36b1cd62f)).

#### Scale table

| N | engine | build | RSS Δ | heap Δ | on-disk | warm hit |
|---:|---|---:|---:|---:|---:|---:|
| 100k | urlfilter (upstream) | 57 ms | **22.7 MiB** | 2.1 MiB | — | 725 ns |
| 100k | **domainhash** | **25 ms** | 5.1 MiB* | ~0 | **488 KiB** | **125 ns** |
| 500k | urlfilter | 359 ms | **84.2 MiB** | 10.5 MiB | — | 1461 ns |
| 500k | **domainhash** | **108 ms** | 21.1 MiB* | ~0 | **2.4 MiB** | **131 ns** |
| 1M | urlfilter | 922 ms | **149.3 MiB** | 21.0 MiB | — | 2384 ns |
| 1M | **domainhash** | **242 ms** | 40.4 MiB* | ~0 | **4.8 MiB** | **141 ns** |

* Domainhash RSS Δ right after `Build()` still includes transient builder
scratch. **Steady-state for lookups is the mmap file** (~0.5 / 2.4 / 4.8 MiB
page cache). Urlfilter RSS is live heap and is not reclaimable without dropping
the engine.

Vs the previous Next-Gen desktop numbers (2026-11-01), domainhash **build is
~3.7–6× faster** at the same file sizes. Warm hits stay flat with N; urlfilter
hits still grow with list size. Larger machines see the same wins — less RAM
and faster rebuilds — not only SBCs.

OpenStick estimate (×~12 single-thread factor, 4× A53 @ ~1 GHz): domainhash
build **~0.3 / ~1.3 / ~3 s** for 100k / 500k / 1M.

```bash
GOMAXPROCS=4 go run ./scripts/bench-domainhash -n 100000,500000,1000000 -lookups 20000
```

### What is different from stock AdGuard Home?

| | Stock AdGuard Home | **Next-Gen** |
|---|---|---|
| Simple DNS block rules (`hosts`, `\|\|domain^`) | Full `urlfilter` `NetworkRule` objects (~hundreds of bytes each + shortcut index) | Diverted into a **sorted hash blob** on disk (`blocklist.bin`), **mmap**'d and binary-searched |
| Steady memory for ~1M domains | ~**150 MiB** RSS for the rule engine alone (synthetic, 2026-11-12) | ~**5 MiB** on-disk / page-cache resident index |
| Filter rebuild peak | Often **2–3×** live engine size (old + new + `GOGC`); TI-class lists can spike **hundreds of MiB** | Batched hashing sized from `MemAvailable − margin` (+ optional absolute cap / `GOMEMLIMIT`); rebuild peak stays near the small complex leftover engine |
| Complex / allowlist rules | `urlfilter` | Still `urlfilter` (only rules a hash table cannot express) |
| Lookup I/O | In-memory rule graph | Warm lookups are **RAM-speed** over the kernel **page cache** (not a `read()` per query) |
| Target hardware | Desktops, NAS, Pi-class and up | **Routers / OpenStick / SBCs** first; desktops/NAS still benefit |

Upstream PR
[#8498](https://github.com/AdguardTeam/AdGuardHome/pull/8498)
reduces rebuild peaks for stock urlfilter, but **steady-state still stores every
rule as a rich object**. Next-Gen changes that representation for the common
DNS-block case.

### Alternatives + Comparison

From the
[blog post](https://blog.bosscher.ch/posts/adguard_home_next_gen/):

| | Stock AdGuard Home | AGH Next-Gen | Pi-hole (FTL) | dnsmasq | Blocky | esp32-c3-adblock |
|---|---|---|---|---|---|---|
| Assessment | Delivers the most flexibility when it comes to blocking but has an upper limit. | AGH Features + improved efficiency | Elegant implementation, less functionality than Adguard | Not optimised for blocking. Strength: very reliable + battle tested | Efficient and elegant, limited feature set | Very elegant but limited to the ESP32-C3 hardware |
| Encrypted DNS | Yes (DoH / DoT) | Yes (DoH / DoT) | Yes (DoH / DoT in recent FTL) | No | Yes (DoH / DoT / DoQ) | No |
| Adblock / regex / `$client` | Yes | Yes | Limited | No | Limited | No |
| Memory Usage | 200–300 MB | ~40 MB | ~80 MB (estimate) | ~100 MB (estimate) | tens of MB (scales with lists) | ~50 KB RAM |
| Rebuild | Up to GBs | ~60 MB | ~200 MB (SQLite index rebuild) | N/A | list reload in-process | flash / OTA `blocklist.bin` |
| DHCP | Yes | Yes | Yes (optional) | Yes | No | No (planned) |
| WebUI | Yes | Yes | Yes | No | No (3rd-party UIs only) | Yes |
| Representation | NetworkRule (~296 B) + ShortcutIndex | Truncated FNV hash (5–8 B) in sorted `blocklist.bin` | Full domain string in SQLite `gravity.db`, B-tree index (~32 B/domain in the index, plus the string in the table) | Full hostname in dnsmasq’s in-process hash table | In-memory allow/deny sets (+ regex) | Truncated FNV hash (40-bit) in flash |
| Lookup | 5-gram shortcut → candidates → full `Match()` | Binary search on hashes (+ parent suffixes) | `WHERE domain = ?` on indexed B-tree (+ group/carray) | Hash of hostname → entry | Hash / set membership (+ regex) | Binary search on hashes (+ parent suffixes) |
| Scaling | ~O(windows × bucket) then full match; RSS scales with objects | O(log N), RSS ≈ file size | O(log N) B-tree; Dominik cites ~&lt;5 ms even at ~3M on a Pi when warm | O(1) average hash, but RAM scales linearly with N | O(1)-ish sets; RAM grows with list size | O(log N); flash-bound (~250k–537k domains) |

### Real-life OpenStick usage (2026-11-01)

Device: OpenStick **aarch64**, **465 MiB** RAM, `adguardhome.service` with
`MemoryMax=250M`, Next-Gen binary `v1.0.0-b.1-nextgen-ebc23755`,
`domain_hash_enabled`.

Loaded HaGeZi **Normal / Pro / Ultimate / Threat Intelligence Feeds** on top of
existing filters:

| Stage | Unique hashes | Diverted domains | `blocklist.bin` | Steady RSS | Rebuild peak |
|---|---:|---:|---:|---:|---:|
| Baseline lists | 186k | 186k | 0.89 MiB | ~38 MiB | ~61 MiB |
| Mid (partial TIF) | 1.38M | 1.87M | 6.6 MiB | ~41–62 MiB | ~139 MiB |
| **+ full TIF** | **2.18M** | **2.71M** | **11 MiB** | **~47 MiB** | **~122 MiB** |

Takeaway: hashes **×12**, steady RSS **+~9 MiB**. Rebuild peaks stay under
~140 MiB. DNS blocking verified (`doubleclick.net` → `0.0.0.0`). Complex
urlfilter leftovers stayed at **7** small files; **3** 40-bit collisions on the
full load.

That same TIF-class load is what tends to OOM stock urlfilter on this class of
device.

### Enable on a device

```yaml
filtering:
  domain_hash_enabled: true
  domain_hash_bytes: 5  # 40-bit; use 8 for stricter TI collision policy
  # Optional absolute rebuild batch ceiling (bytes).  0 = auto from
  # MemAvailable - domain_hash_mem_margin_bytes, also capped by GOMEMLIMIT.
  # domain_hash_mem_budget_bytes: 16777216   # 16 MiB
  # domain_hash_mem_margin_bytes: 33554432   # 32 MiB headroom vs MemAvailable
```

Rebuild memory sizing (auto):

1. Start from Linux `MemAvailable − domain_hash_mem_margin_bytes`
2. If `domain_hash_mem_budget_bytes > 0`, take the minimum with that absolute cap
3. If `GOMEMLIMIT` / `debug.SetMemoryLimit` is set, take the minimum with
   `GOMEMLIMIT − 32MiB` reserve (floored at 8 MiB)
4. Floor at 8 MiB; the in-memory batch itself is also capped at 16 MiB

Use **`GOMEMLIMIT`** for “powerful CPU, tight RAM / cgroup” hosts (containers,
OpenStick). Example:

```bash
GOMEMLIMIT=96MiB GOGC=50 ./AdGuardHome
```

Filter-file divert during rebuild uses up to `min(max(GOMAXPROCS-1, 1), 8)`
workers sharing one builder (mutex on append/flush), so worker count follows
CPU while the batch budget follows memory.

AdGuard Home is a network-wide software for blocking ads and tracking. After you set it up, it'll cover ALL your home devices, and you don't need any client-side software for that.

It operates as a DNS server that re-routes tracking domains to a “black hole”, thus preventing your devices from connecting to those servers. It's based on software we use for our public [AdGuard DNS] servers, and both share a lot of code.

[AdGuard DNS]: https://adguard-dns.io/

- [AdGuard Home Next-Gen](#adguard-home-next-gen)
    - [Benchmarks (vs upstream urlfilter)](#benchmarks-vs-upstream-urlfilter)
    - [What is different from stock AdGuard Home?](#what-is-different-from-stock-adguard-home)
    - [Alternatives + Comparison](#alternatives--comparison)
    - [Real-life OpenStick usage (2026-11-01)](#real-life-openstick-usage-2026-11-01)
    - [Enable on a device](#enable-on-a-device)
- [Getting Started](#getting-started)
    - [Automated install (Linux/Unix/MacOS/FreeBSD/OpenBSD)](#automated-install-linux-and-mac)
    - [Alternative methods](#alternative-methods)
    - [Guides](#guides)
    - [API](#api)

Build, contribute, compare-to-Pi-Hole, and other upstream docs live in the
[AdGuard Home README](https://github.com/AdguardTeam/AdGuardHome#readme).

## <a href="#getting-started" id="getting-started" name="getting-started">Getting Started</a>

### <a href="#automated-install-linux-and-mac" id="automated-install-linux-and-mac" name="automated-install-linux-and-mac">Automated install (Linux/Unix/MacOS/FreeBSD/OpenBSD)</a>

To install with `curl` run the following command:

```sh
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```

To install with `wget` run the following command:

```sh
wget --no-verbose -O - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```

To install with `fetch` run the following command:

```sh
fetch -o - https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```

The script also accepts some options:

- `-c <channel>` to use specified channel;
- `-r` to reinstall AdGuard Home;
- `-u` to uninstall AdGuard Home;
- `-v` for verbose output.

Note that options `-r` and `-u` are mutually exclusive.

### <a href="#alternative-methods" id="alternative-methods" name="alternative-methods">Alternative methods</a>

#### <a href="#manual-installation" id="manual-installation" name="manual-installation">Manual installation</a>

Please read the **[Getting Started][wiki-start]** article on our Wiki to learn how to install AdGuard Home manually, and how to configure your devices to use it.

#### <a href="#docker" id="docker" name="docker">Docker</a>

You can use our official Docker image on [Docker Hub].

#### <a href="#snap-store" id="snap-store" name="snap-store">Snap Store</a>

If you're running **Linux,** there's a secure and easy way to install AdGuard Home: get it from the [Snap Store].

[Docker Hub]: https://hub.docker.com/r/adguard/adguardhome
[Snap Store]: https://snapcraft.io/adguard-home
[wiki-start]: https://adguard-dns.io/kb/adguard-home/getting-started/

### <a href="#guides" id="guides" name="guides">Guides</a>

See our [Wiki][wiki].

[wiki]: https://github.com/AdguardTeam/AdGuardHome/wiki

### <a href="#api" id="api" name="api">API</a>

If you want to integrate with AdGuard Home, you can use our [REST API][openapi]. Alternatively, you can use this [python client][pyclient], which can be used to build the [AdGuard Home Assistant integration][assistant-integration].

[assistant-integration]:   https://www.home-assistant.io/integrations/adguard/
[openapi]:  https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi
[pyclient]: https://pypi.org/project/adguardhome/
