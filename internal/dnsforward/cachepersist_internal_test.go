package dnsforward

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSCachePersist_RoundTrip(t *testing.T) {
	t.Parallel()

	const host = "persist.example."

	ups := aghtest.NewUpstream()
	ups.OnExchange = func(_ context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
		resp = (&dns.Msg{}).SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    600,
			},
			A: net.IP{192, 0, 2, 10},
		}}

		return resp, nil
	}

	p1, err := proxy.New(&proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		CacheEnabled:   true,
		CacheSizeBytes: 64 * 1024,
	})
	require.NoError(t, err)

	cliAddr := netip.MustParseAddrPort("192.0.2.2:53")
	req := (&dns.Msg{}).SetQuestion(host, dns.TypeA)
	dctx := &proxy.DNSContext{
		Req:  req,
		Addr: cliAddr,
	}
	err = p1.Resolve(testutil.ContextWithTimeout(t, testTimeout), dctx)
	require.NoError(t, err)
	require.NotNil(t, dctx.Res)

	path := filepath.Join(t.TempDir(), "dns_cache.bin")
	n, err := saveProxyDNSCacheCount(path, p1)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	p2, err := proxy.New(&proxy.Config{
		Logger: testLogger,
		UpstreamConfig: &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{ups},
		},
		CacheEnabled:   true,
		CacheSizeBytes: 64 * 1024,
	})
	require.NoError(t, err)

	loaded, err := loadProxyDNSCache(path, p2)
	require.NoError(t, err)
	assert.Equal(t, 1, loaded)

	// Second resolve should be served from the restored cache without hitting
	// the upstream again.
	ups.OnExchange = func(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
		t.Fatal("upstream should not be called for cached answer")

		return nil, nil
	}

	dctx2 := &proxy.DNSContext{
		Req:  (&dns.Msg{}).SetQuestion(host, dns.TypeA),
		Addr: cliAddr,
	}
	err = p2.Resolve(testutil.ContextWithTimeout(t, testTimeout), dctx2)
	require.NoError(t, err)
	require.NotNil(t, dctx2.Res)
	require.NotEmpty(t, dctx2.Res.Answer)
}
