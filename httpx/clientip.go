package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPFunc extracts the caller's IP address from a request.
type ClientIPFunc func(*http.Request) string

// TrustedProxyClientIP returns a ClientIPFunc that only believes
// X-Forwarded-For when the direct peer (r.RemoteAddr) is one of the given
// trusted proxy networks (CIDRs such as "127.0.0.1/32" or "10.0.0.0/8"; a
// bare IP is treated as a single-host network). It then walks
// X-Forwarded-For right to left and returns the first address that is not
// itself a trusted proxy. A request that reaches the backend directly, not
// through a trusted proxy, is identified by RemoteAddr alone, so a client
// can't pick its own rate-limit bucket by sending a forged header.
//
// With no trusted proxies, the result is always RemoteAddr. Behind a
// reverse proxy that means every request shares the proxy's address, so
// configure the proxy's address here in any proxied deployment.
func TrustedProxyClientIP(trustedCIDRs []string) (ClientIPFunc, error) {
	var nets []netip.Prefix
	for _, raw := range trustedCIDRs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, addrErr := netip.ParseAddr(s)
			if addrErr != nil {
				return nil, fmt.Errorf("httpx: invalid trusted proxy %q: %w", s, err)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		nets = append(nets, p.Masked())
	}
	trusted := func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		for _, n := range nets {
			if n.Contains(addr) {
				return true
			}
		}
		return false
	}

	return func(r *http.Request) string {
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = r.RemoteAddr
		}
		if len(nets) == 0 || !trusted(peer) {
			return peer
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if _, err := netip.ParseAddr(ip); err == nil && !trusted(ip) {
					return ip
				}
			}
		}
		return peer
	}, nil
}
