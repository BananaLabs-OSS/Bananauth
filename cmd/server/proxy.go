package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientAddressKey struct{}

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var proxies []netip.Prefix
	for _, raw := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("BANANAUTH_TRUSTED_PROXY_CIDRS must contain valid CIDRs")
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}

func trustForwardedAddresses(next http.Handler, proxies []netip.Prefix) http.Handler {
	if len(proxies) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, parseErr := netip.ParseAddr(host)
		if err == nil && parseErr == nil && isTrustedProxy(peer, proxies) {
			hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
			for i := len(hops) - 1; i >= 0; i-- {
				hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
				if err != nil {
					break
				}
				if !isTrustedProxy(hop, proxies) {
					r = r.WithContext(context.WithValue(r.Context(), clientAddressKey{}, hop.Unmap().String()))
					break
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isTrustedProxy(address netip.Addr, proxies []netip.Prefix) bool {
	for _, prefix := range proxies {
		if prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}
