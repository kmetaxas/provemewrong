package dnsx

import (
	"context"
	"net"
)

// StdlibResolver adapts the standard library's *net.Resolver to the Lookup
// interface, for callers that prefer the system resolver's behavior
// (/etc/hosts, search domains, caching) over dnsx's controlled, observable
// queries.
//
// It cannot expose per-query observability: RCode, TTL and CNAMEs are empty,
// and the Server label is whatever the caller set (or "system"). Note the
// stdlib resolver keeps its own internal 5s per-query timeout and retry
// policy, which is exactly why dnsx exists — this type is for comparison or
// when hosts-file/search-domain handling matters more than timeout control.
type StdlibResolver struct {
	Resolver *net.Resolver // nil -> net.DefaultResolver
	Server   string        // label reported in Result.Server ("system" if empty)
}

// Lookup resolves host via the standard library resolver.
func (s *StdlibResolver) Lookup(ctx context.Context, host string) (Result, error) {
	r := s.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return Result{}, err
	}
	server := s.Server
	if server == "" {
		server = "system"
	}
	return Result{Addrs: addrs, Server: server}, nil
}
