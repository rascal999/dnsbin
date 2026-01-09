package utils

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func QueryTTL(query, resolver string) (int, error) {
	host, _, _ := net.SplitHostPort(resolver)
	if host == "" {
		host = resolver
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "53")
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(query), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, host)
	if err != nil {
		return 0, err
	}

	if len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			return int(ans.Header().Ttl), nil
		}
	}

	if len(r.Ns) > 0 {
		for _, ns := range r.Ns {
			return int(ns.Header().Ttl), nil
		}
	}

	return 0, fmt.Errorf("TTL not found in response")
}

func TriggerQuery(query, resolver string) {
	host, _, _ := net.SplitHostPort(resolver)
	if host == "" {
		host = resolver
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "53")
	}

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(query), dns.TypeA)
	
	// We don't care about the result, just triggering the query
	c.Exchange(m, host)
}