package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (

	// register metrics
	opsAllowed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_processed_ops_allowed_total",
		Help: "The total number of allowed requests",
	})
	opsDenied = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_processed_ops_denied_total",
		Help: "The total number of denied requests",
	})
	opsUnauthSource = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_processed_ops_unauth_source_ip_total",
		Help: "The total number of requests from unauthorized networks",
	})
	opsRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_processed_requests_total",
		Help: "The total number of requests",
	})
	opsCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_cache_evictions_total",
		Help: "The total number of entries evicted from cache",
	})
	opsPolicyLoads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_policy_loads_total",
		Help: "The total number of policy file loads",
	})
)
