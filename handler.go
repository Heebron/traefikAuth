package main

import (
	"fmt"
	"log"
	net2 "net"
	"net/http"
	"net/url"
	"strings"
)

func requestHandler(w http.ResponseWriter, r *http.Request) {
	proto, ok := r.Header["X-Forwarded-Proto"]

	if !ok || proto[0] != "https" {
		http.Error(w, "not a TLS connection", http.StatusBadRequest)
		return
	}

	serviceName, ok := r.Header["X-Forwarded-Host"] // actual destination
	if !ok {
		http.Error(w, "missing service name (Host header) info", http.StatusBadRequest)
		return
	}

	unescapedList, ok := r.Header["X-Forwarded-Tls-Client-Cert-Info"]

	if !ok {
		http.Error(w, "missing cert info", http.StatusBadRequest)
		return
	}

	unescaped, err := url.QueryUnescape(unescapedList[0])
	if err != nil {
		http.Error(w, fmt.Sprintf("could not decode identity information: %s", err.Error()), http.StatusBadRequest)
		return

	}
	m := extractor.FindStringSubmatch(unescaped)
	// subgroup 1 is the 'CN' (common name)
	// subgroup 2 is the 'O' (org)

	if len(m) != 3 {
		http.Error(w, "could not extract actor 'CN' and/or issuer 'O'", http.StatusBadRequest)
		log.Printf("could not extract identity information from request %s", r.Host)
		return
	}

	// current policy is dynamically updated
	if currentPolicy.isAuthorized(m[2], m[1], serviceName[0]) {
		opsAllowed.Inc()
		return
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
	opsDenied.Inc()
}

func isInCidrSet(ipPort string) bool {
	opsRequests.Inc()
	ip := net2.ParseIP(ipPort[0:strings.Index(ipPort, ":")])
	for _, i := range cidrSet {
		if i.Contains(ip) {
			return true
		}
	}
	log.Printf("unauthorized source address %s", ip.String())
	opsUnauthSource.Inc()
	return false
}

func filterByCIDRFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isInCidrSet(r.RemoteAddr) {
			next(w, r)
			return
		}
		http.Error(w, "unauthorized - source IP not in configured CIDR", http.StatusUnauthorized)
	}
}

func filterByCIDRHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isInCidrSet(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized - source IP not in configured CIDR", http.StatusUnauthorized)
	})
}
