/*
Copyright (c) 2022 Ken Pratt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package main

import (
	"fmt"
	"log"
	net2 "net"
	"net/http"
	"net/url"
	"strings"
)

func myApp(w http.ResponseWriter, r *http.Request) {

	proto, ok := r.Header["X-Forwarded-Proto"]

	// Is the connection to traefik a TLS/SSL connection?
	if !ok || proto[0] != "https" {
		http.Error(w, "not a secure connection", http.StatusBadRequest)
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
	if currentPolicy.isAuthorized(m[2], m[1]) {
		return
	}

	if verbose {
		log.Printf("escaped:%s", unescapedList[0])
		log.Printf("unescaped:%s", unescaped)
		log.Printf("CN:%s", m[1])
		log.Printf("O:%s", m[2])
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func isInCidrSet(ipPort string) bool {
	ip := net2.ParseIP(ipPort[0:strings.Index(ipPort, ":")])
	for _, i := range cidrSet {
		if i.Contains(ip) {
			return true
		}
	}
	log.Printf("unauthorized source address %s", ip.String())
	return false
}

func cidrFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isInCidrSet(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized - source IP not in configured CIDR", http.StatusUnauthorized)
	})
}
