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
	var ok bool
	var err error
	var proto, host, unescapedList []string
	var unescaped string

	// is the connection to traefik a TLS/SSL connection?
	if proto, ok = r.Header["X-Forwarded-Proto"]; !ok || proto[0] != "https" {
		http.Error(w, "not a secure connection", http.StatusBadRequest)
		return
	}

	// need the host information for SNI matching
	if host, ok = r.Header["X-Forwarded-Host"]; !ok || host[0] == "" {
		http.Error(w, "missing the X-Forwarded-Host header", http.StatusBadRequest)
		return
	}

	// we need the PKI cert info
	if unescapedList, ok = r.Header["X-Forwarded-Tls-Client-Cert-Info"]; !ok || unescapedList[0] == "" {
		http.Error(w, "missing the X-Forwarded-Tls-Client-Cert-Info header", http.StatusBadRequest)
		return
	}

	// replace escape sequences with what they represent
	if unescaped, err = url.QueryUnescape(unescapedList[0]); err != nil {
		http.Error(w, fmt.Sprintf("could not decode identity information: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// grab DN attributes
	m := extractor.FindStringSubmatch(unescaped)

	if len(m) != 5 {
		http.Error(w, "could not extract subject 'CN' and/or issuer 'O'", http.StatusBadRequest)
		log.Printf("could not extract identity information from '%s' provided by host %s", unescaped, r.Host)
		return
	}

	// traefik sometimes reverses the Subject and Issuer
	var cn, o string
	if m[0][0] == 'S' { // S is for "Subject"
		cn, o = m[1], m[2]
	} else {
		cn, o = m[4], m[3]
	}

	// current policy is dynamically updated
	if currentPolicy.isAuthorized(host[0], o, cn) {
		return
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
