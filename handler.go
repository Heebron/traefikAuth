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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	net2 "net"
	"net/http"
	"os"
	"strings"
)

func myApp(w http.ResponseWriter, r *http.Request) {
	var ok bool
	var proto, pemData, host []string
	var cert *x509.Certificate
	var err error
	var der []byte

	// Is the connection to traefik a TLS connection?
	if proto, ok = r.Header["X-Forwarded-Proto"]; !ok || proto[0] != "https" {
		http.Error(w, "not a secure connection", http.StatusBadRequest)
		return
	}

	// We need the host information for SNI matching.
	if host, ok = r.Header["X-Forwarded-Host"]; !ok || host[0] == "" {
		http.Error(w, "missing the X-Forwarded-Host header", http.StatusBadRequest)
		return
	}

	// Grab the cert (PEM format).
	if pemData, ok = r.Header["X-Forwarded-Tls-Client-Cert"]; !ok || pemData[0] == "" {
		// If we don't have a client certificate, check the URI and see if it is whitelisted.

		// debug - planning on supporting X-Forwarded-Uri
		//if uri, ok := r.Header["X-Forwarded-Uri"]; ok {
		//	_, _ = fmt.Fprintln(os.Stderr, "uri = ", uri[0])
		//}
		// end debug

		http.Error(w, "no certificate in the X-Forwarded-Tls-Client-Cert header", http.StatusBadRequest)
		return
	}

	// Remove all but first cert.
	pemData[0], _, _ = strings.Cut(pemData[0], ",")

	// Decode the cert (base64).
	if der, err = base64.StdEncoding.DecodeString(pemData[0]); err != nil {
		http.Error(w, "could not decode PEM data", http.StatusBadRequest)
		_, _ = fmt.Fprintf(os.Stderr, "could not decode PEM data, '%s' from %s\n", err.Error(), r.Host)
		return
	}

	// Parse the cert data.
	if cert, err = x509.ParseCertificate(der); err != nil {
		http.Error(w, "could not parse certificate", http.StatusBadRequest)
		_, _ = fmt.Fprintf(os.Stderr, "could not parse certificate, '%s' from %s\n", err.Error(), r.Host)
		return
	}

	// If authorized, provide TLS offload headers (there is no official standard header set for this).
	if currentPolicy.isAuthorized(host[0], cert.Issuer.Organization[0], cert.Subject.CommonName) {
		w.Header().Add("X-Client-Verify", "SUCCESS") // can't get here if TLS handshake fails between client and traefik
		w.Header().Add("X-Client-Subject", cert.Subject.ToRDNSequence().String())
		w.Header().Add("X-Client-Issuer", cert.Issuer.ToRDNSequence().String())
		w.Header().Add("X-Forwarded-Proto", "https")

		// todo: implement trusted assertion - in the mean time, strip the headers
		w.Header().Add("X-ProxiedEntitiesChain", "")
		w.Header().Add("X-ProxiedIssuersChain", "")

		return // All is well.
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func isInCidrSet(ipPort string) bool {
	lastColon := strings.LastIndex(ipPort, ":")
	ipPart := ipPort[0:lastColon]
	if ipPart[0] == '[' { // IPv6
		ipPart = ipPort[1 : len(ipPart)-1]
	}
	ip := net2.ParseIP(ipPart)
	for _, i := range cidrSet {
		if i.Contains(ip) {
			return true
		}
	}
	fmt.Printf("unauthorized source address %s\n", ip.String())
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
