package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

func requestHandler(w http.ResponseWriter, r *http.Request) {

	proto, ok := r.Header["X-Forwarded-Proto"]

	if !ok || proto[0] != "https" {
		http.Error(w, "not a TLS connection", http.StatusBadRequest)
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
		//if verboseFlag {
		//	log.Printf("accepted %s from %s", unescaped, r.Host)
		//}
		return
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
	//log.Printf("rejected %s from %s", unescaped, r.Host)
}
