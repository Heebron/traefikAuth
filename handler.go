/*
*
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
	"net/http"
	"net/url"
)

func myApp(w http.ResponseWriter, r *http.Request) {

	proto, ok := r.Header["X-Forwarded-Proto"]

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
		//if verboseFlag {
		//	log.Printf("accepted %s from %s", unescaped, r.Host)
		//}
		return
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
	//log.Printf("rejected %s from %s", unescaped, r.Host)
}
