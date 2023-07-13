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
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math"
	net2 "net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
)

var (
	version       = "DEV"
	buildStamp    = "DEV"
	extractor     = regexp.MustCompile(`^Subject="CN=(.*?)";Issuer="O=(.*?)"|Issuer="O=(.*?)";Subject="CN=(.*?)"`)
	currentPolicy *policy
	cidrSet       []net2.IPNet
)

// see https://doc.traefik.io/traefik/middlewares/http/forwardauth/
// https://community.traefik.io/t/how-to-implement-a-forwardauth-service-with-traefik2/3392
func main() {
	var err error

	policyFile := flag.String("policy", path.Join(os.Getenv("HOME"), ".traefikForwardAuthPolicy.yaml"),
		"policyMap file")
	vFlag := flag.Bool("version", false, "show the version and quit")
	cacheSize := flag.Int("cacheSize", 53, "identity decision working set size")
	listenPort := flag.Int("listenPort", 7980, "upon which TCP/IP port to listen for traefik connections")
	bindAddr := flag.String("bindAddr", "0.0.0.0", "which network device to bind")
	cidrsFlag := flag.String("cidrs", "", "incoming connections must come from within this list of comma separated CIDRs")
	certFile := flag.String("certFile", "", "pem encoded file containing a X.509 server certificate")
	keyFile := flag.String("keyFile", "", "pem encoded file containing an unencrypted X.509 certificate key")
	caFile := flag.String("caFile", "", "pem encoded file containing X.509 trusted issuer certificates to add to platform truststore")
	flag.Parse()

	if *vFlag {
		fmt.Printf("traefik PKI forwardAuth service v%s\n", version)
		return
	}

	log.Printf("traefik PKI forwardAuth service")
	log.Printf("version %s", version)
	log.Printf("date built %s", buildStamp)

	var tlsConfig *tls.Config
	if *keyFile != "" && *certFile != "" {
		if tlsConfig, err = initTLS(*certFile, *keyFile, *caFile); err != nil {
			log.Printf("could not set up TLS: %s", err.Error())
			return
		}
	}

	// set up CIDR filter
	if *cidrsFlag != "" {
		list := strings.Split(*cidrsFlag, ",")
		for _, i := range list {
			if _, cidr, err := net2.ParseCIDR(i); err != nil {
				log.Printf("can't process CIDR '%s: %s", i, err.Error())
				return
			} else {
				cidrSet = append(cidrSet, *cidr)
			}
		}
	}

	// adjust cache size
	*cacheSize = int(math.Min(53, math.Max(200000, float64(*cacheSize))))

	// load policy
	currentPolicy = processPolicyFile(*policyFile, *cacheSize)
	if currentPolicy.err != nil {
		log.Printf("can't process policy file '%s: %s", *policyFile, currentPolicy.err.Error())
		return
	}

	// register file change listener
	changeListener := make(chan *policy)
	go insertNewPolicy(changeListener)                            // sink for policy changes
	go policyFileWatcher(*policyFile, *cacheSize, changeListener) // file changes
	go signalWatcher(*policyFile, *cacheSize, changeListener)     // SIGUSR1 received

	// Start server on port specified above
	bindSpec := fmt.Sprintf("%s:%d", *bindAddr, *listenPort)
	log.Printf("server is listening on '%s'", bindSpec)

	// set up routes
	mux := http.ServeMux{}
	mux.Handle("/", cidrFilter(http.HandlerFunc(myApp))) // only allow connections from particular IP address range

	// set up server
	srv := &http.Server{Addr: bindSpec, Handler: &mux, TLSConfig: tlsConfig}

	// get'er going
	if tlsConfig != nil {
		log.Print(srv.ListenAndServeTLS("", ""))
	} else {
		log.Print(srv.ListenAndServe())
	}
}

// insertNewPolicy inserts new policy if it different then the current policy.
func insertNewPolicy(updates chan *policy) {
	for {
		e := <-updates // wait for change
		if e.err != nil {
			log.Printf("can't update policy: %s", e.err.Error())
		} else {
			if bytes.Compare(e.hash, currentPolicy.hash) != 0 {
				currentPolicy = e
				log.Print("policy updated and cache flushed")
			} else {
				log.Print("policy unchanged")
			}
		}
	}
}

// signalWatcher responds to a SIGUSR1
func signalWatcher(f string, cacheSize int, updates chan *policy) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1) // SIGUSR1
	for {
		<-sig // wait for it
		log.Println("SIGUSR1 received")
		updates <- processPolicyFile(f, cacheSize)
	}
}
