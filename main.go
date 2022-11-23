package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"math"
	net2 "net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	version    = "DEV"
	buildStamp = "DEV"
	gitHash    = "DEV"

	extractor     = regexp.MustCompile(`Subject="CN=(.*)";Issuer="O=(.*)"`)
	currentPolicy *policy
	cidrSet       []net2.IPNet
	cacheSize     int
)

// see https://doc.traefik.io/traefik/middlewares/http/forwardauth/
// https://community.traefik.io/t/how-to-implement-a-forwardauth-service-with-traefik2/3392
func main() {
	var err error

	policyFile := flag.String("policy", path.Join(os.Getenv("HOME"), ".traeficForwardAuthPolicy.yaml"),
		"policyMap file")
	vFlag := flag.Bool("version", false, "show the version and quit")
	cacheSizeFlag := flag.Int("cacheSize", 53, "identity decision working set size")
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
	log.Printf("git hash %s", gitHash)

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
	cacheSize = int(math.Min(53, math.Max(200000, float64(*cacheSizeFlag))))
	if cacheSize != *cacheSizeFlag {
		log.Printf("cache size adjusted to %d", cacheSize)
	}

	// load policy
	currentPolicy = processPolicyFile(*policyFile)
	if currentPolicy.err != nil {
		log.Printf("can't process policy file '%s: %s", *policyFile, currentPolicy.err.Error())
		return
	}
	opsPolicyLoads.Inc()

	// register file change listener
	changeListener := make(chan *policy)
	go policyFileWatcher(*policyFile, changeListener)
	go handlePolicyChanges(changeListener)

	// Start server on port specified above
	bindSpec := fmt.Sprintf("%s:%d", *bindAddr, *listenPort)
	log.Printf("server is listening on '%s'", bindSpec)

	// set up routes
	mux := http.ServeMux{}
	mux.Handle("/", cidrFilter(http.HandlerFunc(requestHandler)))
	mux.Handle("/metrics", cidrFilter(promhttp.Handler()))

	// set up server
	srv := &http.Server{Addr: bindSpec, Handler: &mux, TLSConfig: tlsConfig}

	// get'er going
	if tlsConfig != nil {
		log.Print(srv.ListenAndServeTLS("", ""))
	} else {
		log.Print(srv.ListenAndServe())
	}
}

func handlePolicyChanges(updates chan *policy) {
	for { // loop forever
		select {
		case e := <-updates:
			if e.err != nil {
				log.Printf("can't update policy: %s", e.err.Error())
			} else {
				if bytes.Compare(e.hash, currentPolicy.hash) != 0 {
					currentPolicy = e // I assume this is atomic
					log.Print("new policy received and cache flushed")
					opsPolicyLoads.Inc()
				}
			}
		}
	}
}

// initTLS allows adding trusted certs to the platform truststore
func initTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	var err error
	var serverCert tls.Certificate
	if serverCert, err = tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, err
	}

	var rootCAs *x509.CertPool
	if rootCAs, err = x509.SystemCertPool(); err != nil {
		return nil, err
	}

	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caFile != "" {
		var caCerts []byte
		caCerts, err = os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}

		// Append our cert set to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caCerts); !ok {
			log.Print("cacerts were not appended")
		}
	}

	return &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{serverCert}, // server cert
		MinVersion:   tls.VersionTLS12,
	}, nil
}
