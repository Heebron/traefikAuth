package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
)

var (
	version    = "DEV"
	buildStamp = "DEV"
	gitHash    = "DEV"

	extractor     = regexp.MustCompile(`Subject="CN=(.*)";Issuer="O=(.*)"`)
	currentPolicy *policy
)

type configuration struct {
	SourceCidr []string            `yaml:"source cidr"`
	Org        map[string][]string `yaml:"org"`
	ListenPort int                 `yaml:"listen port"`
	BindAddr   string              `yaml:"bind addr"`
	CacheSize  int                 `yaml:"cache size"`
}

// see https://doc.traefik.io/traefik/middlewares/http/forwardauth/
// https://community.traefik.io/t/how-to-implement-a-forwardauth-service-with-traefik2/3392
func main() {
	port := flag.Int("port", 7980, "upon which TCP port to listen")
	bind := flag.String("bind", "0.0.0.0", "upon which IP address to listen")
	cfgFile := flag.String("config", path.Join(os.Getenv("HOME"), ".traeficForwardAuthConfig.yaml"),
		"configuration file")
	policyFile := flag.String("policy", path.Join(os.Getenv("HOME"), ".traeficForwardAuthPolicy.yaml"),
		"policyMap file")
	vFlag := flag.Bool("version", false, "show the version and quit")
	certFile := flag.String("cert", "", "PEM encoded server cert file")
	keyFile := flag.String("key", "", "PEM encoded unencrypted key file for cert")
	caCerts := flag.String("cacerts", "", "PEM encoded set of trusted issuer certs to add to platform truststore")
	flag.Parse()

	if *vFlag {
		fmt.Printf("traefik PKI forwardAuth service v%s\n", version)
		return
	}

	log.Printf("traefik PKI forwardAuth service")
	log.Printf("version %s", version)
	log.Printf("date built %s", buildStamp)
	log.Printf("git hash %s", gitHash)

	confFile, err := os.Open(*cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	decoder := yaml.NewDecoder(confFile)
	config := configuration{}
	err = decoder.Decode(&config)

	if err != nil {
		log.Printf("could not read configuration file: %s", err.Error())
	}

	var tlsConfig *tls.Config
	if *keyFile != "" && *certFile != "" {
		if tlsConfig, err = initTLS(*certFile, *keyFile, *caCerts); err != nil {
			log.Printf("could not set up TLS: %s", err.Error())
			return
		}
	}

	// load policy
	currentPolicy = processPolicyFile(*policyFile, config.CacheSize)
	if currentPolicy.err != nil {
		log.Printf("can't process policy file '%s: %s", *policyFile, currentPolicy.err.Error())
		return
	}

	changeListener := make(chan *policy)
	go policyFileWatcher(*policyFile, config.CacheSize, changeListener)
	go handlePolicyChanges(changeListener)

	if *port != 0 && *port != config.ListenPort {
		log.Printf("configured listen port %d overridden by command line to %d", config.ListenPort, *port)
		config.ListenPort = *port
	}

	if *bind != "" && *bind != config.BindAddr {
		log.Printf("configured bind address %s overridden by command line to %s", config.BindAddr, *bind)
		config.BindAddr = *bind
	}

	// Start server on port specified above
	bindSpec := fmt.Sprintf("%s:%d", config.BindAddr, config.ListenPort)
	log.Printf("server is listening on '%s'", bindSpec)

	mux := http.ServeMux{}
	mux.HandleFunc("/", requestHandler)
	srv := &http.Server{
		Addr:      bindSpec,
		Handler:   &mux,
		TLSConfig: tlsConfig,
	}

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
