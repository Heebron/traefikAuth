package main

import (
	"bytes"
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
	vFlag := flag.Bool("version", false, "show the version")
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
		log.Fatal(err)
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

	// register the policy handler
	http.HandleFunc("/", myApp)

	// Start server on port specified above
	bindSpec := fmt.Sprintf("%s:%d", config.BindAddr, config.ListenPort)
	log.Printf("server is listening on '%s'", bindSpec)
	log.Print(http.ListenAndServe(bindSpec, nil))
}

func handlePolicyChanges(updates chan *policy) {
	for {
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
