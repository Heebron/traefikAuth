package main

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	lru2 "github.com/hashicorp/golang-lru/v2"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"regexp"
)

type policyMap []struct {
	ServiceName string   `yaml:"service name"`
	O           string   `yaml:"o"`
	CN          []string `yaml:"cn"`
}

type compEntry struct {
	serviceName *regexp.Regexp
	o           *regexp.Regexp
	cn          []*regexp.Regexp
}

type policy struct {
	err   error // carry any errors processing a policy file
	cache *lru2.Cache[string, bool]
	hash  []byte

	// compiled regex
	comparators []compEntry
}

func policyFileWatcher(f string, c chan<- *policy) {
	// set up the policyMap file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		c <- &policy{err: err}
		return
	}
	defer func() { _ = watcher.Close() }()

	if err = watcher.Add(f); err != nil {
		c <- &policy{err: err}
		return
	}

	// all set
	log.Printf("watching policy file '%s' for changes", f)
	for {
		// now listen for file changes
		select {
		case _ = <-watcher.Events: // wait for file event.
			c <- processPolicyFile(f)
		case err := <-watcher.Errors:
			c <- &policy{err: err}
		}
	}
}

func processPolicyFile(f string) *policy {
	if p, err := loadPolicy(f); err != nil {
		return &policy{err: err}
	} else {
		newPolicy := compilePolicy(p)
		if newPolicy.err != nil {
			return newPolicy // return on error
		} else if newLRU, err := lru2.NewWithEvict[string, bool](cacheSize, func(k string, v bool) {
			log.Printf("key %s evicted from cache", k)
			opsCacheEvictions.Inc()
		}); err != nil {
			return &policy{err: err}
		} else {
			newPolicy.cache = newLRU
			return newPolicy
		}
	}
}

func loadPolicy(f string) (policyMap, error) {
	confFile, err := os.Open(f)

	if err != nil {
		return policyMap{}, err
	}

	decoder := yaml.NewDecoder(confFile)
	policy := policyMap{}
	err = decoder.Decode(&policy)
	_ = confFile.Close()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func compilePolicy(p policyMap) *policy {
	newPolicy := &policy{}
	h := sha1.New()
	for i, value := range p {
		if len(value.CN) == 0 {
			continue
		}

		// compile the service matcher
		serviceNameCompiled, err := regexp.Compile(value.ServiceName)
		if err != nil {
			return &policy{err: errors.New(fmt.Sprintf("policy entry %d: service name=%s could not be compiled: %s", i+1, value.ServiceName, err.Error()))}
		}
		h.Write([]byte(value.ServiceName))

		// compile the org matcher
		oCompiled, err := regexp.Compile(value.O)
		if err != nil {
			return &policy{err: errors.New(fmt.Sprintf("policy entry %d: o=%s could not be compiled: %s", i+1, value.O, err.Error()))}
		}
		h.Write([]byte(value.O))

		newEntry := compEntry{o: oCompiled, serviceName: serviceNameCompiled}

		// iterate over the CN list and compile
		for _, j := range value.CN {
			compiled, err := regexp.Compile(j)
			if err != nil {
				return &policy{err: errors.New(fmt.Sprintf("policy entry %d: cn=%s could not be compiled: %s", i+1, j, err.Error()))}
			}
			newEntry.cn = append(newEntry.cn, compiled)
			h.Write([]byte(j))
		}

		newPolicy.comparators = append(newPolicy.comparators, newEntry)
	}

	newPolicy.hash = h.Sum(nil)
	return newPolicy
}

// isAuthorized returns true if the individual is authorized otherwise false. There is a race condition where the same
// positive or negative entry may be injected into the cache multiple times. This is OK and does not compromise the
// validity of the algorithm. The cost to remove this race is responsiveness so not worth implementing.
func (p *policy) isAuthorized(o, cn, serviceName string) bool {
	key := serviceName + "|" + o + "|" + cn

	if isAllowed, exists := p.cache.Get(key); exists {
		return isAllowed // already in cache
	}

	// run through policy looking for matches
	for _, v := range p.comparators {
		if v.serviceName.MatchString(serviceName) && v.o.MatchString(o) { // 'service name' && 'o' match
			for _, cnMatcher := range v.cn {
				if cnMatcher.MatchString(cn) { // the 'cn' match
					// could look it up again, in case added by other thread, but not worth it - ok to add duplicates
					p.cache.Add(key, true)
					log.Printf("service name=%s o=%s cn=%s added to allow cache", serviceName, o, cn)
					return true
				}
			}
		}
	}
	p.cache.Add(key, false)
	log.Printf("service name=%s o=%s cn=%s added to deny cache", serviceName, o, cn)

	return false // finish
}
