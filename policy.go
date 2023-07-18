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
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/Heebron/set"
	"github.com/fsnotify/fsnotify"
	lru2 "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
)

type policyFile struct {
	RevList []string `yaml:"revocation list"`
	Hosts   []struct {
		SniMatch string `yaml:"sni match"`
		O        string `yaml:"o"`
		CN       struct {
			Allow struct {
				Match []string `yaml:"match"`
			} `yaml:"allow"`
			Deny struct {
				Match []string `yaml:"match"`
			} `yaml:"deny"`
		} `yaml:"cn"`
	} `yaml:"hosts"`
}

type compEntry struct {
	sniMatch   *regexp.Regexp
	o          *regexp.Regexp
	allowMatch []string
	denyMatch  []string
}

type policy struct {
	err            error // carry any errors processing a policy file
	cache          *lru2.Cache[string, bool]
	hash           []byte
	revocationList set.Set[string] // set of revoked certificate serial numbers

	// compiled regex
	comparators []compEntry
}

func policyFileWatcher(f string, cacheSize int, c chan<- *policy) {
	// set up the policyFile file watcher
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
	fmt.Printf("watching policy file '%s' for changes\n", f)
	for {
		select {
		case e := <-watcher.Events: // wait for file event.
			if e.Has(fsnotify.Write) {
				c <- processPolicyFile(f, cacheSize)
			}
		case err := <-watcher.Errors:
			c <- &policy{err: err}
		}
	}
}

func processPolicyFile(f string, cacheSize int) *policy {
	if p, err := loadPolicy(f); err != nil {
		return &policy{err: err}
	} else {
		newPolicy := compilePolicy(p)
		if newPolicy.err != nil {
			return newPolicy // return on error
		} else if newLRU, err := lru2.New[string, bool](cacheSize); err != nil {
			return &policy{err: err}
		} else {
			newPolicy.cache = newLRU
			return newPolicy
		}
	}
}

func loadPolicy(f string) (policyFile, error) {
	confFile, err := os.Open(f)
	if err != nil {
		return policyFile{}, err
	}
	defer func() { _ = confFile.Close() }()

	decoder := yaml.NewDecoder(confFile)
	newPolicy := policyFile{}
	err = decoder.Decode(&newPolicy)
	if err != nil {
		return policyFile{}, err
	}

	return newPolicy, nil
}

func compilePolicy(p policyFile) *policy {
	newPolicy := &policy{}
	h := sha1.New()

	// loop through the revocation list
	for _, value := range p.RevList {
		newPolicy.revocationList.Add(value)
		h.Sum([]byte(value))
	}

	// loop through the policy list
	for i, value := range p.Hosts {

		// process direct match allow
		if len(value.CN.Allow.Match) == 0 {
			continue
		}

		// TODO: implement deny and regexps

		// we have something to allow or deny, include i in the policy map

		sniCompiled, err := regexp.Compile(value.SniMatch)
		if err != nil {
			return &policy{err: errors.New(fmt.Sprintf("policy entry %d: sni match=%s could not be compiled: %s", i+1, value.SniMatch, err.Error()))}
		}
		h.Write([]byte(value.SniMatch))

		oCompiled, err := regexp.Compile(value.O)
		if err != nil {
			return &policy{err: errors.New(fmt.Sprintf("policy entry %d: o=%s could not be compiled: %s", i+1, value.O, err.Error()))}
		}
		h.Write([]byte(value.O))

		newEntry := compEntry{sniMatch: sniCompiled, o: oCompiled, allowMatch: value.CN.Allow.Match}

		h.Write([]byte(fmt.Sprintf("%v", value.CN))) // list out for hashing

		newPolicy.comparators = append(newPolicy.comparators, newEntry)
	}

	newPolicy.hash = h.Sum(nil)
	return newPolicy
}

// isAuthorized return true if the individual is authorized else false.
func (p *policy) isAuthorized(host, o, cn, serial string) bool {

	key := cn + "[" + o + "]" + host

	isAllowed, exists := p.cache.Get(key) // concurrent safe

	if exists { // already in cache
		return isAllowed
	}

	// todo: update traefik config to include serial
	// check for revoked cert
	if serial != "" && p.revocationList.Contains(serial) {
		fmt.Printf("host=%s o=%s cn=%s added to deny cache - revoked cert\n", host, o, cn)
		p.cache.Add(key, false)
		return false
	}

	// run through policy looking for matches
	for _, v := range p.comparators {
		if v.sniMatch.MatchString(host) && v.o.MatchString(o) && slices.Contains(v.allowMatch, cn) {
			p.cache.Add(key, true) // concurrent safe
			fmt.Printf("host=%s o=%s cn=%s added to allow cache\n", host, o, cn)
			return true
		}
	}
	p.cache.Add(key, false)
	fmt.Printf("host=%s o=%s cn=%s added to deny cache\n", host, o, cn)

	return false // finish
}
