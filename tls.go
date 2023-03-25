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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
)

// initTLS initializes a TLS v1.3/v1.2 transport using the configured PKI certificate and key. Additionally, if
// any CA certs are configured, they will be added to the default system set of CA certs. The certFile, keyFile, and
// caFile parameters are all filepaths to PEM encoded files. The certFile and keyFile represent an X.509 certificate
// and private key pair. The caFile file is a set of trusted X.509 certificates.
func initTLS(certFile string, keyFile string, caFile string) (*tls.Config, error) {
	if cert, caSet, err := loadPKI(certFile, keyFile, caFile); err == nil {
		return &tls.Config{
			RootCAs:      caSet,                   // extra trusted CAs
			Certificates: []tls.Certificate{cert}, // server cert
			MinVersion:   tls.VersionTLS12,
		}, nil
	} else {
		return nil, err
	}
}

func loadPKI(certFile string, keyFile string, caFile string) (tls.Certificate, *x509.CertPool, error) {
	var err error

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caFile != "" {
		file, err := os.Open(caFile)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		defer func() { _ = file.Close() }()
		caCerts, err := io.ReadAll(file)
		if err != nil {
			return tls.Certificate{}, nil, err
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caCerts); !ok {
			return tls.Certificate{}, nil, errors.New("No CA certs appended.")
		}
	}
	return serverCert, rootCAs, nil
}
