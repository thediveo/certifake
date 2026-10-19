// Copyright 2026 Harald Albrecht.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy
// of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package certifake_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/thediveo/certifake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

var _ = Describe("end-to-end", func() {

	It("connects securely to a test server endpoint usin in-memory cert+key", func() {
		const msg = "It's HTTPS"

		By("creating cert and key")
		cert := Successful(certifake.New(certifake.WithIP("127.0.0.1")))

		By("creating an HTTPS server")
		server := httptest.NewUnstartedServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(msg))
			}),
		)
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		DeferCleanup(server.Close)

		By("creating an HTTP client")
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		}

		r := Successful(client.Get(server.URL))
		DeferCleanup(r.Body.Close)
		Expect(r.StatusCode).To(Equal(http.StatusOK))
		Expect(string(Successful(io.ReadAll(r.Body)))).To(Equal(msg))
	})

	It("connects securely to an HTTP server using loaded cert+key", func() {
		By("creating and saving a cert and key")
		tmpDir := Successful(os.MkdirTemp("", "certifake-test-*"))
		DeferCleanup(os.RemoveAll, tmpDir)
		certPath := filepath.Join(tmpDir, "server.crt")
		keyPath := filepath.Join(tmpDir, "server.key")

		Expect(certifake.Save(
			Successful(certifake.New(certifake.WithIP("127.0.0.1"))),
			certPath, 0644,
			keyPath, 0600,
		)).To(Succeed())

		By("loading cert and key")
		cert := Successful(tls.LoadX509KeyPair(certPath, keyPath))
		const msg = "It's HTTPS"

		By("creating an HTTPS server")
		server := httptest.NewUnstartedServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(msg))
			}),
		)
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		DeferCleanup(server.Close)

		By("creating an HTTP client")
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		}

		r := Successful(client.Get(server.URL))
		DeferCleanup(r.Body.Close)
		Expect(r.StatusCode).To(Equal(http.StatusOK))
		Expect(string(Successful(io.ReadAll(r.Body)))).To(Equal(msg))
	})

})
