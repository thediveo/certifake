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
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/thediveo/certifake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

var _ = Describe("certifake options", func() {

	It("uses the default validity duration of one hour", func() {
		before := time.Now()
		cert := Successful(certifake.New())
		after := time.Now()

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))
		Expect(parsed.NotAfter).To(BeTemporally(
			">=", before.Add(time.Hour).Add(-time.Second)))
		Expect(parsed.NotAfter).To(BeTemporally(
			"<=", after.Add(time.Hour)))
	})

	It("uses the configured validity duration", func() {
		validity := 30 * time.Minute
		before := time.Now()
		cert := Successful(certifake.New(certifake.ValidWithin(validity)))
		after := time.Now()

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))

		Expect(parsed.NotAfter).To(BeTemporally(">=",
			before.Add(validity).Truncate(time.Second)))
		Expect(parsed.NotAfter).To(BeTemporally("<=",
			after.Add(validity).Truncate(time.Second).Add(time.Second)))
	})

	DescribeTable("rejects invalid validity durations",
		func(validity time.Duration) {
			Expect(certifake.New(certifake.ValidWithin(validity))).Error().To(
				MatchError(MatchRegexp(`certificate validity duration must be positive`)))
		},
		Entry("zero", time.Duration(0)),
		Entry("negative", -time.Second),
	)

	It("includes configured DNS names", func() {
		cert := Successful(certifake.New(
			certifake.WithDomain("example.com"),
			certifake.WithDomain("localhost"),
		))

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))
		Expect(parsed.DNSNames).To(ConsistOf(
			"example.com",
			"localhost",
		))
	})

	It("includes configured IP addresses", func() {
		cert := Successful(certifake.New(
			certifake.WithIP("192.0.2.1"),
			certifake.WithIP(net.ParseIP("2001:db8::1")),
			certifake.WithIP(netip.MustParseAddr("192.0.2.2")),
		))

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))
		Expect(parsed.IPAddresses).To(ConsistOf(
			ipEqual("192.0.2.1"),
			ipEqual("2001:db8::1"),
			ipEqual("192.0.2.2"),
		))
	})

	It("unmaps IPv4-mapped IPv6 addresses provided as net.IP", func() {
		cert := Successful(certifake.New(
			certifake.WithIP(net.ParseIP("::ffff:192.0.2.1")),
		))

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))
		Expect(parsed.IPAddresses).To(ConsistOf(
			ipEqual("192.0.2.1"),
		))
	})

	It("accepts multiple configuration options", func() {
		cert := Successful(certifake.New(
			certifake.ValidWithin(5*time.Minute),
			certifake.WithDomain("example.com"),
			certifake.WithDomain("api.example.com"),
			certifake.WithIP("127.0.0.1"),
		))

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))
		Expect(parsed.DNSNames).To(ConsistOf(
			"example.com",
			"api.example.com",
		))
		Expect(parsed.IPAddresses).To(ConsistOf(
			ipEqual("127.0.0.1"),
		))
		Expect(parsed.NotAfter).To(BeTemporally(
			"~",
			time.Now().Add(5*time.Minute),
			2*time.Minute,
		))
	})

	It("returns an error when a configuration option fails", func() {
		Expect(certifake.New(func(_ *certifake.Options) error {
			return errors.New("D'OH!")
		})).Error().To(HaveOccurred())
	})

	It("does not apply options after an option fails", func() {
		called := false

		Expect(certifake.New(
			func(_ *certifake.Options) error {
				return errors.New("D'OH!")
			},
			func(_ *certifake.Options) error {
				called = true
				return nil
			},
		)).Error().To(MatchError(ContainSubstring("D'OH!")))
		Expect(called).To(BeFalse())
	})

})
