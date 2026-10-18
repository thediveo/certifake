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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/thediveo/certifake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

var _ = Describe("certifakes", func() {

	It("generates a valid self-signed ECDSA certificate", func() {
		before := time.Now()
		cert := Successful(certifake.New())
		after := time.Now()
		Expect(cert.Certificate).To(HaveLen(1))

		privkey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue())
		Expect(privkey.Curve).To(Equal(elliptic.P521()))

		parsed := Successful(x509.ParseCertificate(cert.Certificate[0]))

		Expect(parsed.Subject.CommonName).To(Equal("unittestcertifake"))
		Expect(parsed.IsCA).To(BeFalse())
		Expect(parsed.BasicConstraintsValid).To(BeTrue())
		Expect(parsed.KeyUsage).To(Equal(x509.KeyUsageDigitalSignature))
		Expect(parsed.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth))

		Expect(parsed.CheckSignature(
			parsed.SignatureAlgorithm,
			parsed.RawTBSCertificate,
			parsed.Signature,
		)).To(Succeed())
		Expect(parsed.PublicKey).To(Equal(&privkey.PublicKey))

		Expect(parsed.NotBefore).To(BeTemporally(
			">=", before.Add(-time.Minute).Add(-time.Second)))
		Expect(parsed.NotBefore).To(BeTemporally(
			"<=", after.Add(-time.Minute)))

		Expect(parsed.NotAfter).To(BeTemporally(
			">=", before.Add(time.Hour).Add(-time.Second)))
		Expect(parsed.NotAfter).To(BeTemporally(
			"<=", after.Add(time.Hour)))
	})

	Context("with a TLS certifake", func() {

		var cert tls.Certificate

		BeforeEach(func() {
			cert = Successful(certifake.New(
				certifake.WithDomain("example.com"),
				certifake.WithIP("127.0.0.1"),
			))
		})

		It("encodes the certificate and private key as PEM", func() {
			certPEM, keyPEM := Successful2R(certifake.ToPEM(cert))

			certBlock, rest := pem.Decode(certPEM)
			Expect(certBlock).NotTo(BeNil())
			Expect(certBlock.Type).To(Equal(certifake.PEMTypeCertificate))
			Expect(rest).To(BeEmpty())

			keyBlock, rest := pem.Decode(keyPEM)
			Expect(keyBlock).NotTo(BeNil())
			Expect(keyBlock.Type).To(Equal(certifake.PEMTypePrivateKey))
			Expect(rest).To(BeEmpty())
		})

		It("encodes a certificate that can be parsed", func() {
			certPEM, _ := Successful2R(certifake.ToPEM(cert))

			block, rest := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			Expect(rest).To(BeEmpty())

			parsed := Successful(x509.ParseCertificate(block.Bytes))
			Expect(parsed.Subject.CommonName).To(Equal("unittestcertifake"))
			Expect(parsed.DNSNames).To(ConsistOf("example.com"))
			Expect(parsed.IPAddresses).To(ConsistOf(ipEqual("127.0.0.1")))
		})

		It("encodes a private key that can be parsed", func() {
			_, keyPEM := Successful2R(certifake.ToPEM(cert))

			block, rest := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil())
			Expect(rest).To(BeEmpty())

			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			privkey, ok := key.(*ecdsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(privkey.Curve).To(Equal(elliptic.P521()))
		})

		It("preserves the certificate's public/private key relationship", func() {
			certPEM, keyPEM := Successful2R(certifake.ToPEM(cert))

			certBlock, rest := pem.Decode(certPEM)
			Expect(certBlock).NotTo(BeNil())
			Expect(rest).To(BeEmpty())

			keyBlock, rest := pem.Decode(keyPEM)
			Expect(keyBlock).NotTo(BeNil())
			Expect(rest).To(BeEmpty())

			parsedCert := Successful(x509.ParseCertificate(certBlock.Bytes))
			key := Successful(x509.ParsePKCS8PrivateKey(keyBlock.Bytes))
			privkey := AssignableTo[*ecdsa.PrivateKey](key)
			Expect(parsedCert.PublicKey).To(Equal(&privkey.PublicKey))
		})

		It("returns an error for an empty certificate chain", func() {
			Expect(certifake.ToPEM(tls.Certificate{})).Error().To(MatchError("certificate chain empty"))
		})

		It("encodes only the first certificate in the chain", func() {
			second := Successful(certifake.New())
			cert.Certificate = append(cert.Certificate, second.Certificate[0])

			certPEM, _ := Successful2R(certifake.ToPEM(cert))
			block, rest := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			Expect(rest).To(BeEmpty())
			Expect(block.Bytes).To(Equal(cert.Certificate[0]))
			Expect(block.Bytes).NotTo(Equal(cert.Certificate[1]))
		})

		It("returns an error when the private key cannot be marshaled", func() {
			cert := tls.Certificate{
				Certificate: [][]byte{{1, 2, 3}},
				PrivateKey:  nil,
			}
			Expect(certifake.ToPEM(cert)).Error().To(MatchError(ContainSubstring("cannot marshal private key")))
		})

	})

})
