// Copyright 2026 Harald Albrecht.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certifake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/thediveo/nonstd/xslices"
)

const (
	PEMTypeCertificate = "CERTIFICATE"
	PEMTypePrivateKey  = "PRIVATE KEY"
)

// New returns a new certificate configured using the passed options; otherwise,
// it returns an error. The certificate returned is valid for one hour, use
// [ValidWithin] to configure a different validity duration. The certificate has
// no SAN configured. Use [WithDomain] and/or [WithIP] to appropriately
// configure the certificate.
func New(opts ...Opt) (tls.Certificate, error) {
	o := Options{
		validWithin: 1 * time.Hour,
	}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return tls.Certificate{}, err
		}
	}

	privkey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot generate ECDSA private key, reason: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		// ensure to use increasing serial numbers as otherwise some clients
		// will reject the certificate.
		SerialNumber: big.NewInt(now.UnixNano()),

		Subject: pkix.Name{
			CommonName: "unittestcertifake",
		},

		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(o.validWithin),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		DNSNames: o.domains,
		IPAddresses: xslices.Map(o.ips, func(addr netip.Addr) net.IP {
			return addr.AsSlice()
		}),
	}

	der, err := x509.CreateCertificate(rand.Reader,
		&template, &template, // ...thus self-signed
		&privkey.PublicKey, privkey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot create certificate, reason: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privkey,
	}, nil
}

// ToPEM returns the certificate PEM together with the key PEM; otherwise, it
// returns an error.
func ToPEM(cert tls.Certificate) (certpem []byte, keypem []byte, err error) {
	if len(cert.Certificate) == 0 {
		return nil, nil, errors.New("certificate chain empty")
	}
	certpem = pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: cert.Certificate[0],
	})

	keyder, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal private key, reason: %w", err)
	}
	keypem = pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: keyder,
	})

	return certpem, keypem, nil
}

// Save a certificate to their certificate and private key PEM files; otherwise,
// returns an error. The certificate file permissions should be 0644 (readable
// by all; readable and writeable by owner) and the private key file permissions
// 0600 (only readable and writeable by user).
func Save(cert tls.Certificate, certpath string, certperm os.FileMode, keypath string, keyperm os.FileMode) error {
	certpem, keypem, err := ToPEM(cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certpath, certpem, certperm); err != nil {
		return fmt.Errorf("cannot write certificate, reason: %w", err)
	}
	if err := os.WriteFile(keypath, keypem, keyperm); err != nil {
		return fmt.Errorf("cannot write private key, reason: %w", err)
	}
	return nil
}
