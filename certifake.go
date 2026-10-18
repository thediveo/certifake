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
	"time"

	"github.com/thediveo/nonstd/xslices"
)

const (
	PEMTypeCertificate = "CERTIFICATE"
	PEMTypePrivateKey  = "PRIVATE KEY"
)

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
