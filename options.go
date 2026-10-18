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
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Opt is a configuration option for creating certifakes.
type Opt func(*Options) error

// Options stores the configuration options when creating certifakes.
type Options struct {
	validWithin time.Duration
	domains     []string
	ips         []netip.Addr
}

// ValidWithin configures how long a self-signed certifake is to be valid from
// the moment of its creation.
func ValidWithin(d time.Duration) Opt {
	return func(o *Options) error {
		if d <= 0 {
			return fmt.Errorf("certificate validity duration must be positive, not %d", d)
		}
		o.validWithin = d
		return nil
	}
}

// WithDomain configures a certifake with the specified domain. WithDomain can
// be specified multiple times.
func WithDomain(d string) Opt {
	return func(o *Options) error {
		o.domains = append(o.domains, d)
		return nil
	}
}

// WithIP configures a certifake with the specified IP address in either textual
// form, net.IP, or netip.Addr forms. WithIP can be specified multiple times.
func WithIP[A ~string | net.IP | netip.Addr](addr A) Opt {
	return func(o *Options) error {
		switch addr := any(addr).(type) {
		case string:
			o.ips = append(o.ips, netip.MustParseAddr(addr))
		case net.IP:
			a, ok := netip.AddrFromSlice(addr)
			if !ok {
				return fmt.Errorf("invalid net.IP: %v", addr)
			}
			o.ips = append(o.ips, a.Unmap())
		case netip.Addr:
			o.ips = append(o.ips, addr)
		}
		return nil
	}
}
