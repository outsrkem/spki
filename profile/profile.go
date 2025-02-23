package profile

import (
	"crypto/x509/pkix"
	"net"
	"net/url"
)

type Profile struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}
