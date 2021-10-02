package parser

import (
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/anonymization"
	"net"
)

// IP Resource JSON objects in API responses.
// It represents IPs of blocked/allowed IP addresses
type IP struct {
	Encrypt string `json:"encrypt"`
	Ipaddr  string `json:"ipaddr"`
}

func (ip *IP) String() string {
	s, err := ip.Decrypt()
	if err != nil {
		return ""
	}
	return s
}

func (ip *IP) Decrypt() (string, error) {
	if len(ip.Ipaddr) > 0 {
		return anonymization.DecryptIp(ip.Ipaddr, ip.Encrypt)
	}
	return "", ErrJsonEmptyIPAddressField
}

func (ip *IP) Parse() ([]byte, error) {
	if len(ip.Ipaddr) > 0 {
		return []byte(net.ParseIP(ip.Ipaddr).To4()), nil
	}
	return nil, ErrJsonEmptyIPAddressField
}
