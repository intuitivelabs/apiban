package apiban

import (
	"fmt"
	"log"
)

// IP Resource JSON objects in API responses.
// It represents IPs of blocked/allowed IP addresses
type IP struct {
	Encrypt string `json:"encrypt"`
	Ipaddr  string `json:"ipaddr"`
}

func (ip *IP) Process(ttl int, api APICode) error {
	if IpTables() == nil {
		return ErrNoIptables
	}
	switch api {
	case APIBanned:
		if IpTables().Sets[IpTables().Bl] == nil {
			return ErrNoBlacklistFound
		}
		return ip.Blacklist(ttl)
	case APIAllowed:
		if IpTables().Sets[IpTables().Wl] == nil {
			return ErrNoWhitelistFound
		}
		return ip.Whitelist(ttl)
	}
	return fmt.Errorf("unknown API: %d", api)
}

func (ip *IP) Whitelist(ttl int) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToWhitelist(ipStr, ttl); err == nil {
			log.Printf("processed IP: %s", ipStr)
		}
	}
	return err
}

func (ip *IP) Blacklist(ttl int) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToBlacklist(ipStr, ttl); err == nil {
			log.Printf("processed IP: %s", ipStr)
		}
	}
	return err
}

func (ip *IP) Decrypt() (string, error) {
	if len(ip.Ipaddr) > 0 {
		return DecryptIp(ip.Ipaddr, ip.Encrypt)
	}
	return "", ErrJsonEmptyIPAddressField
}
