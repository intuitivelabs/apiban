package apiban

import (
	"fmt"
	"log"
	"strconv"
	"time"
)

// NewBannedApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses
func NewBannedApi(configId, baseUrl, token string) *Api {
	bannedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIBanned)
	bannedApi.Values.Add("list", "ipblack")
	bannedApi.ResponseProc = (IpVector).Blacklist
	return &bannedApi
}

// NewAllowedApi returns an initialized Api object which can be used for retrieving whitelisted IP addresses
func NewAllowedApi(configId, baseUrl, token string) *Api {
	allowedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIAllowed)
	allowedApi.Values.Add("list", "ipwhite")
	allowedApi.ResponseProc = (IpVector).Whitelist
	return &allowedApi
}

// IP Resource JSON objects in API responses.
// It represents IPs of blocked/allowed IP addresses
type IP struct {
	Encrypt string `json:"encrypt"`
	Ipaddr  string `json:"ipaddr"`
}

type IpVector []IP

func (ips IpVector) Decrypt(plainTxt []string) int {
	var (
		i int = 0
	)
	for _, ip := range ips {
		if i > len(plainTxt) {
			break
		}
		if b, err := ip.Decrypt(); err != nil {
			continue
		} else {
			plainTxt[i] = b
			i++
		}
	}
	return i
}

func (ips IpVector) Whitelist(ttl time.Duration) error {
	plainTxt := make([]string, len(ips))
	n := ips.Decrypt(plainTxt)
	return GetFirewall().AddToWhitelist(plainTxt[0:n], ttl)
}

func (ips IpVector) Blacklist(ttl time.Duration) error {
	plainTxt := make([]string, len(ips))
	n := ips.Decrypt(plainTxt)
	return GetFirewall().AddToBlacklist(plainTxt[0:n], ttl)
}

func (ip *IP) Process(ttl time.Duration, api APICode) error {
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

func (ip *IP) Whitelist(ttl time.Duration) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToWhitelist([]string{ipStr}, ttl); err == nil {
			log.Printf("processed IP: %s", ipStr)
		}
	}
	return err
}

func (ip *IP) Blacklist(ttl time.Duration) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToBlacklist([]string{ipStr}, ttl); err == nil {
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

// IPResponse describes the response for bwnoa/v4list API
type IPResponse struct {
	Metadata JSONMap `json:"metadata"`

	// ID is the timestamp of the next IPResponse
	ID string `json:"ID,omitempty"`

	// IPs is the list of blocked/allowed IP addresses in this entry
	IPs []IP `json:"elements"`
}

// ProcResponse processes the response returned by the GET API.
func (msg *IPResponse) Process(api *Api) error {
	if len(msg.IPs) == 0 {
		log.Print("No new bans to add...")
		return nil
	}

	ttl := GetConfig().BlacklistTtl
	if ttl == 0 {
		// try to get the ttl from the answers metadata
		t, _ := msg.Metadata.Ttl()
		ttl = time.Duration(t) * time.Second
	}
	log.Print("ttl: ", ttl)
	if timestamp, err := msg.Metadata.Timestamp(); err != nil {
		return err
	} else {
		api.Timestamp = strconv.Itoa(timestamp)
	}

	// process IP objects
	msg.procIP(ttl, api)
	return nil
}

func (msg *IPResponse) procIP(ttl time.Duration, api *Api) {
	if err := api.ResponseProc(msg.IPs, ttl); err != nil {
		log.Printf("failed to process IP addresses: %s", err.Error())
	}
}
