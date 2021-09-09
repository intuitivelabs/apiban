package apiban

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"
)

// NewBannedApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses
func NewBannedIpApi(configId, baseUrl, token string) *Api {
	bannedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	bannedIpApi.init("IP blacklist", configId, baseUrl, BwV4List, token, IpBanned)
	bannedIpApi.Values.Add("list", "ipblack")
	bannedIpApi.ResponseProc = (IpVector).Blacklist
	log.Printf("%s", bannedIpApi.String())
	return &bannedIpApi
}

// NewAllowedApi returns an initialized Api object which can be used for retrieving whitelisted IP addresses
func NewAllowedIpApi(configId, baseUrl, token string) *Api {
	allowedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	allowedIpApi.init("IP whitelist", configId, baseUrl, BwV4List, token, IpAllowed)
	allowedIpApi.Values.Add("list", "ipwhite")
	allowedIpApi.ResponseProc = (IpVector).Whitelist
	log.Printf("%s", allowedIpApi.String())
	return &allowedIpApi
}

func RegisterIpApis(configId, baseUrl, token string) {
	Apis[IpBanned] = NewBannedIpApi(configId, baseUrl, token)
	Apis[IpAllowed] = NewAllowedIpApi(configId, baseUrl, token)
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
	case IpBanned:
		if IpTables().Sets[IpTables().Bl] == nil {
			return ErrNoBlacklistFound
		}
		return ip.Blacklist(ttl)
	case IpAllowed:
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
