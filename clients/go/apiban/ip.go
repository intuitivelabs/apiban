package apiban

import (
	"log"
	"net"
	"net/url"
)

// NewBannedApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses
func NewBannedIpApi(configId, baseUrl, token, limit string) *Api {
	bannedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	bannedIpApi.init("IP blacklist", configId, baseUrl, BwV4List, token, limit, IpBanned)
	bannedIpApi.Values.Add("list", "ipblack")
	log.Printf("%s", bannedIpApi.String())
	return &bannedIpApi
}

// NewHoneynetApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses from the public honeynet
func NewHoneynetIpApi(configId, baseUrl, token, limit string, bin bool) *Api {
	bannedIpApi := Api{
		Values:   url.Values{},
		Client:   defaultHttpClient,
		IpBinary: bin,
	}
	bannedIpApi.init("IP public blacklist (honeynet)", configId, baseUrl, BwV4List, token, limit, IpHoneynet)
	bannedIpApi.Values.Add("list", "ipblack")
	bannedIpApi.Values.Add("honeynet", "true")
	log.Printf("%s", bannedIpApi.String())
	return &bannedIpApi
}

// NewAllowedApi returns an initialized Api object which can be used for retrieving whitelisted IP addresses
func NewAllowedIpApi(configId, baseUrl, token, limit string) *Api {
	allowedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	allowedIpApi.init("IP whitelist", configId, baseUrl, BwV4List, token, limit, IpAllowed)
	allowedIpApi.Values.Add("list", "ipwhite")
	log.Printf("%s", allowedIpApi.String())
	return &allowedIpApi
}

func RegisterIpApis(configId, baseUrl, token, limit string, bin bool) {
	Apis[IpBanned] = NewBannedIpApi(configId, baseUrl, token, limit)
	Apis[IpHoneynet] = NewHoneynetIpApi(configId, baseUrl, token, limit, bin)
	Apis[IpAllowed] = NewAllowedIpApi(configId, baseUrl, token, limit)
}

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
		return DecryptIp(ip.Ipaddr, ip.Encrypt)
	}
	return "", ErrJsonEmptyIPAddressField
}

func (ip *IP) Parse() ([]byte, error) {
	if len(ip.Ipaddr) > 0 {
		return []byte(net.ParseIP(ip.Ipaddr).To4()), nil
	}
	return nil, ErrJsonEmptyIPAddressField
}
