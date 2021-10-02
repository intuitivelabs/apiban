package api

import (
	"log"
	"net/url"
)

// NewBannedApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses
func NewBannedIpApi(configId, baseUrl, token, limit string) *Api {
	bannedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	bannedIpApi.Init("IP blacklist", configId, baseUrl, BwV4List, token, limit, IpBanned)
	bannedIpApi.Values.Add("list", "ipblack")
	log.Printf("%s", bannedIpApi.String())
	return &bannedIpApi
}

// NewHoneynetApi returns an initialized Api object which can be used for retrieving blacklisted IP addresses from the public honeynet
func NewHoneynetIpApi(configId, baseUrl, token, limit string, bin bool) *Api {
	honeynetIpApi := Api{
		Values:   url.Values{},
		Client:   defaultHttpClient,
		IpBinary: bin,
	}
	honeynetIpApi.Init("IP public blacklist (honeynet)", configId, baseUrl, BwV4List, token, limit, IpHoneynet)
	honeynetIpApi.Values.Add("list", "ipblack")
	honeynetIpApi.Values.Add("honeynet", "true")
	log.Printf("%s", honeynetIpApi.String())
	return &honeynetIpApi
}

// NewAllowedApi returns an initialized Api object which can be used for retrieving whitelisted IP addresses
func NewAllowedIpApi(configId, baseUrl, token, limit string) *Api {
	allowedIpApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	allowedIpApi.Init("IP whitelist", configId, baseUrl, BwV4List, token, limit, IpAllowed)
	allowedIpApi.Values.Add("list", "ipwhite")
	log.Printf("%s", allowedIpApi.String())
	return &allowedIpApi
}

func RegisterIpApis(configId, baseUrl, token, limit string, bin bool) {
	Apis[IpBanned] = NewBannedIpApi(configId, baseUrl, token, limit)
	Apis[IpHoneynet] = NewHoneynetIpApi(configId, baseUrl, token, limit, bin)
	Apis[IpAllowed] = NewAllowedIpApi(configId, baseUrl, token, limit)
}
