package apiban

import (
	"fmt"
	"log"
	"net/url"
	"time"
)

// URI Resources JSON objects in API responses
type URI struct {
	Encrypt string `json:"encrypt"`
	URI     string `json:"uri"`
}

func (uri *URI) Process(ttl time.Duration, api APICode) error {
	fmt.Printf("processing uri: %s", uri.URI)
	return nil
}

func (uri *URI) Decrypt() (string, error) {
	return "", nil
}

// NewBannedUriApi returns an initialized Api object which can be used for retrieving banned (blacklisted) URIs
func NewBannedUriApi(configId, baseUrl, token string) *Api {
	bannedUriApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	bannedUriApi.init("SIP URI blacklist", configId, baseUrl, BwV4List, token, UriBanned)
	bannedUriApi.Values.Add("list", "uriblack")
	log.Printf("%s", bannedUriApi.String())
	return &bannedUriApi
}

// NewAllowedUriApi returns an initialized Api object which can be used for retrieving explicitly allowed (whitelisted) URIs
func NewAllowedUriApi(configId, baseUrl, token string) *Api {
	allowedUriApi := Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	allowedUriApi.init("SIP URI whitelist", configId, baseUrl, BwV4List, token, UriAllowed)
	allowedUriApi.Values.Add("list", "uriwhite")
	log.Printf("%s", allowedUriApi.String())
	return &allowedUriApi
}

func RegisterUriApis(configId, baseUrl, token string) {
	Apis[UriBanned] = NewBannedUriApi(configId, baseUrl, token)
	Apis[UriAllowed] = NewAllowedUriApi(configId, baseUrl, token)
}

// ApiBannedURIReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version&table=uriblack
func ApiBannedURI(key, startFrom, version, baseUrl string) (*JSONResponse, error) {
	values := url.Values{}
	values.Add("version", version)
	values.Add("table", "uriblack")
	return nil, nil
}

func LogUris(uris []string) error {
	for _, uri := range uris {
		if len(uri) > 0 {
			log.Printf(`banned URI: "%s"`, uri)
		}
	}
	return nil
}
