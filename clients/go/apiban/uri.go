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

// NewUriApi returns an initialized Api object which can be used for retrieving URIs
func NewUriApi(configId, baseUrl, token string) *Api {
	uriApi.init(configId, baseUrl, "bwnoa/v4list", token, APIUri)
	uriApi.Values.Add("list", "uri")
	return &uriApi
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
