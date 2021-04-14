package apiban

import (
	"fmt"
	"net/url"
)

// URI Resources JSON objects in API responses
type URI struct {
	Encrypt string `json:"encrypt"`
	URI     string `json:"uri"`
}

func (uri *URI) Process(ttl int, api APICode) error {
	fmt.Printf("processing uri: %s", uri.URI)
	return nil
}

// ApiBannedURIReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version&table=uriblack
func ApiBannedURI(key, startFrom, version, baseUrl string) (*JSONResponse, error) {
	values := url.Values{}
	values.Add("version", version)
	values.Add("table", "uriblack")
	return nil, nil
}
