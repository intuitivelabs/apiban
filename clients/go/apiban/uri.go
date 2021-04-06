package apiban

import (
	"net/url"
)

func procURI(ips []JSONMap, ttl int, code APICode) {
	return
}

// ApiBannedURIReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version&table=uriblack
func ApiBannedURI(key, startFrom, version, baseUrl string) (*IPResponse, error) {
	values := url.Values{}
	values.Add("version", version)
	values.Add("table", "uriblack")
	return ApiRequestWithQueryValues(baseUrl, "banned", values)
}
