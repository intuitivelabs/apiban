package apiban

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Response should be implemented by all processors for JSON responses
type Response interface {
	Process(*Api) error
}

type Api struct {
	Client   http.Client
	ConfigId string
	BaseUrl  string
	Path     string
	// timestamp to use for the next request
	Timestamp string
	// query parameters are stored here
	Values       url.Values
	Code         APICode
	ResponseProc func(IpVector, time.Duration) error
}

// use insecure if configured - TESTING PURPOSES ONLY!
var transCfg = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

var httpClient = &http.Client{Transport: transCfg}

// API response JSON objects
var IPMapKeys = [...]string{"IP", "fromua", "encrypt", "exceeded", "count", "timestamp"}
var MetadataKeys = [...]string{"defaultBlacklistTtl"}

type JSONMap map[string]interface{}

type APICode int

const (
	APIBanned APICode = iota
	APIAllowed
	APIUri
)

// errors
var (
	// ErrBadRequest indicates a 400 response was received;
	//
	// NOTE: this is used by the server to indicate both that an IP address is not
	// blocked (when calling Check) and that the list is complete (when calling
	// Banned)
	ErrBadRequest = errors.New("Bad Request")
	// encryption errors
	ErrEncryptNoKey    = errors.New("IP encrypted but no passphrase or encryption key configured")
	ErrEncryptWrongKey = errors.New("IP encrypted but wrong passphrase or encryption key configured")
	// API JSON errors
	ErrJsonParser                              = errors.New(`cannot parse JSON response`)
	ErrJsonMetadataDefaultBlacklistTtlMissing  = errors.New(`malformed JSON response: "defaultBlacklistTtl not present in metadata`)
	ErrJsonMetadataGeneratedatMissing          = errors.New(`malformed JSON response: "lastTimestamp not present in metadata`)
	ErrJsonMetadataDefaultBlacklistTtlDataType = errors.New(`malformed JSON response: "defaultBlacklistTtl has wrong data type`)
	ErrJsonEncryptFieldNotString               = errors.New("malformed JSON response: encrypt field is not string in JSON")
	ErrJsonEmptyIPAddressField                 = errors.New("malformed JSON response: IP address field is empty")
)

func (metadata JSONMap) Ttl() (ttl int, err error) {
	ttl = 0
	err = nil

	if metaTtl, ok := metadata["defaultBlacklistTtl"]; ok {
		floatTtl, _ := metaTtl.(float64)
		ttl = int(floatTtl)
		if ttl < 0 {
			ttl = 0
		}
		return
	}
	err = ErrJsonMetadataDefaultBlacklistTtlMissing
	return
}

func (metadata JSONMap) Timestamp() (timestamp int, err error) {
	timestamp = 0
	err = nil

	if metaTimestamp, ok := metadata["lastTimestamp"]; ok {
		floatTimestamp, _ := metaTimestamp.(float64)
		timestamp = int(floatTimestamp)
		if timestamp < 0 {
			timestamp = 0
		}
		return
	}
	err = ErrJsonMetadataGeneratedatMissing
	return
}

var (
	defaultHttpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	bannedApi Api = Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	allowedApi Api = Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
	uriApi Api = Api{
		Values: url.Values{},
		Client: defaultHttpClient,
	}
)

func NewBannedApi(configId, baseUrl, token string) *Api {
	bannedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIBanned)
	bannedApi.Values.Add("list", "ipblack")
	bannedApi.ResponseProc = (IpVector).Blacklist
	return &bannedApi
}

func NewAllowedApi(configId, baseUrl, token string) *Api {
	allowedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIAllowed)
	allowedApi.Values.Add("list", "ipwhite")
	allowedApi.ResponseProc = (IpVector).Whitelist
	return &allowedApi
}

func NewUriApi(configId, baseUrl, token string) *Api {
	uriApi.init(configId, baseUrl, "bwnoa/v4list", token, APIUri)
	uriApi.Values.Add("list", "uri")
	return &uriApi
}

func (api *Api) init(configId, baseUrl, path, token string, code APICode) {
	for k, _ := range api.Values {
		delete(api.Values, k)
	}
	api.Code = code
	if len(configId) == 0 {
		configId = "0"
	}
	api.ConfigId = configId
	api.Timestamp = configId
	api.BaseUrl = baseUrl
	api.Path = path
	if len(token) > 0 {
		api.Values.Add("token", token)
	}
}

func (api *Api) Request() (Response, error) {
	if api.Timestamp == "" {
		// start from 0 if an empty start timestamp was provided
		api.Timestamp = "0"
	}
	api.Values.Set("timestamp", api.Timestamp)
	return api.RequestWithQueryValues()
}

func (api *Api) RequestWithQueryValues() (Response, error) {
	var apiUrl string

	query := api.Values.Encode()

	if len(query) > 0 {
		apiUrl = fmt.Sprintf("%s%s?%s", api.BaseUrl, api.Path, query)
	} else {
		apiUrl = fmt.Sprintf("%s%s", api.BaseUrl, api.Path)
	}
	log.Printf(`"%s" api url: %s`, api.Path, apiUrl)
	//e, err := queryServer(httpClient, apiUrl)
	buf, err := api.Get(apiUrl)
	if err != nil {
		return nil, err
	}

	response, err := api.parseResponse(buf)
	if err != nil {
		return nil, err
	}
	return response, nil

}

func (api *Api) Response(msg Response) {
	msg.Process(api)
}

// ApiBannedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func (api *Api) Process() (err error) {
	res, err := api.Request()
	if err != nil {
		err = fmt.Errorf(`%s request error: %w`, api.Path, err)
	} else if res == nil {
		err = fmt.Errorf(`%s response with empty body`, api.Path)
	} else {
		if IpTables() == nil {
			err = ErrNoIptables
			return
		}
		if api.Code == APIBanned && IpTables().Sets[IpTables().Bl] == nil {
			err = ErrNoBlacklistFound
			return
		}
		if api.Code == APIAllowed && IpTables().Sets[IpTables().Wl] == nil {
			err = ErrNoWhitelistFound
			return
		}
		api.Response(res)
	}
	return
}

func (api Api) parseResponse(msg []byte) (Response, error) {
	var (
		err          error
		jsonResponse JSONResponse
		errResponse  ErrResponse
	)

	// try JSONResponse first
	if err = json.Unmarshal(msg, &jsonResponse); err == nil {
		if jsonResponse.Metadata != nil && len(jsonResponse.Metadata) > 0 {
			return &jsonResponse, nil
		}
	}

	// try ErrResponse
	if err = json.Unmarshal(msg, &errResponse); err == nil {
		return &errResponse, nil
	}

	return nil, fmt.Errorf("%s: %w", ErrJsonParser.Error(), err)

}

func (api Api) Get(url string) ([]byte, error) {
	response, err := api.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("api %s get error: %w", api.Path, err)
	}
	defer response.Body.Close()
	switch code := response.StatusCode; {
	case code == http.StatusBadRequest:
		return nil, fmt.Errorf("bad request (%d): %s from %q", response.StatusCode, response.Status, url)
	case code == http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limit reached (%d): %s from %q", response.StatusCode, response.Status, url)
	case code > http.StatusBadRequest && code < http.StatusInternalServerError:
		return nil, fmt.Errorf("client error (%d): %s from %q", response.StatusCode, response.Status, url)
	case code >= http.StatusInternalServerError:
		return nil, fmt.Errorf("server error (%d): %s from %q", response.StatusCode, response.Status, url)
	case code >= http.StatusMultipleChoices:
		return nil, fmt.Errorf("unhandled error (%d): %s from %q", response.StatusCode, response.Status, url)
	}

	return ioutil.ReadAll(response.Body)
}

// Resource is a generic term for IP addressses, URIs; this interface should be implemented by all resources
type Resource interface {
	// Process locally the resource received from the server (by applying b/w listing, fw rules aso)
	Process(ttl time.Duration, api APICode) error
}

// generic response object used for unmarshalling either IPObj or URIObj
type Element struct {
	r Resource
}

func (elem *Element) UnmarshalJSON(msg []byte) error {
	var (
		ip  IP
		uri URI
	)
	elem.r = nil
	if string(msg) == "null" {
		return nil
	}

	if err := json.Unmarshal(msg, &ip); err == nil {
		if len(ip.Ipaddr) > 0 {
			elem.r = &ip
			return nil
		}
	}

	if err := json.Unmarshal(msg, &uri); err == nil {
		if len(uri.URI) > 0 {
			elem.r = &uri
			return nil
		}
	}

	return ErrJsonParser
}

// JSONResponse describes the response for bwnoa/v4list API
type JSONResponse struct {
	Metadata JSONMap `json:"metadata"`

	// ID is the timestamp of the next response
	ID string `json:"ID,omitempty"`

	// an array of resources (either of: IP addr, URI) in this response
	Elements []*Element `json:"elements"`
}

// ProcResponse processes the response returned by the GET API.
func (msg *JSONResponse) Process(api *Api) error {
	if len(msg.Elements) == 0 {
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
	msg.processElements(ttl, api)
	return nil
}

func (msg *JSONResponse) processElements(ttl time.Duration, api *Api) {
	for _, s := range msg.Elements {
		err := msg.processElement(s, ttl, api)
		if err != nil {
			log.Printf("failed to process IP: %s", err.Error())
		}
	}
}

func (msg *JSONResponse) processElement(el *Element, ttl time.Duration, api *Api) error {
	return el.r.Process(ttl, api.Code)
}

// ErrResponse
type ErrResponse struct {
	StatusCode        int    `json:"statusCode"`
	StatusDescription string `json:"statusDescription"`
}

func (msg *ErrResponse) Process(api *Api) error {
	log.Printf(`received an error response for api "%s": %d %s`, api.Path, msg.StatusCode, msg.StatusDescription)
	return nil
}
