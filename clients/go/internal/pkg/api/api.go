package api

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/config"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/firewall"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/parser"
)

// errors
var (
	// ErrBadRequest indicates a 400 response was received;
	//
	// NOTE: this is used by the server to indicate both that an IP address is not
	// blocked (when calling Check) and that the list is complete (when calling
	// Banned)
	ErrBadRequest                = errors.New("Bad Request")
	ErrUnknownApi                = errors.New("Unknown API code")
	ErrJsonEncryptFieldNotString = errors.New("malformed JSON response: encrypt field is not string in JSON")
)

// Response processing
// Response should be implemented by all processors for API JSON responses
type Response interface {
	Process(*Api) error
}

// JSONResponse describes the response for bwnoa/v4list API
type JSONResponse struct {
	Metadata parser.JSONMap `json:"metadata"`

	// ID is the timestamp of the next response
	ID string `json:"ID,omitempty"`

	// an array of resources (either of: IP addr, URI) in this response
	Elements parser.Elements `json:"elements"`
}

// Process processes the response returned by the GET API.
func (msg *JSONResponse) Process(api *Api) error {
	if len(msg.Elements) == 0 {
		log.Print("No new bans to add...")
		return nil
	}

	ttl := config.GetConfig().BlacklistTtl
	if ttl == 0 {
		// try to get the ttl from the answers metadata
		t, _ := msg.Metadata.Ttl()
		ttl = time.Duration(t) * time.Second
	}

	// TODO debug
	//log.Print("ttl: ", ttl)

	// store the next key in the api datastructure
	api.Key = msg.Metadata.NextEncodedKey()

	if timestamp, err := msg.Metadata.Timestamp(); err != nil {
		return err
	} else if api.Key == nil {
		// subsequent requests within the same API call are sent with the first request's timestamp
		// store the timestamp only if this is the last response
		api.Timestamp = strconv.Itoa(timestamp)
	}

	// process IP objects
	cnt, err := msg.processElements(ttl, api)
	if cnt < len(msg.Elements) {
		log.Printf("processed %d out of %d elements", cnt, len(msg.Elements))
	}
	return err
}

func (msg *JSONResponse) decryptElements(pos int, dst []string) (decrypted int, processed int) {
	var (
		errCnt = 0
		el     *parser.Element
	)
	if pos >= len(msg.Elements) {
		return 0, 0
	}
	for processed, el = range msg.Elements[pos:] {
		if el == nil {
			continue
		}
		if decrypted > len(dst) {
			break
		}
		if b, err := el.R.Decrypt(); err != nil {
			// TODO debug
			//fmt.Printf("error decrypting \"%v\": %s\n", el.r, err)
			errCnt++
			continue
		} else {
			// TODO debug
			// fmt.Printf("decrypted element: %s\n", b)
			dst[decrypted] = b
			decrypted++
		}
	}
	if decrypted < len(dst) {
		log.Printf("%d out of %d elements were decrypted", decrypted, len(dst))
	}
	if errCnt > 0 {
		log.Printf("%d decryption errors", errCnt)
	}
	return
}

func (msg *JSONResponse) parseIpElements(pos int, dst []net.IP) (parsed int, processed int) {
	var (
		errCnt = 0
		el     *parser.Element
	)
	if pos >= len(msg.Elements) {
		return 0, 0
	}
	for processed, el = range msg.Elements {
		if el == nil {
			continue
		}
		if parsed > len(dst) {
			break
		}
		ip, ok := el.R.(*parser.IP)
		if !ok {
			// TODO debug
			//fmt.Printf("error decrypting \"%v\": %s\n", el.r, err)
			errCnt++
			continue
		}
		if b, err := ip.Parse(); err != nil {
			// TODO debug
			//fmt.Printf("error decrypting \"%v\": %s\n", el.r, err)
			errCnt++
			continue
		} else {
			// TODO debug
			// fmt.Printf("decrypted element: %s\n", b)
			dst[parsed] = b
			parsed++
		}
	}
	if parsed < len(dst) {
		log.Printf("%d out of %d elements were parsed", parsed, len(dst))
	}
	if errCnt > 0 {
		log.Printf("%d parse errors", errCnt)
	}
	return
}

func (msg *JSONResponse) processElements(ttl time.Duration, api *Api) (int, error) {
	if len(msg.Elements) == 0 {
		return 0, nil
	}
	switch api.Code {
	case IpBanned:
		return msg.processIpBanned(ttl)
	case IpAllowed:
		return msg.processIpAllowed(ttl)
	case IpHoneynet:
		return msg.processIpHoneynet(ttl, api.IpBinary)
	default:
		return 0, ErrUnknownApi
	}
}

// specific response processing function per API code
func (msg *JSONResponse) processIpBanned(ttl time.Duration) (int, error) {
	ips := make([]string, len(msg.Elements))
	msg.decryptElements(0, ips)
	return firewall.AddToBlacklist(ips, ttl)
}

func (msg *JSONResponse) processIpAllowed(ttl time.Duration) (int, error) {
	ips := make([]string, len(msg.Elements))
	msg.decryptElements(0, ips)
	return firewall.AddToWhitelist(ips, ttl)
}

func (msg *JSONResponse) processIpHoneynet(ttl time.Duration, bin bool) (int, error) {
	if bin {
		ips := make([]net.IP, len(msg.Elements))
		msg.parseIpElements(0, ips)
		return firewall.AddToPublicBlacklistBin(ips, ttl)
	}
	return firewall.AddToPublicBlacklist(msg.Elements, ttl)
}

// ErrResponse
type ErrResponse struct {
	StatusCode        int    `json:"statusCode"`
	StatusDescription string `json:"statusDescription"`
}

func (msg *ErrResponse) Process(api *Api) error {
	log.Printf(`received an error response for api "%s": %d %s`, api.Path, msg.StatusCode, msg.StatusDescription)
	// do not send any subsequent request within this API call
	api.Key = nil
	return nil
}

// API generic processing
type Api struct {
	Name     string
	Client   http.Client
	ConfigId string
	BaseUrl  string
	Path     string
	// timestamp to use for the next request
	Timestamp string
	// Key for the next subsequent request within one API call
	Key *string
	// query parameters dictionary.
	// mandatory parameters used by all API calls:
	// - "token": SSO authentication and authorization token
	// - "limit": upper limit for how many elements (records) are sent in a response
	Values   url.Values
	Code     APICode
	IpBinary bool
}

var (
	defaultHttpClientTimeout = 2 * time.Second
	// client used for all API requests
	defaultHttpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: defaultHttpClientTimeout,
	}
	// API register
	Apis [numberOfApis]*Api
)

// API codes
type APICode int

const (
	IpBanned APICode = iota
	IpAllowed
	// banned IP addresses published by the public honeynet
	IpHoneynet
	UriBanned
	UriAllowed
	numberOfApis
)

// API paths
const (
	BwV4List = "bwnoa/v4list"
)

// Init the members of Api data structure.
// name, configId, baseUrl and path are used as such to initialize api structure members.
// Non-empty token and limit are loaded into the api.Values map and used as query parameters in the URL.
// Internally the API is represented using code. The http client will use the specified (optional) timeout.
func (api *Api) Init(name, configId, baseUrl, path, token, limit string, code APICode, timeout ...time.Duration) {
	for k := range api.Values {
		delete(api.Values, k)
	}
	api.Client.Timeout = defaultHttpClientTimeout
	if len(timeout) > 0 {
		api.Client.Timeout = timeout[0]
	}
	api.Name = name
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
	if len(limit) > 0 {
		api.Values.Add("Limit", limit)
	}
}

// String returns an string representation for API
func (api Api) String() string {
	return `API "` + api.Name + `" URL: ` + api.Url()
}

// Url returns an string representation for the API's URL
func (api Api) Url() string {
	var apiUrl string

	query := api.Values.Encode()

	if len(query) > 0 {
		apiUrl = fmt.Sprintf("%s%s?%s", api.BaseUrl, api.Path, query)
	} else {
		apiUrl = fmt.Sprintf("%s%s", api.BaseUrl, api.Path)
	}

	return apiUrl
}

// setTimestamp sets a `Timestamp` query parameter into the API `Values` based on the `Timestamp` member value.
func (api *Api) setTimestamp() {
	if api.Timestamp == "" {
		// start from 0 if an empty start timestamp was provided
		api.Timestamp = "0"
	}
	api.Values.Set("timestamp", api.Timestamp)
}

// setKey sets a `nextEncodedKey` query parameter into the API `Values` based on the `Key` member value.
// If `Key` is nil the query parameter is deleted from `Values`.
func (api *Api) setKey() {
	if api.Key != nil {
		api.Values.Set("nextEncodedKey", *api.Key)
	} else {
		api.Values.Del("nextEncodedKey")
	}
}

func (api *Api) delKey() {
	api.Key = nil
	api.setKey()
}

// Request adds all generic query parameters to URL, sends an API request with Get() and returns the parsed response.
// If "timestamp" is an empty string it sets it to 0.
func (api *Api) Request() (Response, error) {
	// set query parameters
	api.setTimestamp()
	api.setKey()

	url := api.Url()

	// TODO debug
	log.Printf(`"%s" api url: %s`, api.Path, url)
	buf, err := api.Get(url)
	if err != nil {
		return nil, err
	}

	response, err := api.parseResponse(buf)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Get sends an HTTP/GET request
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

// Response processes the answer received from the API server.
// It returns a boolean flag which shows if this is the last response and a possible error.
func (api *Api) Response(msg Response) (bool, error) {
	if err := msg.Process(api); err != nil {
		return true, err
	}
	return api.Key == nil, nil
}

// Process sends an HTTP request and processes the received request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func (api *Api) Process() (err error) {
	err = nil
	for true {
		// build and send the API request
		res, err := api.Request()
		if err != nil {
			err = fmt.Errorf(`%s request error: %w`, api.Path, err)
			break
		}
		if res == nil {
			err = fmt.Errorf(`%s response with empty body`, api.Path)
			break
		}
		// process the API response
		last, err := api.Response(res)
		if err != nil {
			err = fmt.Errorf(`%s response processing error %w`, api.Path, err)
			break
		}
		if last {
			break
		}
	}
	// remove the key parameter from the query since it is not used in the
	// first request of the API call.
	api.delKey()
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

	return nil, fmt.Errorf("%s: %w", parser.ErrJsonParser.Error(), err)
}
