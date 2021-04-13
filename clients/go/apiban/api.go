package apiban

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
		err         error
		ipResponse  IPResponse
		errResponse ErrResponse
	)

	// try IPResponse first
	if err = json.Unmarshal(msg, &ipResponse); err == nil {
		if ipResponse.Metadata != nil && len(ipResponse.Metadata) > 0 {
			return &ipResponse, nil
		}
	}

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

// ErrResponse
type ErrResponse struct {
	StatusCode        int    `json:"statusCode"`
	StatusDescription string `json:"statusDescription"`
}

func (msg *ErrResponse) Process(api *Api) error {
	log.Printf(`received an error response for api "%s": %d %s`, api.Path, msg.StatusCode, msg.StatusDescription)
	return nil
}
