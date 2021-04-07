package apiban

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/intuitivelabs/anonymization"
)

var (
	bannedApi  Api = Api{Values: url.Values{}}
	allowedApi Api = Api{Values: url.Values{}}
)

func decryptIp(encrypted string, kvCode interface{}) (decrypted string, err error) {
	// check the string type for "encrypt" field
	err = nil
	decrypted = encrypted
	kvCodeStr, ok := kvCode.(string)
	if !ok {
		err = ErrJsonEncryptFieldNotString
		return
	}
	log.Print("encrypt field: ", kvCodeStr)
	if isPlainTxt(kvCodeStr) {
		// not encrypted; passthrough
		return
	}
	// check if encrypt flags are part of the encrypt field
	split := strings.Split(kvCodeStr, "|")
	switch len(split) {
	case 1:
		// flags are not there; nothing special to do
	case 2:
		// flags are present; get the code
		kvCodeStr = split[1]
		log.Print("key validation code: ", kvCodeStr)
	default:
		// broken format
		err = fmt.Errorf("encrypt field unknown format: %s", kvCodeStr)
		return
	}
	if (Validator == nil) || (Ipcipher == nil) {
		err = ErrEncryptNoKey
		return
	}
	if !Validator.Validate(kvCodeStr) {
		err = ErrEncryptWrongKey
		return
	}
	decrypted = Ipcipher.(*anonymization.Ipcipher).DecryptStr(encrypted)
	return
}

// IPObj JSON objects in API responses
type IPObj struct {
	Encrypt string `json:"encrypt"`
	IP      string `json:"ipaddr"`
}

func (ip *IPObj) Process(ttl int, api APICode) error {
	switch api {
	case APIBanned:
		return ip.Blacklist(ttl)
	case APIAllowed:
		return ip.Whitelist(ttl)
	}
	return fmt.Errorf("unknown API: %d", api)
}

func (ip *IPObj) Whitelist(ttl int) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToWhitelist(ipStr, ttl); err == nil {
			log.Printf("processed IP: %s", ipStr)
		}
	}
	return err
}

func (ip *IPObj) Blacklist(ttl int) error {
	var (
		err   error
		ipStr string
	)
	if ipStr, err = ip.Decrypt(); err == nil {
		if err = IpTables().AddToBlacklist(ipStr, ttl); err == nil {
			log.Printf("processed IP: %s", ipStr)
		}
	}
	return err
}

func (ip *IPObj) Decrypt() (string, error) {
	if len(ip.IP) > 0 {
		return decryptIp(ip.IP, ip.Encrypt)
	}
	return "", ErrJsonEmptyIPAddressField
}

type Response interface {
	Process(Api) error
}

// IPResponse describes a set of blocked IP addresses from APIBAN.org
type IPResponse struct {
	Metadata JSONMap `json:"metadata"`

	// ID is the timestamp of the next IPResponse
	ID string `json:"ID"`

	// IPs is the list of blocked/allowed IP addresses in this entry
	IPs []IPObj `json:"elements"`
}

// ProcResponse processes the response returned by the GET API.
func (msg *IPResponse) Process(api Api) error {
	if msg.ID == api.ConfigId || len(msg.IPs) == 0 {
		log.Print("No new bans to add...")
		return nil
	}

	ttl := int(GetConfig().BlacklistTtl / time.Second) // round-down to seconds
	if ttl == 0 {
		// try to get the ttl from the answers metadata
		ttl, _ = msg.Metadata.Ttl()
	}
	log.Print("ttl: ", ttl)
	// process IP objects
	msg.procIP(ttl, api)
	return nil
}

func (msg *IPResponse) procIP(ttl int, api Api) {
	for _, s := range msg.IPs {
		err := api.ResponseProc(&s, ttl)
		if err != nil {
			log.Printf("failed to process IP: %s", err.Error())
		}
	}
}

type Api struct {
	ConfigId     string
	BaseUrl      string
	Path         string
	Values       url.Values
	Code         APICode
	ResponseProc func(*IPObj, int) error
}

func NewBannedApi(configId, baseUrl, token string) *Api {
	bannedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIBanned)
	bannedApi.Values.Add("list", "ipblack")
	bannedApi.ResponseProc = (*IPObj).Blacklist
	return &bannedApi
}

func NewAllowedApi(configId, baseUrl, token string) *Api {
	allowedApi.init(configId, baseUrl, "bwnoa/v4list", token, APIAllowed)
	allowedApi.Values.Add("list", "ipwhite")
	allowedApi.ResponseProc = (*IPObj).Whitelist
	return &allowedApi
}

func (api *Api) init(configId, baseUrl, path, token string, code APICode) {
	for k, _ := range api.Values {
		delete(api.Values, k)
	}
	api.Code = code
	api.ConfigId = configId
	api.BaseUrl = baseUrl
	api.Path = path
	if len(token) > 0 {
		api.Values.Add("token", token)
	}
}

func (api Api) Request(startFrom string) (*IPResponse, error) {
	if startFrom == "" {
		// start from 0 if an empty start timestamp was provided
		startFrom = "0"
	}
	api.Values.Set("timestamp", startFrom)
	return api.RequestWithQueryValues()
}

func (api Api) RequestWithQueryValues() (*IPResponse, error) {
	var apiUrl string
	var id string

	startFrom := api.Values.Get("timestamp")

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &IPResponse{
		ID: startFrom,
	}

	query := api.Values.Encode()

	if len(query) > 0 {
		apiUrl = fmt.Sprintf("%s%s?%s", api.BaseUrl, api.Path, query)
	} else {
		apiUrl = fmt.Sprintf("%s%s", api.BaseUrl, api.Path)
	}
	log.Printf(`"%s" api url: %s`, api.Path, apiUrl)
	e, err := queryServer(httpClient, apiUrl)
	if err != nil {
		return nil, err
	}

	// empty body
	if e == nil {
		return nil, nil
	}

	// terminate the processing
	if e.ID == "none" || len(e.IPs) == 0 {
		// do not save the ID
		return out, nil
	}

	if e.ID == "" {
		log.Println("e.ID empty")
		var timestamp int
		if timestamp, err = e.Metadata.Timestamp(); err != nil {
			return nil, err
		}
		id = strconv.Itoa(timestamp)
	} else {
		id = e.ID
	}

	// store metadata
	out.Metadata = e.Metadata

	// Set the next ID and store it as state
	out.ID = id
	GetState().Timestamp = id

	// Aggregate the received IPs
	out.IPs = append(out.IPs, e.IPs...)

	return out, nil
}

func (api Api) Response(msg Response) {
	msg.Process(api)
}

// ApiBannedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func (api Api) Process(startFrom string) (id string, err error) {
	id = ""
	res, err := api.Request(startFrom)
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
		id = res.ID
	}
	return
}
