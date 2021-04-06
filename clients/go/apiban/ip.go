package apiban

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/intuitivelabs/anonymization"
	"github.com/vladabroz/go-ipset/ipset"
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

// IPResponse describes a set of blocked IP addresses from APIBAN.org
type IPResponse struct {
	Metadata JSONMap `json:"metadata"`

	// ID is the timestamp of the next IPResponse
	ID string `json:"ID"`

	// IPs is the list of blocked/allowed IP addresses in this entry
	IPs []IPObj `json:"elements"`
}

type Api struct {
	ConfigId     string
	BaseUrl      string
	Path         string
	Values       url.Values
	Code         APICode
	ResponseProc func(*IPObj, int) error
}

var (
	bannedApi  Api = Api{Values: url.Values{}}
	allowedApi Api = Api{Values: url.Values{}}
)

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

func (api Api) Req(startFrom string) (*IPResponse, error) {
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
		if timestamp, err = getTimestampFromMetadata(e.Metadata); err != nil {
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

// ApiBannedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func (api Api) Process(startFrom string) (id string, err error) {
	id = ""
	res, err := api.Req(startFrom)
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
		ProcResponse(res, api.ConfigId, api.Code)
		id = res.ID
	}
	return
}

func ApiIPReq(startFrom, token, baseUrl string, values url.Values) (*IPResponse, error) {
	if len(token) > 0 {
		values.Add("token", token)
	}
	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}
	values.Add("timestamp", startFrom)
	return ApiRequestWithQueryValues(baseUrl, "bwnoa/v4list", values)
}

// ApiBannedIPReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiBannedIPReq(startFrom, token, baseUrl string) (*IPResponse, error) {
	values := url.Values{}
	values.Add("list", "ipblack")
	return ApiIPReq(startFrom, token, baseUrl, values)
}

// ApiAllowedIPReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiAllowedIPReq(startFrom, token, baseUrl string) (*IPResponse, error) {
	values := url.Values{}
	values.Add("list", "ipwhite")
	return ApiIPReq(startFrom, token, baseUrl, values)
}

// ApiBannedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiBannedIP(startFrom, token, baseUrl, configId string) (id string, err error) {
	id = ""
	res, err := ApiBannedIPReq(startFrom, token, baseUrl)
	if err != nil {
		err = fmt.Errorf(`"banned" request error: %w`, err)
	} else if res == nil {
		err = fmt.Errorf(`"banned" response with empty body`)
	} else {
		if IpTables() != nil && IpTables().Sets[IpTables().Bl] != nil {
			ProcResponse(res, configId, APIBanned)
			id = res.ID
		}
	}
	return
}

// ApiAllowedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiAllowedIP(startFrom, token, baseUrl, configId string) (id string, err error) {
	id = ""
	res, err := ApiAllowedIPReq(startFrom, token, baseUrl)
	if err != nil {
		err = fmt.Errorf(`"allowed" request error: %w`, err)
	} else if res == nil {
		err = fmt.Errorf(`"allowed" response with empty body`)
	} else {
		if IpTables() != nil && IpTables().Sets[IpTables().Wl] != nil {
			ProcResponse(res, configId, APIAllowed)
			id = res.ID
		}
	}
	return
}

// Banned returns a set of banned addresses, optionally limited to the
// specified startFrom ID.  If no startFrom is supplied, the entire current list will
// be pulled.
func Banned(key string, startFrom string, version string, baseUrl string) (*IPResponse, error) {
	if key == "" {
		return nil, errors.New("API Key is required")
	}

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &IPResponse{
		ID: startFrom,
	}

	url := fmt.Sprintf("%s%s/banned/%s?version=%s", baseUrl, key, out.ID, version)
	log.Println("banned url: ", url)
	e, err := queryServer(httpClient, url)
	if err != nil {
		return nil, err
	}

	// empty body
	if e == nil {
		return nil, nil
	}

	if e.ID == "" {
		fmt.Println("e.ID empty")
		return nil, errors.New("empty ID received")
	}

	if e.ID == "none" || len(e.IPs) == 0 {
		// do not save the ID
		return out, nil
	}

	// store metadata
	out.Metadata = e.Metadata

	// Set the next ID and store it as state
	out.ID = e.ID
	GetState().Timestamp = e.ID

	// Aggregate the received IPs
	out.IPs = append(out.IPs, e.IPs...)

	return out, nil
}

// ProcBannedResponse processes the response returned by the GET(banned) API
func ProcBannedResponse(entry *IPResponse, id string, blset ipset.IPSet) {
	if entry.ID == id || len(entry.IPs) == 0 {
		//log.Print("Great news... no new bans to add. Exiting...")
		log.Print("No new bans to add...")
		//os.Exit(0)
	}

	ttl := int(GetConfig().BlacklistTtl)
	if ttl == 0 {
		// try to get the ttl from the answers metada
		ttl, _ = getTtlFromMetadata(entry.Metadata)
	}
	log.Print("ttl: ", ttl)
	for _, s := range entry.IPs {
		/*
			//BUG in ipset library? Test method does not seem to work properly - returns;  Failed to test ipset list entry-error testing entry 184.159.238.21: exit status 1 (184.159.238.21 is NOT in set blacklist.
			log.Print("Working on entry", s)
			exists, erro := blset.Test(s)
			if exists == false {
				log.Print("Failed to test ipset list entry-", erro)
			}
			if exists == true {
				log.Print("IPResponse already existing...")
				continue
			}
			if exists == false {
				log.Print("IPResponse NOT existing...")
			}
		*/
		var (
			err   error
			ipStr string
		)
		if ipStr, err = decryptIp(s.IP, s.Encrypt); err != nil {
			log.Printf("Error while decrypting ip %s: %s", ipStr, err)
			continue
		}
		err = blset.Add(ipStr, ttl)
		if err != nil {
			log.Print("Adding IP to ipset failed. ", err.Error())
		} else {
			log.Print("Processing IP: ", ipStr)
		}
	}
}

func procIP(ips []IPObj, ttl int, code APICode) {
	for _, s := range ips {
		err := s.Process(ttl, code)
		if err != nil {
			log.Printf("failed to process IP: %s", err.Error())
		}
	}
}
