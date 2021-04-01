package apiban

import (
	"errors"
	"fmt"
	"log"
	"net/url"
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

// ApiBannedIPReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiBannedIPReq(key, startFrom, version, baseUrl string) (*IPResponse, error) {
	values := url.Values{}
	values.Add("version", version)
	return ApiRequestWithQueryValues(key, startFrom, baseUrl, "banned", values)
}

// ApiAllowedIPReq sends an HTTP request using an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiAllowedIPReq(key, startFrom, version, baseUrl string) (*IPResponse, error) {
	values := url.Values{}
	values.Add("version", version)
	values.Add("list", "ipwhite")
	return ApiRequestWithQueryValues(key, startFrom, baseUrl, "banned", values)
}

// ApiBannedIP sends an HTTP request and processes the received request; it returns the "id" that should be used in the next request.
// It uses an URL built like this from the input parameters:
// https://baseUrl/key/banned/startFrom?version=version
func ApiBannedIP(key, startFrom, version, baseUrl, configId string) (id string, err error) {
	id = ""
	res, err := ApiBannedIPReq(key, startFrom, version, baseUrl)
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
func ApiAllowedIP(key, startFrom, version, baseUrl, configId string) (id string, err error) {
	id = ""
	res, err := ApiAllowedIPReq(key, startFrom, version, baseUrl)
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

	ttl := GetConfig().blTtl
	if ttl == 0 {
		var err error
		// try to get the ttl from the answers metada
		if ttl, err = getTtlFromMetadata(entry.Metadata); err != nil {
			log.Printf("failed to get blacklist ttl from metadata: %s", err)
			ttl = 0
		} else if ttl < 0 {
			// negative ttl does not make sense
			ttl = 0
		}
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
