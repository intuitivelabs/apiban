package apiban

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/intuitivelabs/anonymization"
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

// IPResponse describes the response for bwnoa/v4list API
type IPResponse struct {
	Metadata JSONMap `json:"metadata"`

	// ID is the timestamp of the next IPResponse
	ID string `json:"ID,omitempty"`

	// IPs is the list of blocked/allowed IP addresses in this entry
	IPs []IPObj `json:"elements"`
}

// ProcResponse processes the response returned by the GET API.
func (msg *IPResponse) Process(api *Api) error {
	if len(msg.IPs) == 0 {
		log.Print("No new bans to add...")
		return nil
	}

	ttl := int(GetConfig().BlacklistTtl / time.Second) // round-down to seconds
	if ttl == 0 {
		// try to get the ttl from the answers metadata
		ttl, _ = msg.Metadata.Ttl()
	}
	log.Print("ttl: ", ttl)
	if timestamp, err := msg.Metadata.Timestamp(); err != nil {
		return err
	} else {
		api.Timestamp = strconv.Itoa(timestamp)
	}

	// process IP objects
	msg.procIP(ttl, api)
	return nil
}

func (msg *IPResponse) procIP(ttl int, api *Api) {
	for _, s := range msg.IPs {
		err := api.ResponseProc(&s, ttl)
		if err != nil {
			log.Printf("failed to process IP: %s", err.Error())
		}
	}
}
