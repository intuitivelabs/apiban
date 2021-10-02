package parser

import (
	"encoding/json"
	"errors"
)

var (
	// API JSON errors
	ErrJsonParser                              = errors.New(`cannot parse JSON response`)
	ErrJsonMetadataDefaultBlacklistTtlMissing  = errors.New(`malformed JSON response: "defaultBlacklistTtl not present in metadata`)
	ErrJsonMetadataGeneratedatMissing          = errors.New(`malformed JSON response: "lastTimestamp not present in metadata`)
	ErrJsonMetadataDefaultBlacklistTtlDataType = errors.New(`malformed JSON response: "defaultBlacklistTtl has wrong data type`)
	ErrJsonEmptyIPAddressField                 = errors.New("malformed JSON response: IP address field is empty")
)

// API response JSON objects
var (
	IPMapKeys    = [...]string{"IP", "fromua", "encrypt", "exceeded", "count", "timestamp"}
	MetadataKeys = [...]string{"defaultBlacklistTtl"}
)

type JSONMap map[string]interface{}

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

func (metadata JSONMap) NextEncodedKey() *string {
	if metaKey, ok := metadata["nextEncodedKey"]; ok {
		key, _ := metaKey.(string)
		if len(key) == 0 {
			return nil
		}
		return &key
	}
	return nil
}

// Resource is a generic term for IP addressses, URIs; this interface should be implemented by all resources
type Resource interface {
	// Process locally the resource received from the server (by applying b/w listing, fw rules aso)
	// Process(ttl time.Duration, api APICode) error
	Decrypt() (string, error)
	String() string
}

// generic response object used for unmarshalling either IP or URI JSON objects
type Element struct {
	R Resource
}

type Elements []*Element

// UnmarshalJSON decodes the element by using trial and error between IP and URI JSON objects
func (elem *Element) UnmarshalJSON(msg []byte) error {
	var (
		ip  IP
		uri URI
	)
	elem.R = nil
	if string(msg) == "null" {
		return nil
	}

	if err := json.Unmarshal(msg, &ip); err == nil {
		if len(ip.Ipaddr) > 0 {
			elem.R = &ip
			return nil
		}
	}

	if err := json.Unmarshal(msg, &uri); err == nil {
		if len(uri.URI) > 0 {
			elem.R = &uri
			return nil
		}
	}

	return ErrJsonParser
}
