/*
 * Copyright (C) 2020 Fred Posner (palner.com)
 *
 * This file is part of APIBAN.org.
 *
 * apiban-iptables-client is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * apiban-iptables-client is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package apiban

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/intuitivelabs/anonymization"
)

var (
	// RootURL is the base URI of the intuitive labs server
	RootURL = "https://siem.intuitivelabs.com/"
)

// anonymization objects
var (
	Ipcipher  cipher.Block            = nil
	Validator anonymization.Validator = nil
)

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
	ErrJsonMetadataDefaultBlacklistTtlMissing  = errors.New(`malformed JSON response: "defaultBlacklistTtl not present in metadata`)
	ErrJsonMetadataGeneratedatMissing          = errors.New(`malformed JSON response: "lastTimestamp not present in metadata`)
	ErrJsonMetadataDefaultBlacklistTtlDataType = errors.New(`malformed JSON response: "defaultBlacklistTtl has wrong data type`)
	ErrJsonEncryptFieldNotString               = errors.New("malformed JSON response: encrypt field is not string in JSON")
	ErrJsonEmptyIPAddressField                 = errors.New("malformed JSON response: IP address field is empty")
)

func InitEncryption(c *Config) {
	var (
		err     error
		encKey  [anonymization.EncryptionKeyLen]byte
		authKey [anonymization.AuthenticationKeyLen]byte
	)
	if c == nil {
		log.Fatalln("Cannot initialize anonymizer module. Exiting.")
		return
	}
	if len(c.Passphrase) == 0 && len(c.EncryptionKey) == 0 {
		log.Print("Neither passphrase nor encryption key provided; anonymization module is not initialized.")
		return
	}
	if len(c.Passphrase) > 0 {
		// generate encryption key from passphrase
		anonymization.GenerateKeyFromPassphraseAndCopy(c.Passphrase,
			anonymization.EncryptionKeyLen, encKey[:])
		log.Print("encryption key: ", hex.EncodeToString(encKey[:]))
	} else if len(c.EncryptionKey) > 0 {
		// use the configured encryption key
		// copy the configured key into the one used during realtime processing
		if decoded, err := hex.DecodeString(c.EncryptionKey); err != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		} else {
			subtle.ConstantTimeCopy(1, encKey[:], decoded)
		}
	}
	// generate authentication (HMAC) key from encryption key
	anonymization.GenerateKeyFromBytesAndCopy(encKey[:], anonymization.AuthenticationKeyLen, authKey[:])
	// initialize a validator using the configured passphrase; neither length nor salt are used since this validator verifies only the remote code
	if Validator, err = anonymization.NewKeyValidator(crypto.SHA256, authKey[:], 5 /*length*/, "" /*salt*/, anonymization.NonceNone, false /*withNonce*/, true /*pre-allocated HMAC*/); err != nil {
		log.Fatalln("Cannot initialize validator. Exiting.")
	}
	if Ipcipher, err = anonymization.NewCipher(encKey[:]); err != nil {
		log.Fatalln("Cannot initialize ipcipher. Exiting.")
	} else {
		Ipcipher = Ipcipher.(*anonymization.Ipcipher)
	}
}

func isPlainTxt(code string) bool {
	return (code == "0") || (code == "plain")
}

func ApiRequestWithQueryValues(baseUrl, api string, values url.Values) (*IPResponse, error) {
	var apiUrl string
	var id string

	startFrom := values.Get("timestamp")

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &IPResponse{
		ID: startFrom,
	}

	query := values.Encode()

	if len(query) > 0 {
		apiUrl = fmt.Sprintf("%s%s?%s", baseUrl, api, values.Encode())
	} else {
		apiUrl = fmt.Sprintf("%s%s", baseUrl, api)
	}
	log.Printf(`"%s" api url: %s`, api, apiUrl)
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

func ApiRequest(key, startFrom, version, baseUrl, api string) (*IPResponse, error) {
	if key == "" {
		return nil, errors.New("API Key is required")
	}

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &IPResponse{
		ID: startFrom,
	}

	url := fmt.Sprintf("%s%s/%s/%s?version=%s", baseUrl, key, api, out.ID, version)
	log.Printf(`"%s" api url: %s`, api, url)
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

func getTimestampFromMetadata(metadata JSONMap) (timestamp int, err error) {
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

func getTtlFromMetadata(metadata JSONMap) (ttl int, err error) {
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

// ProcResponse processes the response returned by the GET API.
func ProcResponse(entry *IPResponse, id string, code APICode) {
	if entry.ID == id || len(entry.IPs) == 0 {
		log.Print("No new bans to add...")
	}

	ttl := int(GetConfig().BlacklistTtl / time.Second) // round-down to seconds
	if ttl == 0 {
		// try to get the ttl from the answers metadata
		ttl, _ = getTtlFromMetadata(entry.Metadata)
	}
	log.Print("ttl: ", ttl)
	// process IP objects
	procIP(entry.IPs, ttl, code)
}

// Check queries APIBAN.org to see if the provided IP address is blocked.
func Check(key string, ip string) (bool, error) {
	if key == "" {
		return false, errors.New("API Key is required")
	}
	if ip == "" {
		return false, errors.New("IP address is required")
	}

	entry, err := queryServer(http.DefaultClient, fmt.Sprintf("%s%s/check/%s", RootURL, key, ip))
	if err == ErrBadRequest {
		// Not blocked
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, errors.New("empty entry received")
	} else if len(entry.IPs) == 1 {
		if entry.IPs[0].IP == "not blocked" {
			// Not blocked
			return false, nil
		}
	}

	// IP address is blocked
	return true, nil
}

func processAnswer(msg io.Reader) (*IPResponse, error) {
	entry := new(IPResponse)
	if err := json.NewDecoder(msg).Decode(entry); err != nil {
		return nil, err
	}
	log.Printf("JSON response: %v", entry)
	return entry, nil
}

func queryServer(c *http.Client, u string) (*IPResponse, error) {
	//resp, err := http.Get(u)
	resp, err := c.Get(u)
	if err != nil {
		return nil, fmt.Errorf("Query Error: %s", err.Error())
	}
	defer resp.Body.Close()

	//fmt.Println("Status code", resp.StatusCode)
	// StatusBadRequest (400) has a number of special cases to handle
	if resp.StatusCode == http.StatusBadRequest {
		return processBadRequest(resp)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit reached (%d): %s from %q", resp.StatusCode, resp.Status, u)
	}
	if resp.StatusCode > 400 && resp.StatusCode < 500 {
		return nil, fmt.Errorf("client error (%d): %s from %q", resp.StatusCode, resp.Status, u)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error (%d): %s from %q", resp.StatusCode, resp.Status, u)
	}
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("unhandled error (%d): %s from %q", resp.StatusCode, resp.Status, u)
	}

	if resp.ContentLength == 0 {
		return nil, nil
	}
	var entry *IPResponse
	if entry, err = processAnswer(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	//fmt.Println("entry from queryServer", entry)
	return entry, nil
}

func processBadRequest(resp *http.Response) (*IPResponse, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Read the bytes buffer into a new bytes.Reader
	r := bytes.NewReader(buf.Bytes())

	// First, try decoding as a normal entry
	e := new(IPResponse)
	if err := json.NewDecoder(r).Decode(e); err == nil {
		// Successfully decoded normal entry

		switch e.ID {
		case "none":
			// non-error case
		case "unauthorized":
			return nil, errors.New("unauthorized")
		default:
			// unhandled case
			return nil, ErrBadRequest
		}

		if len(e.IPs) > 0 {
			switch e.IPs[0].IP {
			case "no new bans":
				return e, nil
			}
		}

		// Unhandled case
		return nil, ErrBadRequest
	}

	// Next, try decoding as an errorEntry
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to re-seek to beginning of response buffer: %w", err)
	}

	type errorEntry struct {
		AddressCode string `json:"ipaddress"`
		IDCode      string `json:"ID"`
	}

	ee := new(errorEntry)
	if err := json.NewDecoder(r).Decode(ee); err != nil {
		return nil, fmt.Errorf("failed to decode Bad Request response: %s", err.Error())
	}

	switch ee.AddressCode {
	case "rate limit exceeded":
		return nil, errors.New("rate limit exceeded")
	default:
		// unhandled case
		return nil, ErrBadRequest
	}
}
