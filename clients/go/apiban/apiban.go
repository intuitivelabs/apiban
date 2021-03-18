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
	"strings"

	"github.com/intuitivelabs/anonymization"
	"github.com/vladabroz/go-ipset/ipset"
)

var (
	// RootURL is the base URI of the intuitive labs server
	RootURL = "https://siem.intuitivelabs.com/"
)

// anonymization objects
var (
	Ipcipher  cipher.Block
	Validator anonymization.Validator
)

// ErrBadRequest indicates a 400 response was received;
//
// NOTE: this is used by the server to indicate both that an IP address is not
// blocked (when calling Check) and that the list is complete (when calling
// Banned)
var ErrBadRequest = errors.New("Bad Request")

// use insecure if configured - TESTING PURPOSES ONLY!
var transCfg = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

var httpClient = &http.Client{Transport: transCfg}

var IPMapKeys = [...]string{"IP", "fromua", "encrypt", "exceeded", "count", "timestamp"}

type IPMap map[string]interface{}

var MetadataKeys = [...]string{"defaultBlacklistTtl"}

type MetadataMap map[string]interface{}

// Entry describes a set of blocked IP addresses from APIBAN.org
type Entry struct {
	// omit Meta when decoding
	Metadata MetadataMap `json:"metadata"`

	// ID is the timestamp of the next Entry
	ID string `json:"ID"`

	// IPs is the list of blocked IP addresses in this entry
	IPs []IPMap `json:"ipaddress"`
}

func InitEncryption(c *Config) {
	var err error
	if c == nil {
		log.Fatalln("Cannot initialize anonymizer module. Exiting.")
		return
	}
	if len(c.Passphrase) > 0 {
		// generate encryption key from passphrase
		if Ipcipher, err = anonymization.NewPassphraseCipher(c.Passphrase); err != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		}
		// initialize a validator using the configured passphrase; neither length nor salt are used since this validator verifies only the remote code
		if Validator, err = anonymization.NewPassphraseValidator(c.Passphrase, 0 /*length*/, "" /*salt*/); err != nil {
			log.Fatalln("Cannot initialize validator. Exiting.")
		}
	} else {
		// use the configured encryption key
		var encKey [anonymization.EncryptionKeyLen]byte
		// copy the configured key into the one used during realtime processing
		if decoded, err := hex.DecodeString(c.EncryptionKey); err != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		} else {
			subtle.ConstantTimeCopy(1, encKey[:], decoded)
		}
		if Ipcipher, err := anonymization.NewCipher(encKey[:]); err != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		} else {
			Ipcipher = Ipcipher.(*anonymization.Ipcipher)
		}
	}
}

func decryptIp(encrypted string, kvCode interface{}) (decrypted string, ok bool) {
	// check the string type for "encrypt" field
	decrypted = ""
	kvCodeStr, ok := kvCode.(string)
	if !ok {
		log.Print("encrypt field broken format")
		return
	}
	if kvCodeStr != "0" {
		log.Print("key validation code: ", kvCodeStr)
		split := strings.Split(kvCodeStr, "|")
		switch len(split) {
		case 1:
			// flags are not there; nothing special to do
		case 2:
			// flags are present; get the code
			kvCodeStr = split[1]
		default:
			// broken format
			log.Print("encrypt field broken format")
			ok = false
			return
		}
		log.Print("key validation code: ", kvCodeStr)
		if (Validator == nil) || (Ipcipher == nil) {
			log.Print("IP encrypted but no passphrase configured")
			ok = false
			return
		}
		if !Validator.Validate(kvCodeStr) {
			log.Print("IP encrypted but wrong passphrase configured")
			ok = false
			return
		}
		ok = true
		decrypted = Ipcipher.(*anonymization.Ipcipher).DecryptStr(encrypted)
	} else {
		// not encrypted; passthrough
		ok = true
		decrypted = encrypted
	}
	return
}

// Banned returns a set of banned addresses, optionally limited to the
// specified startFrom ID.  If no startFrom is supplied, the entire current list will
// be pulled.
func Banned(key string, startFrom string, version string, baseUrl string) (*Entry, error) {
	if key == "" {
		return nil, errors.New("API Key is required")
	}

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &Entry{
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

	// Set the next ID and store it as state
	out.ID = e.ID
	GetState().Timestamp = e.ID

	// Aggregate the received IPs
	out.IPs = append(out.IPs, e.IPs...)

	return out, nil
}

// ProceBannedResponse processes the response returned by the GET(banned) API
func ProcBannedResponse(entry *Entry, id string, blset ipset.IPSet) {
	if entry.ID == id || len(entry.IPs) == 0 {
		//log.Print("Great news... no new bans to add. Exiting...")
		log.Print("No new bans to add...")
		//os.Exit(0)
	}

	ttl := GetConfig().blTtl
	if ttl == 0 {
		// try to get the ttl from the answers metada
		metaTtl, ok := entry.Metadata["defaultBlacklistTtl"]
		if ok {
			ttl, _ = metaTtl.(int)
		}
	}
	for _, s := range entry.IPs {
		/*
			//BUG in ipset library? Test method does not seem to work properly - returns;  Failed to test ipset list entry-error testing entry 184.159.238.21: exit status 1 (184.159.238.21 is NOT in set blacklist.
			log.Print("Working on entry", s)
			exists, erro := blset.Test(s)
			if exists == false {
				log.Print("Failed to test ipset list entry-", erro)
			}
			if exists == true {
				log.Print("Entry already existing...")
				continue
			}
			if exists == false {
				log.Print("Entry NOT existing...")
			}
		*/
		// check if the "IP" field is present
		ip, ok := s["IP"]
		if !ok {
			continue
		}
		// check the string type for the "IP" field
		ipStr, ok := ip.(string)
		if !ok {
			continue
		}
		// check if "encrypt" field is present
		if kvCode, ok := s["encrypt"]; ok {
			ipStr, ok = decryptIp(ipStr, kvCode)
			if !ok {
				log.Print("encrypt field broken format")
				continue
			}
		}
		err := blset.Add(ipStr, GetConfig().blTtl)
		if err != nil {
			log.Print("Adding IP to ipset failed. ", err.Error())
		} else {
			log.Print("Processing IP: ", ip)
		}
	}
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
		if entry.IPs[0]["IP"] == "not blocked" {
			// Not blocked
			return false, nil
		}
	}

	// IP address is blocked
	return true, nil
}

func processAnswer(msg io.Reader) (*Entry, error) {
	entry := new(Entry)
	if err := json.NewDecoder(msg).Decode(entry); err != nil {
		return nil, err
	}
	return entry, nil
}

func queryServer(c *http.Client, u string) (*Entry, error) {
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
	var entry *Entry
	if entry, err = processAnswer(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	//fmt.Println("entry from queryServer", entry)
	return entry, nil
}

func processBadRequest(resp *http.Response) (*Entry, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Read the bytes buffer into a new bytes.Reader
	r := bytes.NewReader(buf.Bytes())

	// First, try decoding as a normal entry
	e := new(Entry)
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
			switch e.IPs[0]["IP"] {
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
