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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var (
	// RootURL is the base URI of the APIBAN.org API server
	RootURL = "https://apiban.org/api/"
)

// ErrBadRequest indicates a 400 response was received;
//
// NOTE: this is used by the server to indicate both that an IP address is not
// blocked (when calling Check) and that the list is complete (when calling
// Banned)
var ErrBadRequest = errors.New("Bad Request")

// Entry describes a set of blocked IP addresses from APIBAN.org
type Entry struct {

	// ID is the timestamp of the next Entry
	ID string `json:"ID"`

	// IPs is the list of blocked IP addresses in this entry
	IPs []string `json:"ipaddress"`
}

// Banned returns a set of banned addresses, optionally limited to the
// specified startFrom ID.  If no startFrom is supplied, the entire current list will
// be pulled.
func Banned(key string, startFrom string, url string) (*Entry, error) {
	if key == "" {
		return nil, errors.New("API Key is required")
	}

	if startFrom == "" {
		startFrom = "100" // NOTE: arbitrary ID copied from reference source
	}

	out := &Entry{
		ID: startFrom,
	}

	// use insecure if configured - TESTING PURPOSES ONLY!
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transCfg}

	for {
		//e, err := queryServer(http.DefaultClient, fmt.Sprintf("%s%s/banned/%s", url, key, out.ID))
		e, err := queryServer(client, fmt.Sprintf("%s%s/banned/%s", url, key, out.ID))
		fmt.Println("%s%s/banned/%s", url, key, out.ID)
		fmt.Println("e", e)
		if err != nil {
			return nil, err
		}

		if e.ID == "none" || len(e.IPs) == 0 {
			// List complete
			return out, nil
		}
		if e.ID == "" {
			fmt.Println("e.ID empty")
			return nil, errors.New("empty ID received")
		}

		// Set the next ID
		out.ID = e.ID

		// Aggregate the received IPs
		out.IPs = append(out.IPs, e.IPs...)
		fmt.Println("out.IPS %s", out.IPs)
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
		if entry.IPs[0] == "not blocked" {
			// Not blocked
			return false, nil
		}
	}

	// IP address is blocked
	return true, nil
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

	entry := new(Entry)
	if err = json.NewDecoder(resp.Body).Decode(entry); err != nil {
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
			switch e.IPs[0] {
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
