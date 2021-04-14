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
	"crypto"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"

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

// Check queries APIBAN.org to see if the provided IP address is blocked.
/*
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
	} else if len(entry.Elements) == 1 {
		if entry.Elements[0].Ipaddr == "not blocked" {
			// Not blocked
			return false, nil
		}
	}

	// IP address is blocked
	return true, nil
}
*/

func processAnswer(msg io.Reader) (*JSONResponse, error) {
	entry := new(JSONResponse)
	if err := json.NewDecoder(msg).Decode(entry); err != nil {
		return nil, err
	}
	log.Printf("JSON response: %v", entry)
	return entry, nil
}
