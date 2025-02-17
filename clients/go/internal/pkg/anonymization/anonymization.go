package anonymization

import (
	"crypto"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/intuitivelabs/anonymization"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/config"
)

// errors
var (
	// encryption errors
	ErrDecryptNoKey    = errors.New("no passphrase or decryption key configured")
	ErrDecryptWrongKey = errors.New("wrong decryption key")
)

// anonymization objects
var (
	Ipcipher  cipher.Block            = nil
	Validator anonymization.Validator = nil
)

const (
	HmacLen = 5
)

func InitEncryption(c *config.Config) {
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
		//debug
		//log.Print("encryption key: ", hex.EncodeToString(encKey[:]))
	} else if len(c.EncryptionKey) > 0 {
		// use the configured encryption key
		// copy the configured key into the one used during realtime processing
		if decoded, dErr := hex.DecodeString(c.EncryptionKey); dErr != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		} else {
			subtle.ConstantTimeCopy(1, encKey[:], decoded)
		}
	}
	// generate authentication (HMAC) key from encryption key
	anonymization.GenerateKeyFromBytesAndCopy(encKey[:], anonymization.AuthenticationKeyLen, authKey[:])
	// initialize a validator using the configured passphrase; neither length nor salt are used since this validator verifies only the remote code
	if Validator, err = anonymization.NewKeyValidator(crypto.SHA256, authKey[:], HmacLen /*length*/, "" /*salt*/, anonymization.NonceNone, false /*withNonce*/, true /*pre-allocated HMAC*/); err != nil {
		log.Fatalln("Cannot initialize validator. Exiting.")
	}
	if Ipcipher, err = anonymization.NewCipher(encKey[:]); err != nil {
		log.Fatalln("Cannot initialize ipcipher. Exiting.")
	} else {
		Ipcipher = Ipcipher.(*anonymization.Ipcipher)
	}
}

func isPlainTxt(code string) bool {
	if (code == "0") || (code == "plain") {
		return true
	}
	split := strings.Split(code, ":")
	if split[0] == "plain" {
		return true
	}
	return false
}

func Validate(kvCode string) (encrypted bool, err error) {
	err = nil
	encrypted = false
	// TODO debug
	//log.Print("encrypt field: ", kvCode)
	if isPlainTxt(kvCode) {
		// not encrypted; passthrough
		return
	}
	// check if encrypt flags are part of the encrypt field
	split := strings.Split(kvCode, "|")
	switch len(split) {
	case 1:
		// flags are not there; nothing special to do
	case 2:
		// flags are present; get the code
		kvCode = split[1]
		// TODO debug
		//log.Print("key validation code: ", kvCode)
	default:
		// broken format
		err = fmt.Errorf("encrypt field unknown format: %s", kvCode)
		return
	}
	if (Validator == nil) || (Ipcipher == nil) {
		err = ErrDecryptNoKey
		return
	}
	if !Validator.Validate(kvCode) {
		err = ErrDecryptWrongKey
		return
	}
	encrypted = true
	return
}

func DecryptIp(encrypted string, kvCode string) (decrypted string, err error) {
	// check the string type for "encrypt" field
	err = nil
	isEncrypted := false
	decrypted = encrypted
	if isEncrypted, err = Validate(kvCode); err != nil {
		err = fmt.Errorf("IP address decrypt error: %w", err)
		return
	}
	if isEncrypted {
		decrypted = Ipcipher.(*anonymization.Ipcipher).DecryptStr(encrypted)
	}
	return
}
