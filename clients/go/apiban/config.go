package apiban

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/intuitivelabs/anonymization"
	"github.com/jessevdk/go-flags"
)

var (
	defaultConfigFilenames = [...]string{
		"/etc/apiban-ipsets/config.json",
		"config.json",
		"/usr/local/bin/apiban/config.json",
	}
)

// Config is the structure for the JSON config file
type Config struct {
	Apikey  string `long:"APIKEY" description:"api key"`
	Lkid    string `long:"LKID" description:"lk id"`
	Version string `long:"VERSION" description:"protocol version"`
	Url     string `long:"URL" description:"ban list server url"`
	Chain   string `long:"CHAIN" description:"ipset chain name"`
	Tick    string `long:"INTERVAL" description:"tick interval"`
	Full    string `long:"FULL"`
	// state filename
	StateFilename string `long:"STATE_FILENAME" description:"filename for keeping the state"`
	// ttl for the firewall DROP rules
	BlacklistTtl string `long:"BLACKLIST_TTL" description:"blacklisted entry timeout"`
	// passphrase used to generate encryption key for anonymization
	Passphrase string `long:"PASSPHRASE" description:"password for encryption"`
	// encryption key used for anonymization
	EncryptionKey string `long:"ENCRYPTION_KEY" description:"encryption key as a hex string (password and key must not be set in the same time"`

	// black list ttl translated into seconds
	blTtl    int
	filename string
}

var DefaultConfig = Config{}

// global configuration
var config = &DefaultConfig

func GetConfig() *Config {
	return config
}

// LoadConfig attempts to load the APIBAN configuration file from various locations
func LoadConfig(configFilename string) (*Config, error) {
	var filenames []string

	// If we have a user-specified configuration file, use it preferentially
	if configFilename != "" {
		filenames = append(filenames, configFilename)
	}

	// If we can determine the user configuration directory, try there
	configDir, err := os.UserConfigDir()
	if err == nil {
		filenames = append(filenames, fmt.Sprintf("%s/apiban-ipsets/config.json", configDir))
	}

	// Add standard static locations
	filenames = append(filenames, defaultConfigFilenames[:]...)

	for _, loc := range filenames {

		cfg := config
		err := flags.IniParse(loc, cfg)
		if err != nil {
			if _, ok := err.(*os.PathError); ok {
				// file not found
				continue
			}
			return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
		}

		// Store the location of the config file so that we can update it later
		cfg.filename = loc

		// translate configuration parameters if needed
		if t, err := time.ParseDuration(cfg.BlacklistTtl); err != nil {
			return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
		} else if t.Seconds() < 0 {
			return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
		} else {
			cfg.blTtl = int(t.Seconds())
		}

		if len(cfg.Passphrase) != 0 && len(cfg.EncryptionKey) != 0 {
			return nil, fmt.Errorf("failed to read configuration from %s: both passphrase and encryption key are provided", loc)
		}
		// EncryptionKey must be either empty or contain 32 hex digits
		if len(cfg.EncryptionKey) != 0 &&
			len(cfg.EncryptionKey) != (anonymization.EncryptionKeyLen*2) {
			return nil, fmt.Errorf("failed to read configuration from %s: invalid length for encryption key (when non-empty, encryption key must have a length of 32 hex digits)", loc)
		}

		fmt.Println("cfg: ", cfg)

		return cfg, nil
	}

	return nil, errors.New("failed to locate configuration file")
}

// String converts the configuration data structure into a valid JSON string
func (c *Config) String() string {
	var b strings.Builder
	json.NewEncoder(&b).Encode(c)
	return b.String()
}
