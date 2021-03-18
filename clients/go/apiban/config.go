package apiban

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
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
	Apikey  string `json:"APIKEY"`
	Lkid    string `json:"LKID"`
	Version string `json:"VERSION"`
	Url     string `json:"URL"`
	Chain   string `json:"CHAIN"`
	Tick    string `json:"INTERVAL"`
	Full    string `json:"FULL"`
	// state filename
	StateFilename string `json:"STATE_FILENAME"`
	// ttl for the firewall DROP rules
	BlacklistTtl string `json:"BLACKLIST_TTL"`
	// passphrase used to generate encryption key for anonymization
	Passphrase string `json:"PASSPHRASE"`
	// encryption key used for anonymization
	EncryptionKey string `json:"ENCRYPTION_KEY"`

	// black list ttl translated into seconds
	blTtl    int
	filename string
}

// global configuration
var config = &Config{}

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
		f, err := os.Open(loc)
		if err != nil {
			continue
		}
		defer f.Close()

		cfg := config
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
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
