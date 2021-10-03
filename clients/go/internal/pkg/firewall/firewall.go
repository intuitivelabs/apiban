package firewall

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/config"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/parser"
)

type Firewall interface {
	// dumps the commands used for firewall setup
	GetCommands() string

	// whitelisting operation
	AddToWhitelist([]string, time.Duration) (int, error)

	// blacklisting operation
	AddToBlacklist([]string, time.Duration) (int, error)

	// honeynet based blacklisting operation
	AddToPublicBlacklistBin([]net.IP, time.Duration) (int, error)
	AddToPublicBlacklist(parser.Elements, time.Duration) (int, error)
}

const (
	MaxSetSize = 1024
)

// errors
var (
	ErrFirewall               = errors.New("firewall missing")
	ErrNoIptables             = errors.New("iptables was not found")
	ErrNoBlacklistFound       = errors.New("ipset blacklist was not found")
	ErrNoPublicBlacklistFound = errors.New("ipset public blacklist (honeynet) was not found")
	ErrNoWhitelistFound       = errors.New("ipset whitelist was not found")
)

func GetFirewall() Firewall {
	if config.GetConfig().UseNftables {
		return nfTables
	}
	return ipTables
}

func AddToBlacklist(ips []string, ttl time.Duration) (int, error) {
	if fw := GetFirewall(); fw != nil {
		return fw.AddToBlacklist(ips, ttl)
	}
	return 0, ErrFirewall
}

func AddToWhitelist(ips []string, ttl time.Duration) (int, error) {
	if fw := GetFirewall(); fw != nil {
		return fw.AddToWhitelist(ips, ttl)
	}
	return 0, ErrFirewall
}

func AddToPublicBlacklistBin(ips []net.IP, ttl time.Duration) (int, error) {
	if fw := GetFirewall(); fw != nil {
		return fw.AddToPublicBlacklistBin(ips, ttl)
	}
	return 0, ErrFirewall
}

func AddToPublicBlacklist(elems parser.Elements, ttl time.Duration) (int, error) {
	if fw := GetFirewall(); fw != nil {
		return fw.AddToPublicBlacklist(elems, ttl)
	}
	return 0, ErrFirewall
}

func InitializeFirewall(publicBl, bl, wl string, dryRun, addBaseObj bool) (fw Firewall, err error) {
	if config.GetConfig().UseNftables {
		if fw, err = InitializeNFTables(config.GetConfig().Table, config.GetConfig().FwdChain, config.GetConfig().InChain, config.GetConfig().TgtChain, publicBl, bl, wl, dryRun, addBaseObj); err != nil {
			return nil, err
		}
	} else {
		if fw, err = InitializeIPTables(config.GetConfig().TgtChain, publicBl, bl, wl, dryRun); err != nil {
			return nil, err
		}
	}
	if dryRun {
		log.Printf("firewall commands:\n%s", fw.GetCommands())
	}
	return fw, nil
}
