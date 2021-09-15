package apiban

import (
	"errors"
	"log"
	"time"
)

type Firewall interface {
	// dumps the commands used for firewall setup
	GetCommands() string

	// whitelisting operation
	AddToWhitelist([]string, time.Duration) (int, error)

	// blacklisting operation
	AddToBlacklist([]string, time.Duration) (int, error)
}

const (
	MaxSetSize = 1024
)

// errors
var (
	ErrFirewall         = errors.New("firewall missing")
	ErrNoIptables       = errors.New("iptables was not found")
	ErrNoBlacklistFound = errors.New("ipset blacklist was not found")
	ErrNoWhitelistFound = errors.New("ipset whitelist was not found")
)

func GetFirewall() Firewall {
	if GetConfig().UseNftables {
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

func InitializeFirewall(bl, wl string, dryRun bool) (fw Firewall, err error) {
	if GetConfig().UseNftables {
		fw, err = InitializeNFTables(GetConfig().Table, GetConfig().FwdChain, GetConfig().InChain, GetConfig().TgtChain, bl, wl, dryRun)
	} else {
		fw, err = InitializeIPTables(GetConfig().TgtChain, bl, wl, dryRun)
	}
	if dryRun {
		log.Printf("firewall commands:\n%s", fw.GetCommands())
	}
	return fw, err
}
