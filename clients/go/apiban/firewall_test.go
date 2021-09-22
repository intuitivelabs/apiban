package apiban

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func generateAddrRange(prefix string, size int) ([]string, error) {
	var (
		idx int
	)
	if n, err := strconv.Atoi(prefix); err != nil {
		return nil, errors.New("invalid address prefix")
	} else if n <= 0 || n > 255 {
		return nil, errors.New("invalid address prefix")
	}
	if size > 1<<24 {
		return nil, errors.New("size is too large")
	}
	addrRange := make([]string, size)
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			for k := 1; k < 255; k++ {
				if idx >= size {
					break
				}
				addrRange[idx] = prefix +
					"." + strconv.Itoa(i) +
					"." + strconv.Itoa(j) +
					"." + strconv.Itoa(k)
				idx++
			}
		}
	}
	return addrRange, nil
}

func TestNftables(t *testing.T) {
	var (
		err     error
		ips     []string
		nft     *NFTables
		cleanup bool = true
	)
	config = Config{
		Passphrase:  "reallyworks?",
		Table:       "intuitive",
		FwdChain:    "FORWARD",
		InChain:     "INPUT",
		TgtChain:    "MONITORING",
		DryRun:      false,
		UseNftables: true,
	}
	if ips, err = generateAddrRange("10", 10); err != nil {
		t.Fatalf("could not generate address range %s", err)
	}
	u, err := time.ParseDuration("1m")
	if err != nil {
		t.Fatalf("could parse duration %s", err)
	}
	t.Run("initialize nftables", func(t *testing.T) {
		fw, fwErr := InitializeFirewall("honeynet", "blacklist", "whitelist", config.DryRun, true)
		if fwErr != nil {
			t.Fatalf("%s", fwErr)
		}
		nft = fw.(*NFTables)
		if nft == nil {
			t.Fatalf("nftables was not correctly initialized")
		}
		tables, err := nft.Conn.ListTables()
		if err != nil {
			t.Fatalf("%s", err)
		}
		found := false
		for _, table := range tables {
			if table.Name == nft.Table.Name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf(`table "%s" not found`, nft.Table.Name)
		}
		chains, err := nft.Conn.ListChains()
		if err != nil {
			t.Fatalf("%s", err)
		}
		// check that the target chain was created
		var (
			cnt = 0
		)
		for _, chain := range chains {
			if chain.Table.Name != nft.Table.Name {
				continue
			}
			if chain.Name == config.TgtChain {
				if !areChainsEql(chain, nft.RegChain) {
					t.Fatalf(`chain "%s" was not properly created`, config.TgtChain)
				}
				cnt++
			}
			if chain.Name == config.FwdChain {
				if !areChainsEql(chain, nft.FwdChain) {
					t.Fatalf(`configured chain "%s" different from system chain "%s"`, chainToString(nft.FwdChain), chainToString(chain))
				}
				cnt++
			}
			if chain.Name == config.InChain {
				if !areChainsEql(chain, nft.InChain) {
					t.Fatalf(`configured chain "%s" different from system chain "%s"`, chainToString(nft.InChain), chainToString(chain))
				}
				cnt++
			}
		}
		if cnt < 3 {
			t.Fatalf(`only %d out of 3 chains were properly created`, cnt)
		}
		if rule, err := nft.getFirstRule(nft.FwdChain); err != nil {
			t.Fatalf(`get rules failure %s`, err)
		} else {
			if !areRulesEql(rule, nft.Rules[FwdRuleIdx], true) {
				t.Fatalf(`rules mismatch in chain %s`, nft.FwdChain.Name)
			}
		}
		if rule, err := nft.getFirstRule(nft.InChain); err != nil {
			t.Fatalf(`get rules failure %s`, err)
		} else {
			if !areRulesEql(rule, nft.Rules[InRuleIdx], true) {
				t.Fatalf(`rules mismatch in chain %s`, nft.InChain.Name)
			}
		}
		if rules, err := nft.Conn.GetRule(nft.Table, nft.RegChain); err != nil {
			t.Fatalf(`cannot get rules for table %s chain %s: %s`, nft.Table.Name, nft.RegChain.Name, err)
		} else {
			if len(rules) < 2 {
				t.Fatalf(`invalid number of rules for table %s chain %s`, nft.Table.Name, nft.RegChain.Name)
			}
			for i, rule := range rules {
				if i > 1 {
					break
				}
				if !areRulesEql(rule, nft.Rules[i+WlRuleIdx], true) {
					t.Fatalf(`mismatching rules for table %s chain %s`, nft.Table.Name, nft.RegChain.Name)
				}
			}
		}
	})
	t.Run("blacklist", func(t *testing.T) {
		if nft == nil {
			t.Skipf("nftables was not properly initialized")
		}
		if _, err = nft.addStrIpsToSet(BlSet, ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
	t.Run("whitelist", func(t *testing.T) {
		if nft == nil {
			t.Skipf("nftables was not properly initialized")
		}
		if _, err = nft.addStrIpsToSet(WlSet, ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
	if cleanup && nft != nil {
		if err = nft.delRulesAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
		if err = nft.delRegChainAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
		if err = nft.delSetsAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}

func TestIptables(t *testing.T) {
	var (
		err error
		ips []string
		nft *NFTables
		ipt *IPTables
		//cleanup bool = true
	)
	config = Config{
		Passphrase:  "reallyworks?",
		TgtChain:    "MONITORING",
		DryRun:      false,
		UseNftables: false,
	}
	if ips, err = generateAddrRange("10", 10); err != nil {
		t.Fatalf("could not generate address range %s", err)
	}
	u, err := time.ParseDuration("1m")
	if err != nil {
		t.Fatalf("could parse duration %s", err)
	}
	t.Run("initialize iptables", func(t *testing.T) {
		fw, err := InitializeFirewall("honeynet", "blacklist", "whitelist", config.DryRun, false)
		if err != nil {
			t.Fatalf("%s", err)
		}
		ipt = fw.(*IPTables)
		if ipt == nil {
			t.Fatalf("iptables was not correctly initialized")
		}
		// Check if the rules in the base chains exists
		ok, err := ipTables.t.Exists("filter", "INPUT", "-j", config.TgtChain)
		if err != nil || !ok {
			t.Fatalf("iptables does not contain target chain %s rule in chain INPUT", config.TgtChain)
		}
		ok, err = ipTables.t.Exists("filter", "FORWARD", "-j", config.TgtChain)
		if err != nil || !ok {
			t.Fatalf("iptables does not contain target chain %s rule in chain FORWARD", config.TgtChain)
		}
		// Check if the rules in the target chain exists
		ok, err = ipTables.t.Exists("filter", config.TgtChain, "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP")
		if err != nil || !ok {
			t.Fatalf("iptables does not contain blacklist rule in chain %s", config.TgtChain)
		}
		ok, err = ipTables.t.Exists("filter", config.TgtChain, "-m", "set", "--match-set", "whitelist", "src", "-j", "ACCEPT")
		if err != nil || !ok {
			t.Fatalf("iptables does not contain whitelist rule in chain %s", config.TgtChain)
		}
	})
	t.Run("blacklist", func(t *testing.T) {
		if ipt == nil {
			t.Skipf("iptables was not properly initialized")
		}
		if _, err := ipt.AddToBlacklist(ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
	t.Run("whitelist", func(t *testing.T) {
		if nft == nil {
			t.Skipf("iptables was not properly initialized")
		}
		if _, err := ipt.AddToWhitelist(ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
}
