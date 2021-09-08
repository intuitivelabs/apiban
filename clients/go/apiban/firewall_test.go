package apiban

import (
	"errors"
	"fmt"
	"github.com/google/nftables"
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
	if ips, err = generateAddrRange("10", 10); err != nil {
		t.Fatalf("could not generate address range %s", err)
	}
	u, err := time.ParseDuration("1m")
	if err != nil {
		t.Fatalf("could parse duration %s", err)
	}
	t.Run("initialize nftables", func(t *testing.T) {
		nft, err = InitializeNFTables("filter", "FORWARD", "INPUT", "MONITORING", "blacklist", "whitelist", false)
		if err != nil {
			t.Fatalf("%s", err)
		}
		if nft == nil {
			t.Fatalf("nftables was not correctly initialized")
		}
		if chains, err := nft.Conn.ListChains(); err != nil {
			t.Fatalf("%s", err)
		} else {
			// check that the target chain was created
			var chain *nftables.Chain
			for _, chain = range chains {
				if chain.Name == "MONITORING" {
					break
				}
			}
			if chain == nil || chain.Name != "MONITORING" || chain.Table.Name != nft.Table.Name {
				t.Fatalf(`chain "MONITORING" was not properly created`)
			}
			if rule, err := nft.getFirstRule(nft.FwdChain); err != nil {
				t.Fatalf(`get rules failure %s`, err)
			} else {
				if !areRulesEqual(rule, nft.Rules[FwdRuleIdx], true) {
					t.Fatalf(`rules mismatch in chain %s`, nft.FwdChain.Name)
				}
			}
			if rule, err := nft.getFirstRule(nft.InChain); err != nil {
				t.Fatalf(`get rules failure %s`, err)
			} else {
				if !areRulesEqual(rule, nft.Rules[InRuleIdx], true) {
					t.Fatalf(`rules mismatch in chain %s`, nft.InChain.Name)
				}
			}
			if rules, err := nft.Conn.GetRule(nft.Table, chain); err != nil {
				t.Fatalf(`cannot get rules for table %s chain %s: %s`, nft.Table.Name, chain.Name, err)
			} else {
				if len(rules) < 2 {
					t.Fatalf(`invalid number of rules for table %s chain %s`, nft.Table.Name, chain.Name)
				}
				for i, rule := range rules {
					if i > 1 {
						break
					}
					if !areRulesEqual(rule, nft.Rules[i+WlRuleIdx], true) {
						t.Fatalf(`mismatching rules for table %s chain %s`, nft.Table.Name, chain.Name)
					}
				}
			}
		}
	})
	t.Run("blacklist", func(t *testing.T) {
		if nft == nil {
			t.Skipf("nftables was not properly initialized")
		}
		if err := nft.addIpsToSet(BlSet, ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
	t.Run("whitelist", func(t *testing.T) {
		if nft == nil {
			t.Skipf("nftables was not properly initialized")
		}
		if err := nft.addIpsToSet(WlSet, ips[:], u); err != nil {
			t.Fatalf("could not add ip to set %s", err)
		}
	})
	if cleanup && nft != nil {
		if err = nft.delRulesAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
		if err = nft.delTgtChainAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
		if err = nft.delSetsAndFlush(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}
