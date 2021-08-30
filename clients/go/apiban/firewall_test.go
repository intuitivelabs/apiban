package apiban

import (
	"errors"
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
		err error
		ips []string
		nft *NFTables
	)
	if ips, err = generateAddrRange("10", 10); err != nil {
		t.Fatalf("could not generate address range %s", err)
	}
	u, err := time.ParseDuration("1m")
	if err != nil {
		t.Fatalf("could parse duration %s", err)
	}
	t.Run("initialize nftables", func(t *testing.T) {
		nft, err = InitializeNFTables("filter", "FORWARD", "INPUT", "MONITORING", "blacklist", "whitelist")
		if err != nil {
			t.Fatalf("%s", err)
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
}
