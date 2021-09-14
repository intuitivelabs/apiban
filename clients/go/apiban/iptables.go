package apiban

import (
	"encoding/xml"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vladabroz/go-ipset/ipset"
	"log"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

type IPTables struct {
	// stores all the Commands used for setting up the firewall rules
	Commands string
	// table used for firewall rules
	table string
	// chain used as target by firewall rules
	chain string
	// name of the ipset set of addresses for blacklisting
	Bl string
	// name of the ipset set of addresses for whitelisting
	Wl string

	// api which manipulates rules used in iptables
	t *iptables.IPTables

	// sets used in the iptables rules
	Sets map[string]*ipset.IPSet

	// is this a dry run? if yes do not change anything in iptables/ipset, just dump the system Commands that would be used
	dryRun bool
}

var ipTables = &IPTables{}

func InitializeIPTables(chain, bl, wl string, dryRun bool) (*IPTables, error) {
	var err error

	*ipTables = IPTables{
		dryRun: dryRun,
		table:  "filter",
		chain:  chain,
		Bl:     bl,
		Wl:     wl,
		Sets:   make(map[string]*ipset.IPSet)}
	ipTables.t, err = iptables.New()
	if err != nil {
		log.Panic(err)
	}

	// create the user-defined chain for the firewall.
	// check if the chain already exists
	if ok, err := ipTables.ChainExists(chain); err != nil {
		return nil, fmt.Errorf(`"%s" table "%s" chain check error: %w`, ipTables.table, chain, err)
	} else if !ok {
		// chain does NOT exist; create a new chain
		log.Printf(`create chain "%s" in table "%s"`, chain, ipTables.table)
		err = ipTables.ClearChain(chain)
		if err != nil {
			return nil, fmt.Errorf(`"%s" table "%s" chain create error: %w`, ipTables.table, chain, err)
		}
	} else {
		// chain exists; show a warning with all the rules in the chain
		if rules, err := ipTables.t.List(ipTables.table, chain); err != nil {
			return nil, fmt.Errorf(`"%s" table "%s" chain list error: %w`, ipTables.table, chain, err)
		} else {
			log.Printf(
				`WARNING: chain "%s" already exists in table "%s" chain and has the following rules:
%s`,
				chain, ipTables.table, strings.Join(rules, "\n"))
		}
	}

	// add the chain parameter as target for the INPUT chain
	if err = ipTables.AddTarget(ipTables.table, "INPUT", chain); err != nil {
		return nil, err
	}
	// add the chain parameter as target for the FORWARD chain
	if err = ipTables.AddTarget(ipTables.table, "FORWARD", chain); err != nil {
		return nil, err
	}

	if err := ipTables.InsertRuleBlacklist(); err != nil {
		return nil, fmt.Errorf(`blacklist rule insert error: %w`, err)
	}

	if err := ipTables.InsertRuleWhitelist(); err != nil {
		return nil, fmt.Errorf(`whitelist rule insert error: %w`, err)
	}

	return ipTables, nil
}

func checkIPSet(ipsetname string) (bool, error) {
	type IPSet struct {
		XMLName    xml.Name `xml:"ipset"`
		Name       string   `xml:"name,attr"`
		Type       string   `xml:"type"`
		References string   `xml:"references"`
	}
	type IPSets struct {
		XMLName xml.Name `xml:"ipsets"`
		IPSets  []IPSet  `xml:"ipset"`
	}

	var ipsets IPSets
	//cmd := exec.Command("ipset", "list", "-t", "-o", "xml")
	//ipsets := IPSetOutput{}
	cmd := exec.Command("ipset", "list", "-t", "-o", "xml")
	xmlout, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	fmt.Printf("combined out:\n%s\n", string(xmlout))
	// read our opened xmlFile as a byte array.
	//byteValue, _ := ioutil.ReadAll(xmlFile)
	fmt.Println("Type of xmlout", reflect.TypeOf(xmlout))

	//testxml := xml.Unmarshal(xmlout, &ipsets)
	if err := xml.Unmarshal(xmlout, &ipsets); err != nil {
		panic(err)
	}
	fmt.Println(ipsets)
	//fmt.Printf("ipsetnames :\n%s\n", string(ipsets.XMLName))
	fmt.Printf("ipsetnames :\n%s\n", ipsets.IPSets[1].Name)
	//testxml := xml.Unmarshal(byteValue, &ipsets)
	for i := 0; i < len(ipsets.IPSets); i++ {
		fmt.Println("IPSet Type: " + ipsets.IPSets[i].Type)
		fmt.Println("IPSet Name: " + ipsets.IPSets[i].Name)
		if ipsets.IPSets[i].Name == ipsetname {
			fmt.Println("IPSET ALREADY EXISTING")
			return true, nil
		}
	}

	//out, err := cmd.CombinedOutput()
	//fmt.Printf("XML :\n%s\n", ipset.Name)
	//fmt.Printf("testXML :\n%s\n", testxml)
	//fmt.Printf("ipsetnames :\n%s\n", string(ipsets.Name))
	return false, nil
}

func IpTables() *IPTables {
	return ipTables
}

// AddTarget adds target (which is supposed to be a valid chain) as a jump target for chain
func (ipt *IPTables) AddTarget(table, chain, target string) error {
	// Check if target exists
	ok, err := ipt.t.Exists(table, chain, "-j", target)
	if err != nil {
		if !ipt.dryRun {
			return fmt.Errorf(`table:"%s" chain:"%s" target:"%s" check error: %w`, table, chain, target, err)
		}
	}
	// add target to the chain
	if !ok {
		log.Printf(`Adding chain "%s" as target to table:"%s" chain:"%s"`, target, table, chain)
		err = ipt.Insert(table, chain, 1, "-j", target)
		if err != nil {
			return fmt.Errorf(`failed to add chain "%s" as target to table:"%s" chain:"%s": %w`, target, table, chain, err)
		}
	} else {
		log.Printf(`WARNING: chain "%s" already exists as a target in table:"%s" chain:"%s"`, target, table, chain)
	}
	return nil
}

func (ipt *IPTables) ChainExists(chain string) (ok bool, err error) {
	ok = false
	err = nil
	chains, err := ipt.t.ListChains(ipt.table)
	if err != nil {
		return
	}
	for _, val := range chains {
		if val == chain {
			ok = true
		}
	}
	return
}

//ClearChain is a wrapper for iptables.ClearChain which can be used for dry run
func (ipt *IPTables) ClearChain(chain string) error {
	log.Printf(`exec: "iptables -t %s -N %s || iptables -t %s -F %s"`, ipt.table, chain, ipt.table, chain)
	ipt.Commands = fmt.Sprintf("%siptables -t %s -N %s || iptables -t %s -F %s\n", ipt.Commands, ipt.table, chain, ipt.table, chain)
	if ipt.dryRun {
		return nil
	}
	return ipTables.t.ClearChain(ipt.table, chain)
}

//Insert is a wrapper for iptables.Insert which can be used for dry run
func (ipt *IPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	log.Printf(`exec: "iptables -t %s -I %s %d %s"`, table, chain, pos, strings.Join(rulespec, " "))
	ipt.Commands = fmt.Sprintf("%siptables -t %s -I %s %d %s\n", ipt.Commands, table, chain, pos, strings.Join(rulespec, " "))
	if ipt.dryRun {
		return nil
	}
	return ipt.t.Insert(table, chain, pos, rulespec...)
}

func (ipt *IPTables) InsertIpsetRule(table, chain, set string, accept bool) (err error) {
	err = nil
	var target string
	if accept {
		// use ACCEPT target
		target = "ACCEPT"
	} else {
		// use DROP target
		target = "DROP"
	}
	// create the ipset and get a handle to it (if the set exists it is NOT flushed)
	if s, mapOk := ipt.Sets[set]; !mapOk {
		// this ipset was not created yet
		log.Printf(`exec: "ipset create %s hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 -exist"`, set)
		ipt.Commands = fmt.Sprintf("%sipset create %s hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 -exist\n", ipt.Commands, set)
		if !ipt.dryRun {
			s, err = ipset.New(set, "hash:ip", &ipset.Params{})
			if err != nil {
				err = fmt.Errorf(`create ipset "%s" error: %w`, set, err)
				return
			}
			// store the newly created ipset
			ipt.Sets[set] = s
		}
	}
	// Check if rule in ipset based rule in blocking chain
	exists, iptablesErr := ipTables.t.Exists(table, chain, "-m", "set", "--match-set", set, "src", "-j", target)
	if iptablesErr != nil {
		// terminate only if not running in dry run mode
		if !ipt.dryRun {
			err = fmt.Errorf("rule check error: %w", iptablesErr)
			return
		}
	}
	if exists {
		log.Printf(`WARNING: rule already exists: "-t %s -C %s -m set --match-set %s src -j %s"`, table, chain, set, target)
		return
	}
	// insert rule into chain using ipset
	err = ipTables.Insert(table, chain, 1, "-m", "set", "--match-set", set, "src", "-j", target)
	if err != nil {
		err = fmt.Errorf("rule insert error: %w", err)
	}
	return
}

func (ipt *IPTables) InsertRuleBlacklist() (err error) {
	return ipt.InsertIpsetRule(ipt.table, ipt.chain, ipt.Bl, false)
}

func (ipt *IPTables) InsertRuleWhitelist() (err error) {
	return ipt.InsertIpsetRule(ipt.table, ipt.chain, ipt.Wl, true)
}

func (ipt *IPTables) GetCommands() string {
	return ipt.Commands
}

func (ipt *IPTables) AddToBlacklist(ips []string, timeout time.Duration) (err error) {
	err = nil
	if set, ok := ipt.Sets[ipt.Bl]; ok {
		t := int(timeout.Seconds())
		for _, ip := range ips {
			if e := set.Add(ip, t); e != nil {
				err = e
			}
		}
		return err
	}
	return ErrNoBlacklistFound
}

func (ipt *IPTables) AddToWhitelist(ips []string, timeout time.Duration) (err error) {
	err = nil
	if set, ok := ipt.Sets[ipt.Wl]; ok {
		t := int(timeout.Seconds())
		for _, ip := range ips {
			if e := set.Add(ip, t); e != nil {
				err = e
			}
		}
		return err
	}
	return ErrNoWhitelistFound
}
