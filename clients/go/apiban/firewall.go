package apiban

import (
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"reflect"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vladabroz/go-ipset/ipset"
)

type IPTables struct {
	ipset map[string]*ipset.IPSet
	t     *iptables.IPTables
}

var ipTables = &IPTables{}

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
	fmt.Println("Type of xmlout %s", reflect.TypeOf(xmlout))

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

func (ipt *IPTables) AddTarget(table string, chain string, target string) error {
	// Check if target exists
	ok, err := ipt.t.Exists(table, chain, "-j", target)
	if err != nil {
		return fmt.Errorf(`failed to check if target "%s" is in table:"%s" chain:"%s": %w`, target, table, chain, err)
	}
	// add target to the chain
	if !ok {
		log.Printf(`Adding target "%s" to table:"%s" chain:"%s"`, target, table, chain)
		err = ipt.t.Insert(table, chain, 1, "-j", target)
		if err != nil {
			return fmt.Errorf(`failed to add target "%s" to table:"%s" chain:"%s": %w`, target, table, chain, err)
		}
	} else {
		log.Printf(`Target "%s" is already present in table:"%s" chain:"%s"`, target, table, chain)
	}
	return nil
}

func (ipt *IPTables) ChainExists(table string, chain string) (ok bool, err error) {
	ok = false
	err = nil
	chains, err := ipt.t.ListChains(table)
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

func (ipt *IPTables) InsertIpsetRule(table string, chain string, set string, accept bool) (ok bool, err error) {
	ok = false
	err = nil
	if s, mapOk := ipt.ipset[set]; !mapOk {
		// this ipset was not created yet
		s, err = ipset.New(set, "hash:ip", &ipset.Params{})
		if err != nil {
			err = fmt.Errorf(`failed to create ipset "%s": %w`, set, err)
			return
		}
		// store the newly created ipset
		ipt.ipset[set] = s
	}
	// Add rule to blocking chain to check ipset
	log.Print("Creating a rule to check our ipset")
	if accept {
		// use ACCEPT target
		log.Printf(`exec: "iptables -t %s -I %s 1 -m set --match-set %s src -j ACCEPT"`, table, chain, set)
		err = ipTables.t.Insert(table, chain, 1, "-m", "set", "--match-set", set, "src", "-j", "ACCEPT")
	} else {
		// use DROP target
		log.Printf(`exec: "iptables -t %s -I %s 1 -m set --match-set %s src -j DROP"`, table, chain, set)
		err = ipTables.t.Insert(table, chain, 1, "-m", "set", "--match-set", set, "src", "-j", "DROP")
	}
	if err != nil {
		err = fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return
	}
	ok = true
	return
}

func InitializeIPTables(blChain string) (*ipset.IPSet, error) {
	var err error
	var blset *ipset.IPSet

	ipTables.ipset = make(map[string]*ipset.IPSet)
	ipTables.t, err = iptables.New()
	if err != nil {
		log.Panic(err)
	}

	// check if the chain already exists
	if ok, err := ipTables.ChainExists("filter", blChain); err != nil {
		return nil, fmt.Errorf("failed to check if \"filter\" table %s chain exists: %w", blChain, err)
	} else if !ok {
		// chain does NOT exist; create a new chain
		log.Print(`create chain %s in table "filter"`, blChain)
		err = ipTables.t.ClearChain("filter", blChain)
		if err != nil {
			return nil, fmt.Errorf("failed to create \"filter\" table %s chain: %w", blChain, err)
		}
	}

	// add the chain parameter as target for the INPUT chain
	if err = ipTables.AddTarget("filter", "INPUT", blChain); err != nil {
		return nil, err
	}
	// add the chain parameter as target for the FORWARD chain
	if err = ipTables.AddTarget("filter", "FORWARD", blChain); err != nil {
		return nil, err
	}

	// Check if rule in ipset based rule in blocking chain
	ok, err := ipTables.t.Exists("filter", blChain, "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP")
	if err != nil {
		//return "error", fmt.Errorf("failed check rule for ipset: %w", err)
		return nil, fmt.Errorf("failed check rule for ipset: %w", err)
	}
	if !ok {
		ipTables.InsertIpsetRule("filter", blChain, "blacklist", false)
	} else {
		log.Printf(`"ipset" based "DROP" rule is already present in table:"filter" chain "%s"`, blChain)
	}

	// workaround - flush our CHAIN first
	err = ipTables.t.ClearChain("filter", blChain)
	if err != nil {
		//return "error", fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to clean our chain: %w", err)
	}

	//return "chain created", nil
	return blset, nil
}
