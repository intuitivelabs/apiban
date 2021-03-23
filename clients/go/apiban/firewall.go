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
	t *iptables.IPTables
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

// Function to see if string within string
func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func (ipt *IPTables) AddTarget(table string, chain string, target string) error {
	// Check if target exists
	ok, err := ipt.t.Exists(table, chain, "-j", target)
	if err != nil {
		return fmt.Errorf("failed to check rule in %s chain of %s table: %w", err)
	}
	// add target to the chain
	if !ok {
		log.Print("Adding target %s to %s chain of %s table", target, chain, table)
		err = ipt.t.Insert(table, chain, 1, "-j", target)
		if err != nil {
			return fmt.Errorf("failed to add blocking target to INPUT chain: %w", err)
		}
	} else {
		log.Print("Target %s is already present in %s chain of %s table", target, chain, table)
	}
	return nil
}

func (ipt *IPTables) ChainExists(table string, chain string) (bool, error) {
	return false, nil
}

func InitializeIPTables(blChain string) (*ipset.IPSet, error) {
	var err error

	ipTables.t, err = iptables.New()
	if err != nil {
		log.Panic(err)
	}

	// check if the chain already exists
	if ok, err := ipTables.ChainExists("filter", blChain); err != nil {
		return nil, fmt.Errorf("failed to check if \"filter\" table %s chain exists: %w", blChain, err)
	} else if !ok {
		// chain does NOT exist; create a new chain
		log.Print("\"filter\" table does not contain %s chain. Creating now...", blChain)
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

	/* Does not work...
	// Check if rule in blocking chain to ipset exists
	ipsetRuleExists, err := ipt.Exists("filter", blChain, "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP")
	if err != nil {
		//return "error", fmt.Errorf("failed check rule for ipset: %w", err)
		return nil, fmt.Errorf("failed check rule for ipset: %w", err)
	}
	*/
	blset, err := ipset.New("blacklist", "hash:ip", &ipset.Params{})
	if err != nil {
		// failed to create ipset - ipset utility missing?
		//fmt.Println("Error:", err)
		return nil, fmt.Errorf("failed to create ipset: %w", err)
	}

	// workaround - flush our CHAIN first
	err = ipTables.t.ClearChain("filter", blChain)
	if err != nil {
		//return "error", fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to clean our chain: %w", err)
	}

	// Add rule to blocking chain to check ipset
	log.Print("Creating a rule to check our ipset")
	err = ipTables.t.Insert("filter", blChain, 1, "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP")
	if err != nil {
		//return "error", fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
	}

	//return "chain created", nil
	return blset, nil
}
