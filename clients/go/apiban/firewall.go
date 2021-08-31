package apiban

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vladabroz/go-ipset/ipset"

	"github.com/google/nftables"
	//"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

type IPTables struct {
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

	// is this a dry run? if yes do not change anything in iptables/ipset, just dump the system commands that would be used
	dryRun bool
}

var ipTables = &IPTables{}

const (
	MaxSetSize = 1024
)

// errors
var (
	ErrNoIptables       = errors.New("iptables was not found")
	ErrNoBlacklistFound = errors.New("ipset blacklist was not found")
	ErrNoWhitelistFound = errors.New("ipset whitelist was not found")
)

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
		log.Printf(`Chain "%s" is already a target in table:"%s" chain:"%s"`, target, table, chain)
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
	if ipt.dryRun {
		return nil
	}
	return ipTables.t.ClearChain(ipt.table, chain)
}

//Insert is a wrapper for iptables.Insert which can be used for dry run
func (ipt *IPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	log.Printf(`exec: "iptables -t %s -I %s %d %s"`, table, chain, pos, strings.Join(rulespec, " "))
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
		log.Printf(`rule already loaded: "-t %s -C %s -m set --match-set %s src -j %s"`, table, chain, set, target)
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

func (ipt *IPTables) AddToBlacklist(ip string, timeout int) (err error) {
	if set, ok := ipt.Sets[ipt.Bl]; ok {
		return set.Add(ip, timeout)
	}
	return ErrNoBlacklistFound
}

func (ipt *IPTables) AddToWhitelist(ip string, timeout int) (err error) {
	if set, ok := ipt.Sets[ipt.Wl]; ok {
		return set.Add(ip, timeout)
	}
	return ErrNoWhitelistFound
}

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
				`WARNING: "%s" table "%s" chain exists and has the following rules:
"%s"`,
				ipTables.table, chain, strings.Join(rules, "\n"))
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

func IpTables() *IPTables {
	return ipTables
}

// set indeces
type SetIdx int

// indeces for nftables sets
const (
	BlSet SetIdx = iota
	WlSet
)

// indeces for nftables rules
const (
	FwdRuleIdx = iota
	InRuleIdx
	WlRuleIdx
	BlRuleIdx
)

type NFTables struct {
	// is it dry run? (no commits to the kernel)
	DryRun bool
	// filtering table
	Table *nftables.Table

	// chains
	// forwarding chain
	FwdChain *nftables.Chain
	// input chain
	InChain *nftables.Chain
	// chain used as jump target
	TgtChain *nftables.Chain

	// sets
	Sets [2]*nftables.Set

	// expressions used in rules
	JmpTargetExpr []expr.Any
	DropBlExpr    []expr.Any
	AcceptWlExpr  []expr.Any

	// rules
	Rules [4]*nftables.Rule

	// connection to netlink sockets
	Conn *nftables.Conn
}

func newNFTables(table, fwdChain, inChain, target, bl, wl string) *NFTables {

	// initialize the table used for ip address filtering
	nft := &NFTables{
		DryRun: false,
		// system table used for packet filtering (e.g., 'filter')
		Table: &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   table,
		},
		Conn: &nftables.Conn{},
	}

	// initialize chains
	// system chain used for packet forwarding (e.g., 'FORWARD')
	nft.FwdChain = &nftables.Chain{
		Table:    nft.Table,
		Name:     fwdChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	}
	// system chain used for packet input processing (e.g., 'INPUT')
	nft.InChain = &nftables.Chain{
		Table:    nft.Table,
		Name:     inChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	}
	// chain which contains blacklist and whitelist rules; it is used as jump target
	nft.TgtChain = &nftables.Chain{
		Table: nft.Table,
		Name:  target,
		Type:  "",
	}

	// initialize sets
	nft.Sets[BlSet] = &nftables.Set{
		Table:      nft.Table,
		Name:       bl,
		HasTimeout: true,
		KeyType:    nftables.TypeIPAddr,
	}
	nft.Sets[WlSet] = &nftables.Set{
		Table:      nft.Table,
		Name:       wl,
		HasTimeout: true,
		KeyType:    nftables.TypeIPAddr,
	}

	// initialize expressions
	// expression for jumping to the chain target
	nft.JmpTargetExpr = []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: target,
		},
	}
	// expression for dropping the blacklisted addresses
	nft.DropBlExpr = []expr.Any{
		&expr.Payload{
			// payload load 4b @ network header + 12 => reg 1
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        nft.Sets[BlSet].Name,
			SetID:          nft.Sets[BlSet].ID,
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictDrop,
		},
	}
	// expression for accepting the whitelisted addresses
	nft.AcceptWlExpr = []expr.Any{
		&expr.Payload{
			// payload load 4b @ network header + 12 => reg 1
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        nft.Sets[WlSet].Name,
			SetID:          nft.Sets[WlSet].ID,
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	// initialize rules
	// rule used for jumping from forwarding chain to the target chain
	nft.Rules[FwdRuleIdx] = &nftables.Rule{
		Table: nft.Table,
		Chain: nft.FwdChain,
		Exprs: nft.JmpTargetExpr,
	}
	// rule used for jumping from input chain to the target chain
	nft.Rules[InRuleIdx] = &nftables.Rule{
		Table: nft.Table,
		Chain: nft.InChain,
		Exprs: nft.JmpTargetExpr,
	}
	// rule used for accepting packets with saddr matching wl set
	nft.Rules[WlRuleIdx] = &nftables.Rule{
		Table: nft.Table,
		Chain: nft.TgtChain,
		Exprs: nft.AcceptWlExpr,
	}
	// rule used for dropping packets with saddr matching bl set
	nft.Rules[BlRuleIdx] = &nftables.Rule{
		Table: nft.Table,
		Chain: nft.TgtChain,
		Exprs: nft.DropBlExpr,
	}

	return nft
}

func InitializeNFTables(table, fwdChain, inChain, target, bl, wl string) (*NFTables, error) {

	nft := newNFTables(table, fwdChain, inChain, target, bl, wl)

	if err := nft.addSetsAndFlush(); err != nil {
		return nil, fmt.Errorf("nftables intialization error: %w", err)
	}

	// create the user-defined chain for the firewall.
	if err := nft.addTgtChainAndFlush(); err != nil {
		// TODO: rollback
		return nil, fmt.Errorf("nftables intialization error: %w", err)
	}
	log.Printf(`added chain "%s" in table "%s"`, target, nft.Table.Name)

	if err := nft.addRulesAndFlush(); err != nil {
		// TODO: rollback
		return nil, fmt.Errorf("nftables intialization error: %w", err)
	}

	return nft, nil
}

func addIpsToSetElements(ips []string, timeout time.Duration, elements []nftables.SetElement) int {
	var (
		i  int
		ip string
	)
	for i, ip = range ips {
		if i == len(elements) {
			break
		}
		elements[i] = nftables.SetElement{
			Key:     []byte(net.ParseIP(ip).To4()),
			Timeout: timeout,
		}
	}

	return i
}

func areRulesEqual(lhs, rhs *nftables.Rule, cmpHandle bool) bool {
	if cmpHandle && lhs.Handle != rhs.Handle {
		fmt.Printf("handle\n")
		return false
	}
	if len(lhs.Exprs) != len(rhs.Exprs) {
		fmt.Printf("len\n")
		return false
	}
	for i, e := range lhs.Exprs {
		if e == nil {
			fmt.Printf("nil\n")
			return false
		}
		switch t := e.(type) {
		case nil:
			fmt.Printf("expr %d type mismatch\n", i)
			return false
		case *expr.Verdict:
			if r, ok := rhs.Exprs[i].(*expr.Verdict); !ok {
				fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		case *expr.Counter:
			if _, ok := rhs.Exprs[i].(*expr.Counter); !ok {
				fmt.Printf("expr %d type mismatch\n", i)
				return false
			}
		case *expr.Payload:
			if r, ok := rhs.Exprs[i].(*expr.Payload); !ok {
				fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		case *expr.Lookup:
			if r, ok := rhs.Exprs[i].(*expr.Lookup); !ok {
				fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		}
	}
	return true
}

func (nft *NFTables) getFirstRule(chain *nftables.Chain) (rule *nftables.Rule, err error) {
	var (
		rules []*nftables.Rule
	)
	if nft.DryRun {
		return nil, nil
	}
	if rules, err = nft.Conn.GetRule(nft.Table, chain); err != nil {
		return nil, fmt.Errorf("could not get rules from table %s chain %s: %w",
			nft.Table.Name, chain.Name, err)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return rules[0], nil
}

// addSetsAndFlush commits the sets into the kernel
func (nft *NFTables) addSetsAndFlush() error {
	// add sets
	for _, set := range nft.Sets {
		if err := nft.Conn.AddSet(set, nil); err != nil {
			return fmt.Errorf("AddSet (%s) failed: %w", set.Name, err)
		}
	}

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`commiting sets to kernel failed: %w`, err)
		}
	}

	return nil
}

// delSetsAndFlush deletes the rules from the kernel
func (nft *NFTables) delSetsAndFlush() error {
	// add sets
	for _, set := range nft.Sets {
		nft.Conn.DelSet(set)
	}

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`deleting sets from the kernel failed: %w`, err)
		}
	}

	return nil
}

// addChainAndFlush commits the target chain into the kernel
func (nft *NFTables) addTgtChainAndFlush() error {
	// add chain
	nft.Conn.AddChain(nft.TgtChain)

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`"%s" table "%s" chain add - commit to kernel failed: %w`, nft.Table.Name, nft.TgtChain.Name, err)
		}
	}

	return nil
}

// delChainAndFlush deletes the target chain form the kernel
func (nft *NFTables) delTgtChainAndFlush() error {
	// delete chain
	nft.Conn.DelChain(nft.TgtChain)

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`"%s" table "%s" chain delete - commit to kernel failed: %w`, nft.Table.Name, nft.TgtChain.Name, err)
		}
	}

	return nil
}

func (nft *NFTables) delRuleAndFlush(rule *nftables.Rule) error {
	nft.Conn.DelRule(rule)
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			// TODO: rollback
			return fmt.Errorf(`"%s" table rule handle %d del - commit to kernel failed: %w`,
				nft.Table.Name, rule.Handle, err)
		}
	}
	return nil
}

func (nft *NFTables) delDuplicateRules(rule *nftables.Rule) error {
	chains := [2]*nftables.Chain{
		nft.FwdChain,
		nft.InChain,
	}
	for _, chain := range chains[:] {
		var (
			rules []*nftables.Rule
			err   error
		)
		fmt.Printf("chain.Name: %s\n", chain.Name)
		if rules, err = nft.Conn.GetRule(nft.Table, chain); err != nil {
			return fmt.Errorf(`failed to delete duplicate rules: cannot get rules for table %s chain %s: %w`,
				nft.Table.Name, chain.Name, err)
		} else if len(rules) <= 1 {
			return nil
		} else {
			for _, r := range rules[1:] {
				r.Table.Family = nft.Table.Family
				fmt.Printf("rule.Table: %v rule.Chain: %v\n", []byte(r.Table.Name), []byte(r.Chain.Name))
				if areRulesEqual(r, rule, false) {
					if err := nft.delRuleAndFlush(r); err != nil {
						log.Printf(`failed to delete duplicate rules: %s`, err)
					}
				}
			}
		}
	}
	return nil
}

func (nft *NFTables) addBaseChainsRulesAndFlush() error {
	if rule, err := nft.getFirstRule(nft.FwdChain); err != nil {
		return fmt.Errorf(`could not get first rule in "%s" table "%s" chain: %w`,
			nft.Table.Name, nft.FwdChain.Name, err)
	} else if rule != nil {
		nft.Rules[FwdRuleIdx].Position = rule.Handle
	}
	nft.Conn.InsertRule(nft.Rules[FwdRuleIdx])
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			// TODO: rollback
			return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
				nft.Table.Name, err)
		}
	}
	if rule, err := nft.getFirstRule(nft.InChain); err != nil {
		return fmt.Errorf(`could not get first rule in "%s" table "%s" chain: %w`,
			nft.Table.Name, nft.InChain.Name, err)
	} else if rule != nil {
		nft.Rules[InRuleIdx].Position = rule.Handle
	}
	nft.Conn.InsertRule(nft.Rules[InRuleIdx])
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			// TODO: rollback
			return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
				nft.Table.Name, err)
		}
	}
	if err := nft.delDuplicateRules(nft.Rules[FwdRuleIdx]); err != nil {
		log.Printf("%s", err)
	}
	if !nft.DryRun {
		// get the handles of the rules in fwd and input chains
		if rule, err := nft.getFirstRule(nft.FwdChain); err != nil {
			return fmt.Errorf(`could not get first rule in "%s" table "%s" chain: %w`,
				nft.Table.Name, nft.FwdChain.Name, err)
		} else if rule != nil {
			nft.Rules[FwdRuleIdx].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain rule handle: %d`,
			nft.Table.Name, nft.FwdChain.Name, nft.Rules[FwdRuleIdx].Handle)
		if rule, err := nft.getFirstRule(nft.InChain); err != nil {
			return fmt.Errorf(`could not get first rule in "%s" table "%s" chain: %w`,
				nft.Table.Name, nft.InChain.Name, err)
		} else if rule != nil {
			nft.Rules[InRuleIdx].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain rule handle: %d`,
			nft.Table.Name, nft.InChain.Name, nft.Rules[InRuleIdx].Handle)
	}
	return nil
}

func (nft *NFTables) addTgtChainRulesAndFlush() error {
	var (
		err   error
		rules []*nftables.Rule
	)
	if rules, err = nft.Conn.GetRule(nft.Table, nft.TgtChain); err != nil {
		return fmt.Errorf("could not get rules from table %s chain %s: %w",
			nft.Table.Name, nft.TgtChain.Name, err)
	}
	if len(rules) != 0 {
		// there are already rules in the chain
		blFound, wlFound := false, false
		for _, rule := range rules {
			wlFound = wlFound || areRulesEqual(rule, nft.Rules[WlRuleIdx], false)
			blFound = blFound || areRulesEqual(rule, nft.Rules[BlRuleIdx], false)
		}
		if !wlFound {
			rule := nft.Rules[WlRuleIdx]
			rule.Position = rules[0].Handle
			fmt.Printf("inserting rule with handle %d\n", rule.Position)
			nft.Conn.InsertRule(rule)
			if !nft.DryRun {
				if err := nft.Conn.Flush(); err != nil {
					// TODO: rollback
					return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
						nft.Table.Name, err)
				}
			}
		}
		if !blFound {
			rule := nft.Rules[BlRuleIdx]
			rule.Position = rules[0].Handle
			fmt.Printf("inserting rule with handle %d\n", rule.Position)
			nft.Conn.InsertRule(rule)
			if !nft.DryRun {
				if err := nft.Conn.Flush(); err != nil {
					// TODO: rollback
					return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
						nft.Table.Name, err)
				}
			}
		}
	} else {
		for _, rule := range nft.Rules[WlRuleIdx : BlRuleIdx+1] {
			nft.Conn.AddRule(rule)
		}
		if !nft.DryRun {
			if err := nft.Conn.Flush(); err != nil {
				// TODO: rollback
				return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
					nft.Table.Name, err)
			}
		}
	}
	if !nft.DryRun {
		// get the handles of the rules in the target chain
		if rules, err = nft.Conn.GetRule(nft.Table, nft.TgtChain); err != nil {
			return fmt.Errorf("could not get rules from table %s chain %s: %w",
				nft.Table.Name, nft.TgtChain.Name, err)
		}
		for i, rule := range rules {
			if i > 1 {
				break
			}
			nft.Rules[WlRuleIdx+i].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain whitelist rule handle: %d`,
			nft.Table.Name, nft.TgtChain.Name, nft.Rules[WlRuleIdx].Handle)
		log.Printf(`"%s" table "%s" chain blacklist rule handle: %d`,
			nft.Table.Name, nft.TgtChain.Name, nft.Rules[BlRuleIdx].Handle)
	}
	return nil
}

// addRulesAndFlush commits the rules into the kernel
func (nft *NFTables) addRulesAndFlush() error {
	if err := nft.addBaseChainsRulesAndFlush(); err != nil {
		return err
	}
	if err := nft.addTgtChainRulesAndFlush(); err != nil {
		return err
	}
	return nil
}

// delRulesAndFlush deletes the rules from the kernel
func (nft *NFTables) delRulesAndFlush() error {
	var (
		err error
	)
	for _, rule := range nft.Rules {
		if err = nft.Conn.DelRule(rule); err != nil {
			return fmt.Errorf(`"%s" table rules delete failed: %w`, nft.Table.Name, err)
		}
	}
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`"%s" table rules delete - commit to kernel failed: %w`,
				nft.Table.Name, err)
		}
	}
	return nil
}

func (nft *NFTables) getSet(idx SetIdx) *nftables.Set {
	switch idx {
	case BlSet:
		return nft.Sets[BlSet]
	case WlSet:
		return nft.Sets[WlSet]
	default:
		return nil
	}
}

func (nft *NFTables) setAddElements(idx SetIdx, elements []nftables.SetElement) (err error) {
	var i int
	for i = 0; i < len(elements)/MaxSetSize; i++ {
		if err = nft.setAddElementsAndFlush(idx, elements[i*MaxSetSize:(i+1)*MaxSetSize]); err != nil {
			return fmt.Errorf(`adding elements to set failed: %w`, err)
		}
	}
	if len(elements) > i*MaxSetSize {
		if err = nft.setAddElementsAndFlush(idx, elements[i*MaxSetSize:len(elements)]); err != nil {
			return fmt.Errorf(`adding elements to set failed: %w`, err)
		}
	}
	return nil
}

func (nft *NFTables) setAddElementsAndFlush(idx SetIdx, elements []nftables.SetElement) (err error) {
	set := nft.getSet(idx)
	if set == nil {
		return fmt.Errorf(`bad set index %d`, idx)
	}
	nft.Conn.SetAddElements(set, elements)
	if !nft.DryRun {
		if err = nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`commiting set elements to kernel failed: %w`, err)
		}
	}
	return nil
}

func (nft *NFTables) addIpsToSet(idx SetIdx, ips []string, timeout time.Duration) error {
	var elements [2 * MaxSetSize]nftables.SetElement
	set := nft.getSet(idx)
	if set == nil {
		return fmt.Errorf(`bad set index %d`, idx)
	}
	l, i := 0, 0
	for i = 0; i < len(ips); i += l {
		l = addIpsToSetElements(ips[i:], timeout, elements[:])
		if l == 0 {
			break
		}
		if err := nft.setAddElements(idx, elements[0:l]); err != nil {
			return fmt.Errorf(`%w`, err)
		}
		if l >= len(ips[i:]) {
			break
		}
	}
	return nil
}

func (nft *NFTables) AddToWhitelist(ips []string, timeout time.Duration) error {
	return nft.addIpsToSet(WlSet, ips, timeout)
}

func (nft *NFTables) AddToBlacklist(ips []string, timeout time.Duration) error {
	return nft.addIpsToSet(BlSet, ips, timeout)
}
