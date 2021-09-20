package apiban

import (
	"errors"
	"fmt"
	"github.com/google/nftables"
	"log"
	"net"
	"time"
	//"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// nftables specific errors
var (
	ErrNftablesAddBaseObj = errors.New("nftables intialization error: adding base objects is not allowed")
	ErrNftablesInit       = "nftables intialization error: %w"
	ErrAddBaseChainRule   = "adding base chain rule failed: %w"
	ErrAddSet             = `adding set "%s" failed: %w`
	ErrAddSetElements     = `adding elements to set failed: %w`
	ErrCommitSetElements  = `committing elements to set "%s": %w`
	ErrAddChain           = `adding chain "%s" to table "%s" failed: %w`
	ErrAddTable           = `adding table "%s" failed: %w`
	ErrDelRule            = `deleting rule with handle %d from table "%s" chain "%s" failed: %w`
	ErrDelRules           = `deleting rules from table "%s" failed: %w`
	ErrDelSets            = `deleting sets from the kernel failed: %w`
)

// define a new type and implement a method which is used for adding IP addresses into a SetElement
type SetElements []nftables.SetElement

//addIps parses IP address from the input string slice and inserts them into the elements
//It returns the number of IP addresses inserted into the elements
func (elements SetElements) addIps(ips []string, timeout time.Duration) int {
	var (
		i  int = 0
		ip string
		b  net.IP
	)
	for _, ip = range ips {
		if len(ip) == 0 {
			continue
		}
		if i == len(elements) {
			break
		}
		if b = []byte(net.ParseIP(ip).To4()); b == nil {
			continue
		}
		elements[i] = nftables.SetElement{
			Key:     b,
			Timeout: timeout,
		}
		i++
	}

	return i
}

// set indices
type SetIdx int

// indices for nftables sets
const (
	BlSet SetIdx = iota
	WlSet
)

// indices for nftables rules
const (
	FwdRuleIdx = iota
	InRuleIdx
	WlRuleIdx
	BlRuleIdx
)

// IP header constants
const (
	IpAddrLen    = 4
	IpOffSrcAddr = 12
	IpOffDstAddr = 16
)

type NFTables struct {
	// stores all the Commands used for setting up the firewall rules
	Commands string

	// is it dry run? (no commits to the kernel)
	DryRun bool

	// is it allowed to add base objects to nftables?
	AddBaseObj bool

	// filtering table
	Table *nftables.Table

	// chains
	// forwarding chain
	FwdChain *nftables.Chain
	// input chain
	InChain *nftables.Chain
	// chain used as jump target
	RegChain *nftables.Chain

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

var nfTables = &NFTables{}

/* The following functions implement conversion to string for nft objects and commands */
func exprToString(exprs []expr.Any) (s string) {
	for _, e := range exprs {
		switch e := e.(type) {
		case *expr.Counter:
			s += "counter "
		case *expr.Verdict:
			s += fmt.Sprintf("%s ", verdictToString(e))
		case *expr.Payload:
			s += fmt.Sprintf("%s ", payloadToString(e))
		case *expr.Lookup:
			s += fmt.Sprintf("%s ", lookupToString(e))
		default:
			s += "UNKNOWN "
		}
	}
	return
}

func verdictToString(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictGoto:
		return fmt.Sprintf("goto %s", v.Chain)
	case expr.VerdictJump:
		return fmt.Sprintf("jump %s", v.Chain)
	case expr.VerdictBreak:
		return "break"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictQueue:
		return "queue"
	default:
		return "UNKNOWN"
	}
}

func payloadToString(p *expr.Payload) string {
	var base string
	switch p.Base {
	case expr.PayloadBaseLLHeader:
		base = "@ll"
	case expr.PayloadBaseNetworkHeader:
		base = "@nh"
		if p.Len == IpAddrLen {
			switch p.Offset {
			case IpOffSrcAddr:
				return "ip saddr"
			case IpOffDstAddr:
				return "ip daddr"
			}
		}
	case expr.PayloadBaseTransportHeader:
		base = "@th"
	}
	return fmt.Sprintf("%s,%d,%d", base, p.Offset, p.Len)
}

func lookupToString(l *expr.Lookup) (s string) {
	return fmt.Sprintf("@%s", l.SetName)
}

func setToString(s nftables.Set) string {
	if s.Table == nil {
		return "INVALID SET"
	}
	flags := ""
	if s.Constant {
		flags += " " + "constant"
	}
	if s.Interval {
		flags += " " + "interval"
	}
	if s.HasTimeout {
		flags += " " + "timeout"
	}
	if len(flags) > 0 {
		flags = " flags" + flags + " ;"
	}
	timeout := ""
	if s.HasTimeout && s.Timeout > 0 {
		timeout = fmt.Sprintf(" timeout %ds ;", int64(s.Timeout.Seconds()))
	}
	return fmt.Sprintf(`%s %s "{ type %s ;%s%s}"`, s.Table.Name, s.Name, s.KeyType.Name, flags, timeout)
}

func addSetToString(s nftables.Set) string {
	return fmt.Sprintf("nft add set %s", setToString(s))
}

func ruleToString(r *nftables.Rule, withStmt bool) string {
	stmt := ""
	if withStmt {
		stmt = fmt.Sprintf(" %s ", exprToString(r.Exprs))
	}
	return fmt.Sprintf("rule %s %s handle %d%s",
		r.Table.Name,
		r.Chain.Name,
		r.Position,
		stmt)
}

func insertRuleToString(r *nftables.Rule) string {
	return fmt.Sprintf("nft insert %s", ruleToString(r, true))
}

func addRuleToString(r *nftables.Rule) string {
	return fmt.Sprintf("nft add %s", ruleToString(r, true))
}

func replaceRuleToString(r *nftables.Rule) string {
	return fmt.Sprintf("nft replace %s", ruleToString(r, true))
}

func deleteRuleToString(r *nftables.Rule) string {
	return fmt.Sprintf("nft delete %s", ruleToString(r, false))
}

func chainToString(c *nftables.Chain) string {
	if c.Table == nil {
		return "INVALID CHAIN"
	}
	//regular chain
	if c.Type == "" {
		return fmt.Sprintf("chain %s %s", c.Table.Name, c.Name)
	}
	hook := "hook "
	switch c.Hooknum {
	case nftables.ChainHookPrerouting:
		hook += "prerouting "
	case nftables.ChainHookInput:
		hook += "input "
	case nftables.ChainHookForward:
		hook += "forward "
	case nftables.ChainHookOutput:
		hook += "output "
	case nftables.ChainHookPostrouting:
		hook += "postrouting "
	default:
		hook += "INVALID "
	}
	policy := ""
	if c.Policy != nil {
		policy = "policy "
		if *c.Policy == nftables.ChainPolicyDrop {
			policy += "drop ; "
		} else {
			policy += "accept ; "
		}
	}
	return fmt.Sprintf("chain %s %s { type %s %spriority %d ; %s}",
		c.Table.Name, c.Name, c.Type, hook, c.Priority, policy)
}

func addChainToString(c *nftables.Chain) string {
	return fmt.Sprintf("nft add %s", chainToString(c))
}

func tableToString(t *nftables.Table) string {
	return fmt.Sprintf("table %s", t.Name)
}

func addTableToString(t *nftables.Table) string {
	return fmt.Sprintf("nft add %s", tableToString(t))
}

//newNFTables initializes an NFTables structure for firewall use.
func newNFTables(table, fwdChain, inChain, target, bl, wl string, dryRun, addBaseObj bool) *NFTables {
	var (
		policyDrop   = nftables.ChainPolicyDrop
		policyAccept = nftables.ChainPolicyAccept
	)
	// initialize the table used for ip address filtering
	*nfTables = NFTables{
		DryRun:     dryRun,
		AddBaseObj: addBaseObj,
		// system table used for packet filtering (e.g., 'filter')
		Table: &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   table,
		},
		Conn: &nftables.Conn{},
	}

	// initialize chains
	// system chain used for packet forwarding (e.g., 'FORWARD')
	nfTables.FwdChain = &nftables.Chain{
		Table:    nfTables.Table,
		Name:     fwdChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	}
	// system chain used for packet input processing (e.g., 'INPUT')
	nfTables.InChain = &nftables.Chain{
		Table:    nfTables.Table,
		Name:     inChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyAccept,
	}
	// chain which contains blacklist and whitelist rules; it is used as jump target
	nfTables.RegChain = &nftables.Chain{
		Table: nfTables.Table,
		Name:  target,
		Type:  "",
	}

	// initialize sets
	nfTables.Sets[BlSet] = &nftables.Set{
		Table:      nfTables.Table,
		Name:       bl,
		HasTimeout: true,
		KeyType:    nftables.TypeIPAddr,
	}
	nfTables.Sets[WlSet] = &nftables.Set{
		Table:      nfTables.Table,
		Name:       wl,
		HasTimeout: true,
		KeyType:    nftables.TypeIPAddr,
	}

	// initialize expressions
	// expression for jumping to the chain target
	nfTables.JmpTargetExpr = []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: target,
		},
	}
	// expression for dropping the blacklisted addresses
	nfTables.DropBlExpr = []expr.Any{
		&expr.Payload{
			// payload load 4b @ network header + 12 => reg 1
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        nfTables.Sets[BlSet].Name,
			SetID:          nfTables.Sets[BlSet].ID,
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictDrop,
		},
	}
	// expression for accepting the whitelisted addresses
	nfTables.AcceptWlExpr = []expr.Any{
		&expr.Payload{
			// payload load 4b @ network header + 12 => reg 1
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        nfTables.Sets[WlSet].Name,
			SetID:          nfTables.Sets[WlSet].ID,
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	// initialize rules
	// rule used for jumping from forwarding chain to the target chain
	nfTables.Rules[FwdRuleIdx] = &nftables.Rule{
		Table: nfTables.Table,
		Chain: nfTables.FwdChain,
		Exprs: nfTables.JmpTargetExpr,
	}
	// rule used for jumping from input chain to the target chain
	nfTables.Rules[InRuleIdx] = &nftables.Rule{
		Table: nfTables.Table,
		Chain: nfTables.InChain,
		Exprs: nfTables.JmpTargetExpr,
	}
	// rule used for accepting packets with saddr matching wl set
	nfTables.Rules[WlRuleIdx] = &nftables.Rule{
		Table: nfTables.Table,
		Chain: nfTables.RegChain,
		Exprs: nfTables.AcceptWlExpr,
	}
	// rule used for dropping packets with saddr matching bl set
	nfTables.Rules[BlRuleIdx] = &nftables.Rule{
		Table: nfTables.Table,
		Chain: nfTables.RegChain,
		Exprs: nfTables.DropBlExpr,
	}

	return nfTables
}

//InitializeNFTables sets up the necesarry rules, chains and sets for firewall usage.
//When `dryRun` is true this function only logs the necessary `nft` commands for setting up the rules, chains and sets.
func InitializeNFTables(table, fwdChain, inChain, target, bl, wl string, dryRun, addBaseObj bool) (*NFTables, error) {
	nft := newNFTables(table, fwdChain, inChain, target, bl, wl, dryRun, addBaseObj)

	if addBaseObj {
		if err := nft.addTableAndFlush(); err != nil {
			return nil, err
		}
		if err := nft.addBaseChainsAndFlush(); err != nil {
			return nil, err
		}
	}
	if err := nft.addSetsAndFlush(); err != nil {
		return nil, fmt.Errorf(ErrNftablesInit, err)
	}

	// create the user-defined chain for the firewall.
	if err := nft.addRegChainAndFlush(); err != nil {
		// TODO: rollback
		return nil, fmt.Errorf(ErrNftablesInit, err)
	}

	if err := nft.addRulesAndFlush(); err != nil {
		// TODO: rollback
		return nil, fmt.Errorf(ErrNftablesInit, err)
	}

	return nft, nil
}

func areRulesEql(lhs, rhs *nftables.Rule, cmpHandle bool) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}
	if cmpHandle && lhs.Handle != rhs.Handle {
		return false
	}
	if len(lhs.Exprs) != len(rhs.Exprs) {
		//TODO debug
		//fmt.Printf("len\n")
		return false
	}
	for i, e := range lhs.Exprs {
		if e == nil {
			return false
		}
		switch t := e.(type) {
		case nil:
			//fmt.Printf("expr %d type mismatch\n", i)
			return false
		case *expr.Verdict:
			if r, ok := rhs.Exprs[i].(*expr.Verdict); !ok {
				//fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					//fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		case *expr.Counter:
			if _, ok := rhs.Exprs[i].(*expr.Counter); !ok {
				//fmt.Printf("expr %d type mismatch\n", i)
				return false
			}
		case *expr.Payload:
			if r, ok := rhs.Exprs[i].(*expr.Payload); !ok {
				//fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					//fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		case *expr.Lookup:
			if r, ok := rhs.Exprs[i].(*expr.Lookup); !ok {
				//fmt.Printf("expr %d type mismatch\n", i)
				return false
			} else {
				if *t != *r {
					//fmt.Printf("expr %d value mismatch\n", i)
					return false
				}
			}
		}
	}
	return true
}

func areChainsEql(lhs, rhs *nftables.Chain) bool {
	if lhs.Type == "" && rhs.Type == "" {
		return lhs.Table.Name == rhs.Table.Name &&
			lhs.Name == rhs.Name
	}
	return lhs.Table.Name == rhs.Table.Name &&
		lhs.Name == rhs.Name &&
		lhs.Hooknum == rhs.Hooknum &&
		lhs.Priority == rhs.Priority &&
		lhs.Type == rhs.Type &&
		lhs.Policy != nil && rhs.Policy != nil &&
		((*lhs.Policy == 0 && *rhs.Policy == 0) ||
			(*lhs.Policy != 0 && *rhs.Policy != 0))
}

func areTablesEql(lhs, rhs *nftables.Table) bool {
	return lhs.Name == rhs.Name &&
		lhs.Flags == rhs.Flags &&
		lhs.Family == rhs.Family
}

func (nft *NFTables) findEqlRules(rule *nftables.Rule) (eqlRules []*nftables.Rule, err error) {
	var (
		chainRules []*nftables.Rule
	)
	if chainRules, err = nft.Conn.GetRule(nft.Table, rule.Chain); err != nil {
		return nil, fmt.Errorf("could not get rules from table %s chain %s: %w",
			nft.Table.Name, rule.Chain.Name, err)
	}
	for _, r := range chainRules {
		if areRulesEql(r, rule, false) {
			eqlRules = append(eqlRules, r)
		}
	}
	return
}

func (nft *NFTables) chainExists(chain *nftables.Chain) (ok bool, err error) {
	ok = false
	err = nil
	if chains, e := nft.Conn.ListChains(); e != nil {
		err = fmt.Errorf(`could not list chains : %w`, e)
	} else {
		for _, c := range chains {
			if areChainsEql(c, chain) {
				ok = true
				break
			}
		}
	}
	return
}

func (nft *NFTables) tableExists(table *nftables.Table) (ok bool, err error) {
	ok = false
	err = nil
	if tables, e := nft.Conn.ListTables(); e != nil {
		err = fmt.Errorf(`could not list tables: %w`, e)
	} else {
		for _, t := range tables {
			if areTablesEql(t, table) {
				ok = true
				break
			}
		}
	}
	return
}

func (nft *NFTables) isFirstRule(rule *nftables.Rule) (bool, error) {
	r, err := nft.getFirstRule(rule.Chain)
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, nil
	}
	return areRulesEql(r, rule, false), nil
}

func (nft *NFTables) getFirstRule(chain *nftables.Chain) (rule *nftables.Rule, err error) {
	var (
		rules []*nftables.Rule
	)
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
			return fmt.Errorf(ErrAddSetElements, err)
		}
		nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, addSetToString(*set))
	}

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrAddSetElements, err)
		}
	}

	return nil
}

// delSetsAndFlush deletes the sets from the kernel
func (nft *NFTables) delSetsAndFlush() error {
	// add sets
	for _, set := range nft.Sets {
		nft.Conn.DelSet(set)
	}

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrDelSets, err)
		}
	}

	return nil
}

func (nft *NFTables) addChainAndFlush(chain *nftables.Chain) error {
	// check if chain is already configured in the kernel
	if ok, err := nft.chainExists(chain); err != nil {
		return fmt.Errorf(ErrAddChain, chain.Name, chain.Table.Name, err)
	} else if ok {
		return nil
	}
	// add chain
	nft.Conn.AddChain(chain)
	nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, addChainToString(chain))

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrAddChain, chain.Name, nft.Table.Name, err)
		}
		log.Printf(`added chain "%s" in table "%s"`, chain.Name, nft.Table.Name)
	}

	return nil
}

func (nft *NFTables) addTableAndFlush() error {
	if ok, err := nft.tableExists(nft.Table); err != nil {
		return fmt.Errorf(ErrAddTable, nft.Table.Name, err)
	} else if ok {
		return nil
	}
	nft.Conn.AddTable(nft.Table)
	nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, addTableToString(nft.Table))
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrAddTable, nft.Table.Name, err)
		}
		log.Printf(`added table "%s"`, nft.Table.Name)
	}

	return nil
}

func (nft *NFTables) addBaseChainsAndFlush() error {
	if !nft.AddBaseObj {
		return ErrNftablesAddBaseObj
	}
	if err := nft.addChainAndFlush(nft.FwdChain); err != nil {
		return err
	}
	if err := nft.addChainAndFlush(nft.InChain); err != nil {
		return err
	}
	return nil
}

// addChainAndFlush commits the target chain into the kernel
func (nft *NFTables) addRegChainAndFlush() error {
	return nft.addChainAndFlush(nft.RegChain)
}

// delChainAndFlush deletes the target chain form the kernel
func (nft *NFTables) delRegChainAndFlush() error {
	// delete chain
	nft.Conn.DelChain(nft.RegChain)

	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(`deleting regular chain "%s" failed: %w`, nft.RegChain.Name, err)
		}
	}

	return nil
}

func (nft *NFTables) delRuleAndFlush(rule *nftables.Rule) error {
	if err := nft.Conn.DelRule(rule); err != nil {
		return fmt.Errorf(ErrDelSets, rule.Handle, nft.Table.Name, rule.Chain.Name, err)
	}
	nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, deleteRuleToString(rule))
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			// TODO: rollback
			return fmt.Errorf(ErrDelSets, rule.Handle, nft.Table.Name, rule.Chain.Name, err)
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
		if rules, err = nft.Conn.GetRule(nft.Table, chain); err != nil {
			return fmt.Errorf(`failed to delete duplicate rules: cannot get rules for table %s chain %s: %w`,
				nft.Table.Name, chain.Name, err)
		} else if len(rules) <= 1 {
			return nil
		} else {
			for _, r := range rules[1:] {
				r.Table.Family = nft.Table.Family
				//fmt.Printf("rule.Table: %v rule.Chain: %v\n", []byte(r.Table.Name), []byte(r.Chain.Name))
				if areRulesEql(r, rule, false) {
					if err := nft.delRuleAndFlush(r); err != nil {
						log.Printf(`failed to delete duplicate rules: %s`, err)
					}
				}
			}
		}
	}
	return nil
}

//pushRuleAndFlush pushes a rule in table, chain on the first place (i.e. on top of all the other rules)
func (nft *NFTables) pushRuleAndFlush(r *nftables.Rule) error {
	if rule, err := nft.getFirstRule(r.Chain); err != nil {
		return fmt.Errorf(`could not get first rule in "%s" table "%s" chain: %w`,
			r.Table.Name, r.Chain.Name, err)
	} else if rule != nil {
		r.Position = rule.Handle
	}
	nft.Conn.InsertRule(r)
	nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, insertRuleToString(r))
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			// TODO: rollback
			return fmt.Errorf(`"%s" table "%s" chain rule insert - commit to kernel failed: %w`,
				r.Table.Name, r.Chain.Name, err)
		}
	}
	return nil
}

//addBaseChainsRulesAndFlush adds the rules in the base chains and commits them to the kernel
func (nft *NFTables) addBaseChainsRulesAndFlush() (err error) {
	var (
		ok bool
	)
	if ok, err = nft.isFirstRule(nft.Rules[FwdRuleIdx]); err != nil {
		return fmt.Errorf(ErrAddBaseChainRule, err)
	}
	if !ok {
		if err = nft.pushRuleAndFlush(nft.Rules[FwdRuleIdx]); err != nil {
			return fmt.Errorf(ErrAddBaseChainRule, err)
		}
	}
	if ok, err = nft.isFirstRule(nft.Rules[InRuleIdx]); err != nil {
		return fmt.Errorf(ErrAddBaseChainRule, err)
	}
	if !ok {
		if err = nft.pushRuleAndFlush(nft.Rules[InRuleIdx]); err != nil {
			return fmt.Errorf(ErrAddBaseChainRule, err)
		}
	}
	if err = nft.delDuplicateRules(nft.Rules[FwdRuleIdx]); err != nil {
		log.Printf("%s", err)
	}
	if !nft.DryRun {
		// get the handles of the rules in fwd and input chains
		if rule, err := nft.getFirstRule(nft.FwdChain); err != nil {
			return fmt.Errorf(ErrAddBaseChainRule, err)
		} else if rule != nil {
			nft.Rules[FwdRuleIdx].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain rule handle: %d`,
			nft.Table.Name, nft.FwdChain.Name, nft.Rules[FwdRuleIdx].Handle)
		if rule, err := nft.getFirstRule(nft.InChain); err != nil {
			return fmt.Errorf(ErrAddBaseChainRule, err)
		} else if rule != nil {
			nft.Rules[InRuleIdx].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain rule handle: %d`,
			nft.Table.Name, nft.InChain.Name, nft.Rules[InRuleIdx].Handle)
	}
	return nil
}

//addRegChainRulesAndFlush adds the rules to the regular (jump target) chain and commits them to the kernel
func (nft *NFTables) addRegChainRulesAndFlush() error {
	var (
		err   error
		rules []*nftables.Rule
	)
	if rules, err = nft.Conn.GetRule(nft.Table, nft.RegChain); err != nil {
		return fmt.Errorf("could not get rules from table %s chain %s: %w",
			nft.Table.Name, nft.RegChain.Name, err)
	}
	if len(rules) != 0 {
		// there are already rules in the chain
		blFound, wlFound := false, false
		for _, rule := range rules {
			wlFound = wlFound || areRulesEql(rule, nft.Rules[WlRuleIdx], false)
			blFound = blFound || areRulesEql(rule, nft.Rules[BlRuleIdx], false)
			if wlFound && blFound {
				break
			}
		}
		if !blFound {
			if err = nft.pushRuleAndFlush(nft.Rules[BlRuleIdx]); err != nil {
				return fmt.Errorf("failed to add target chain rule: %w", err)
			}
		}
		if !wlFound {
			if err = nft.pushRuleAndFlush(nft.Rules[WlRuleIdx]); err != nil {
				return fmt.Errorf("failed to add target chain rule: %w", err)
			}
		}
	} else {
		for _, rule := range nft.Rules[WlRuleIdx : BlRuleIdx+1] {
			nft.Conn.AddRule(rule)
			nft.Commands = fmt.Sprintf("%s%s\n", nft.Commands, addRuleToString(rule))
		}
		if !nft.DryRun {
			if err = nft.Conn.Flush(); err != nil {
				// TODO: rollback
				return fmt.Errorf(`"%s" table rule add - commit to kernel failed: %w`,
					nft.Table.Name, err)
			}
		}
	}
	if !nft.DryRun {
		// get the handles of the rules in the target chain
		if rules, err = nft.Conn.GetRule(nft.Table, nft.RegChain); err != nil {
			return fmt.Errorf("could not get rules from table %s chain %s: %w",
				nft.Table.Name, nft.RegChain.Name, err)
		}
		for i, rule := range rules {
			if i > 1 {
				break
			}
			nft.Rules[WlRuleIdx+i].Handle = rule.Handle
		}
		log.Printf(`"%s" table "%s" chain whitelist rule handle: %d`,
			nft.Table.Name, nft.RegChain.Name, nft.Rules[WlRuleIdx].Handle)
		log.Printf(`"%s" table "%s" chain blacklist rule handle: %d`,
			nft.Table.Name, nft.RegChain.Name, nft.Rules[BlRuleIdx].Handle)
	}
	return nil
}

// addRulesAndFlush commits the rules into the kernel
func (nft *NFTables) addRulesAndFlush() error {
	if err := nft.addRegChainRulesAndFlush(); err != nil {
		return err
	}
	if err := nft.addBaseChainsRulesAndFlush(); err != nil {
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
			return fmt.Errorf(ErrDelRules, nft.Table.Name, err)
		}
	}
	if !nft.DryRun {
		if err := nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrDelRules, nft.Table.Name, err)
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

func (nft *NFTables) setAddElements(set *nftables.Set, elements []nftables.SetElement) (cnt int) {
	var i int
	for i = 0; i < len(elements)/MaxSetSize; i++ {
		if err := nft.setAddElementsAndFlush(set, elements[i*MaxSetSize:(i+1)*MaxSetSize]); err != nil {
			log.Printf(ErrAddSetElements, set.Name, err)
		} else {
			cnt += MaxSetSize
		}
	}
	if len(elements) > i*MaxSetSize {
		if err := nft.setAddElementsAndFlush(set, elements[i*MaxSetSize:]); err != nil {
			log.Printf(ErrAddSetElements, set.Name, err)
		} else {
			cnt += len(elements) - i*MaxSetSize
		}
	}
	return
}

func (nft *NFTables) setAddElementsAndFlush(set *nftables.Set, elements []nftables.SetElement) (err error) {
	if err = nft.Conn.SetAddElements(set, elements); err != nil {
		return fmt.Errorf(ErrAddSetElements, set.Name, err)
	}
	if !nft.DryRun {
		if err = nft.Conn.Flush(); err != nil {
			return fmt.Errorf(ErrAddSetElements, set.Name, err)
		}
	}
	return nil
}

func (nft *NFTables) addIpsToSet(idx SetIdx, ips []string, timeout time.Duration) (cnt int, err error) {
	var elements [2 * MaxSetSize]nftables.SetElement
	cnt = 0
	err = nil
	sElements := SetElements(elements[:])
	set := nft.getSet(idx)
	if set == nil {
		return 0, fmt.Errorf(`unknown set (index %d)`, idx)
	}
	l, i := 0, 0
	for i = 0; i < len(ips); i += l {
		l = sElements.addIps(ips[i:], timeout)
		if l == 0 {
			break
		}
		cnt += nft.setAddElements(set, elements[0:l])
		if l >= len(ips[i:]) {
			break
		}
	}
	return
}

func (nft *NFTables) AddToWhitelist(ips []string, timeout time.Duration) (int, error) {
	return nft.addIpsToSet(WlSet, ips, timeout)
}

func (nft *NFTables) AddToBlacklist(ips []string, timeout time.Duration) (int, error) {
	return nft.addIpsToSet(BlSet, ips, timeout)
}

func (nft *NFTables) GetCommands() string {
	return nft.Commands
}
