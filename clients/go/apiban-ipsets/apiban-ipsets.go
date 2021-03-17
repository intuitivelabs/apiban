/*
 * Copyright (C) 2020 Fred Posner (palner.com)
 *
 * This file is part of APIBAN.org.
 *
 * apiban-iptables-client is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * apiban-iptables-client is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/intuitivelabs/anonymization"
	"github.com/intuitivelabs/apiban/clients/go/apiban"
	"github.com/vladabroz/go-ipset/ipset"
)

var (
	configFilename string
	logFilename    string
	url            string
	chain          string
	interval       int
	full           string
)

// profiler
var (
	isProfilerOn = true
	wg           sync.WaitGroup
)

const (
	defaultId = "0"
)

func init() {
	flag.StringVar(&chain, "chain", "BLOCKER", "chain for matching entries")
	flag.StringVar(&configFilename, "config", "", "location of configuration file")
	flag.StringVar(&logFilename, "log", "/var/log/apiban-ipsets.log", "location of log file or - for stdout")
	flag.StringVar(&url, "url", "https://siem.intuitivelabs.com/api/", "URL of blacklisted IPs DB")
	flag.IntVar(&interval, "interval", 60, "interval in seconds for the list refresh")
	flag.StringVar(&full, "full", "no", "yes/no - starting from scratch")
	//flag.StringVar(&url, "url", "https://latewed-alb-11jg2pxd7j3ue-835913326.eu-west-1.elb.amazonaws.com/stats?table=ipblacklist&json", "URL of blacklisted IPs DB")
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

func startProfiler(isOn bool) {
	if isOn {
		wg.Add(1)
		go func() {
			log.Printf("Starting Server! \t Go to http://localhost:6060/debug/pprof/\n")
			err := http.ListenAndServe("localhost:6060", nil)
			if err != nil {
				log.Printf("Failed to start the server! Error: %v", err)
				wg.Done()
			}
		}()
	}
}

func signalHandler(sig os.Signal) {
	switch sig {
	case syscall.SIGINT:
		fallthrough
	case syscall.SIGKILL:
		fallthrough
	case syscall.SIGTERM:
		if err := apiban.GetState().SaveToFile(); err != nil {
			log.Println(err)
		}
		os.Exit(1)
	default:
		// no processing
	}
}

func installSignalHandler() chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	return c
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	flag.Parse()

	defer func() {
		cancel()
	}()

	//	defer os.Exit(0)

	startProfiler(isProfilerOn)

	sigChan := installSignalHandler()

	// Open our Log
	if logFilename != "-" && logFilename != "stdout" {
		lf, err := os.OpenFile("/var/log/apiban-ipsets.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	log.Print("** Started APIBAN IPSETS CLIENT")
	log.Print("Licensed under GPLv2. See LICENSE for details.")

	// Open our config file
	apiconfig, err := apiban.LoadConfig(configFilename)
	if err != nil {
		log.Fatalln(err)
	}

	// if no APIKEY, exit
	if apiconfig.Apikey == "" {
		log.Fatalln("Invalid APIKEY. Exiting.")
	}
	// log config values
	log.Print("CLI of FULL received, resetting LKID")

	// allow cli of FULL to reset LKID to 100
	if len(os.Args) > 1 {
		arg1 := os.Args[1]
		if arg1 == "FULL" {
			log.Print("CLI of FULL received, resetting LKID")
			apiconfig.Lkid = defaultId //"100"
		}
	} else {
		log.Print("no command line arguments received")
	}

	// reset LKID to 100 if specified in config file
	if apiconfig.Full == "yes" {
		log.Print("FULL=yes in config file, resetting LKID")
		apiconfig.Lkid = defaultId //"100"
	}

	// if no LKID, reset it to 100
	if len(apiconfig.Lkid) == 0 {
		log.Print("Resetting LKID")
		apiconfig.Lkid = defaultId // "100"
	} else {
		log.Print("LKID:", apiconfig.Lkid)
	}

	// use default
	if len(apiconfig.Chain) == 0 {
		apiconfig.Chain = "BLOCKER"
	}
	log.Print("Chain:", apiconfig.Chain)

	log.Print("Interval for checking the list:", apiconfig.Tick)

	if apiconfig.StateFilename != "" {
		apiban.GetState().Init(apiconfig.StateFilename)
	}
	if err := apiban.GetState().LoadFromFile(); err != nil {
		log.Println(err)
	}

	// generate encryption key from passphrase
	if len(apiconfig.Passphrase) > 0 {
		if apiban.Ipcipher, err = anonymization.NewPassphraseCipher(apiconfig.Passphrase); err != nil {
			log.Fatalln("Cannot initialize ipcipher. Exiting.")
		}
		// initialize a validator using the configured passphrase; neither length nor salt are used since this validator verifies only the remote code
		if apiban.Validator, err = anonymization.NewPassphraseValidator(apiconfig.Passphrase, 0 /*length*/, "" /*salt*/); err != nil {
			log.Fatalln("Cannot initialize validator. Exiting.")
		}
	}
	// Go connect for IPTABLES
	ipt, err := iptables.New()
	if err != nil {
		log.Panic(err)
	}

	//	if err := initializeIPTables(ipt); err != nil {
	//		log.Fatalln("failed to initialize IPTables:", err)
	//	}

	fmt.Println("Creating ipset...")
	blset, err := initializeIPTables(ipt, apiconfig.Chain)

	if err != nil {
		log.Fatalln("failed to initialize iptables and ipsets", err)
	}

	//if iptinit == "chain created" {
	//	log.Print("APIBAN chain was created - Resetting LKID")
	//	apiconfig.Lkid = defaultId
	//}

	///	// Creating ipset "blacklist"
	///	fmt.Println("Creating blacklist")
	///	blset, err := ipset.New("blacklist", "hash:ip", &ipset.Params{})
	///	if err != nil {
	///		fmt.Print("Error", err)
	///	}

	//_, err := blset.List()
	//if err != nil {
	//	fmt.Print("Error", err)
	//}
	//fmt.Print("Content", content)
	fmt.Println("going to run in a looop")
	if err := run(ctx, *blset, *apiconfig, sigChan); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	wg.Wait()
}

func run(ctx context.Context, blset ipset.IPSet, apiconfig apiban.Config, sigChan chan os.Signal) error {

	var id string
	// use the last timestamp saved in the state file (if non zero)
	if id = apiban.GetState().Timestamp; id == "" {
		id = apiconfig.Lkid
	}
	// Get list of banned ip's from APIBAN.org
	fmt.Println("APIKEY", apiconfig.Apikey)
	fmt.Println("URL", apiconfig.Url)
	fmt.Println("TICK", apiconfig.Tick)
	interval, err := time.ParseDuration(apiconfig.Tick)
	if err != nil {
		log.Print("Invalid interval format")
		return err
	}

	// start right away
	currentTimeout := time.Duration(1 * time.Nanosecond)
	for ticker := time.NewTicker(currentTimeout); ; {
		t := time.Time(time.Now())
		log.Println("ticker: ", t)
		select {
		/*
			case <-ctx.Done():
				return nil
		*/
		case sig := <-sigChan:
			signalHandler(sig)

		case t = <-ticker.C:
			// change the timeout to the one in the configuration
			log.Println("ticker:", t)
			res, err := apiban.Banned(apiconfig.Apikey, id, apiconfig.Version, apiconfig.Url)
			if err != nil {
				log.Println("failed to get banned list:", err)
			} else if res == nil {
				log.Println("response with empty body")
			} else {
				apiban.ProcBannedResponse(res, apiconfig.Lkid, blset)
				id = res.ID
			}
		}
		newTimeout := interval
		if newTimeout != currentTimeout {
			/* stop the old timer */
			ticker.Stop()
			currentTimeout = newTimeout
			ticker = time.NewTicker(currentTimeout)
		}
	}
}

func initializeIPTables(ipt *iptables.IPTables, blChain string) (*ipset.IPSet, error) {
	// Get existing chains from IPTABLES
	//fmt.Println("chain to be checked: ", blChain)
	originaListChain, err := ipt.ListChains("filter")
	if err != nil {
		//return "error", fmt.Errorf("failed to read iptables: %w", err)
		return nil, fmt.Errorf("failed to read iptables: %w", err)
	}

	// Search for INPUT in IPTABLES
	if !contains(originaListChain, "INPUT") {
		//return "error", errors.New("iptables does not contain expected INPUT chain")
		return nil, errors.New("iptables does not contain expected INPUT chain")
	}

	// Search for FORWARD in IPTABLES
	if !contains(originaListChain, "FORWARD") {
		//return "error", errors.New("iptables does not contain expected FORWARD chain")
		return nil, errors.New("iptables does not contain expected FORWARD chain")
	}

	// Search for our blacklist chain in IPTABLES
	if !contains(originaListChain, blChain) {
		// create chain itsefl
		log.Print("IPTABLES doesn't contain %s. Creating now...", blChain)
		err = ipt.ClearChain("filter", blChain)
		if err != nil {
			//return "error", fmt.Errorf("failed to clear APIBAN chain: %w", err)
			return nil, fmt.Errorf("failed to clear APIBAN chain: %w", err)
		}
	}

	// Check if target to blocking chain
	inpExists, err := ipt.Exists("filter", "INPUT", "-j", blChain)
	if err != nil {
		//return "error", fmt.Errorf("failed to check rule in INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to check rule in INPUT chain: %w", err)
	}
	// Add blocking chain to INPUT
	if inpExists == false {
		log.Print("Adding target to %s into INPUT chain", blChain)
		err = ipt.Insert("filter", "INPUT", 1, "-j", blChain)
		if err != nil {
			//return "error", fmt.Errorf("failed to add blocking target to INPUT chain: %w", err)
			return nil, fmt.Errorf("failed to add blocking target to INPUT chain: %w", err)
		}
	}
	/*
		err = ipt.Insert("filter", "INPUT", 1, "-j", blChain)
		if err != nil {
			return "error", fmt.Errorf("failed to add APIBAN chain to INPUT chain: %w", err)
		}
	*/

	// Check if target to blocking chain
	fwdExists, err := ipt.Exists("filter", "FORWARD", "-j", blChain)
	if err != nil {
		//return "error", fmt.Errorf("failed check rule in FORWARD chain: %w", err)
		return nil, fmt.Errorf("failed check rule in FORWARD chain: %w", err)
	}
	// Add blocking chain to FORWARD
	if fwdExists == false {
		log.Print("Adding target to %s into FORWARD chain", blChain)
		err = ipt.Insert("filter", "FORWARD", 1, "-j", blChain)
		if err != nil {
			//return "error", fmt.Errorf("failed to add blocking target to INPUT chain: %w", err)
			return nil, fmt.Errorf("failed to add blocking target to INPUT chain: %w", err)
		}
	}

	// test if ipset is existing
	//exists, err := checkIPSet("blacklist")
	//if exists == false {
	//	// Creating ipset "blacklist"
	//	//fmt.Println("Creating blacklist")
	//	make blset, err := ipset.New("blacklist", "hash:ip", &ipset.Params{})
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to create blacklist ipset: %w", err)
	//	}
	//	fmt.Println("ipset successfully created")
	//	//return blset, nil
	//} else {
	//	//blset := ipset.IPSet{"blacklist", "hash:ip", &ipset.Params{}}
	//	//blset, err := ipset.Refresh("blacklist", "hash:ip", &ipset.Params{})
	//	make blset := &ipset.IPSet{"blacklist", "hash:ip", "inet", 1024, 65536, 0}
	//	fmt.Println("using ipset.IPSet")
	//	//blset := ipset.Init("blacklist")
	//	//return blset, fmt.Errorf("failed to create ipset")
	//	//return blset, nil
	//	//blset := ipset.Init("blacklist")
	//}

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
	err = ipt.ClearChain("filter", blChain)
	if err != nil {
		//return "error", fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to clean our chain: %w", err)
	}

	// Add rule to blocking chain to check ipset
	log.Print("Creating a rule to check our ipset")
	err = ipt.Insert("filter", blChain, 1, "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP")
	if err != nil {
		//return "error", fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
		return nil, fmt.Errorf("failed to add ipset chain to INPUT chain: %w", err)
	}

	//return "chain created", nil
	return blset, nil
}
