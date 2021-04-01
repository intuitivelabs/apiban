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
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/intuitivelabs/apiban/clients/go/apiban"
)

var (
	configFilename string
	logFilename    string
	url            string
	chain          string
	interval       int
	full           string
	useStateFile   = false
)

// profiler
var (
	useProfiler = false
	wg          sync.WaitGroup
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

	startProfiler(useProfiler)

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
	if useStateFile {
		if err := apiban.GetState().LoadFromFile(); err != nil {
			log.Println(err)
		}
	}

	apiban.InitEncryption(apiconfig)

	fmt.Println("Creating ipset...")
	iptables, err := apiban.InitializeIPTables(apiconfig.Chain, "blacklist", "whitelist", false /*dry-run?*/)

	if err != nil {
		log.Fatalln("failed to initialize iptables and ipsets: ", err)
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
	if err := run(ctx, *iptables, *apiconfig, sigChan); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	wg.Wait()
}

func run(ctx context.Context, ipt apiban.IPTables, apiconfig apiban.Config, sigChan chan os.Signal) error {

	var bId, aId string
	var cnt int
	// use the last timestamp saved in the state file (if non zero)
	if bId = apiban.GetState().Timestamp; bId == "" {
		bId = apiconfig.Lkid
	}
	aId = bId
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
			cnt++
			// change the timeout to the one in the configuration
			log.Println("ticker:", t)
			//res, err := apiban.ApiRequest(apiconfig.Apikey, id, apiconfig.Version, apiconfig.Url, "banned")
			bId, err = apiban.ApiBannedIP(apiconfig.Apikey, bId, apiconfig.Version, apiconfig.Url, apiconfig.Lkid)
			if err != nil {
				log.Printf("failed to update blacklist: %s", err)
			}
			aId, err = apiban.ApiAllowedIP(apiconfig.Apikey, aId, apiconfig.Version, apiconfig.Url, apiconfig.Lkid)
			if err != nil {
				log.Println("failed to update whitelist: %s", err)
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
