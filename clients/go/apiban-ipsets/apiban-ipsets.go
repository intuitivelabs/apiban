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
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/intuitivelabs/apiban/clients/go/apiban"
)

var (
	useStateFile = false
)

// profiler
var (
	useProfiler = false
	wg          sync.WaitGroup
)

func init() {
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
	var (
		err  error
		apis [3]*apiban.Api
	)
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	defer func() {
		cancel()
	}()

	//	defer os.Exit(0)

	startProfiler(useProfiler)

	sigChan := installSignalHandler()

	log.Print("** client start")

	// Open our config file
	apiconfig, err := apiban.LoadConfig()
	if err != nil {
		log.Fatalln(err)
	}

	// Open our Log
	if apiconfig.LogFilename != "-" && apiconfig.LogFilename != "stdout" {
		lf, err := os.OpenFile(apiconfig.LogFilename,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(-1)
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	if err := apiban.FixConfig(apiconfig); err != nil {
		log.Fatalln(err)
	}
	log.Print("target chain:", apiconfig.TgtChain)

	log.Print("time interval for checking the list:", apiconfig.Tick)

	if apiconfig.StateFilename != "" {
		apiban.GetState().Init(apiconfig.StateFilename)
	}
	if useStateFile {
		if err := apiban.GetState().LoadFromFile(); err != nil {
			log.Println(err)
		}
	}

	apiban.InitEncryption(apiconfig)

	fmt.Println("Initializing firewall...")
	_, err = apiban.InitializeFirewall("blacklist", "whitelist", false)

	if err != nil {
		log.Fatalln("failed to initialize firewall: ", err)
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
	apis[0] = apiban.NewBannedApi(apiconfig.Lkid, apiconfig.Url, apiconfig.Token)
	apis[1] = apiban.NewAllowedApi(apiconfig.Lkid, apiconfig.Url, apiconfig.Token)
	apis[2] = apiban.NewUriApi(apiconfig.Lkid, apiconfig.Url, apiconfig.Token)

	fmt.Println("going to run in a looop")
	if err := run(ctx, *apiconfig, apis[:], sigChan); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	wg.Wait()
}

func run(ctx context.Context, apiconfig apiban.Config, apis []*apiban.Api, sigChan chan os.Signal) error {
	var err error
	var cnt int
	// use the last timestamp saved in the state file (if non zero)
	// Get list of banned ip's from APIBAN.org
	fmt.Println("URL", apiconfig.Url)
	fmt.Print("TICK", apiconfig.Tick)
	interval := apiconfig.Tick

	// start right away
	currentTimeout := time.Duration(1 * time.Nanosecond)
	for ticker := time.NewTicker(currentTimeout); ; {
		t := time.Time(time.Now())
		fmt.Println("ticker: ", t)
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
			fmt.Println("ticker:", t)
			for _, api := range apis {
				err = api.Process()
				if err != nil {
					log.Printf(`failed to process API "%s": %s`, api.Url, err)
				}
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
