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

	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/anonymization"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/api"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/config"
	"github.com/intuitivelabs/apiban/clients/go/internal/pkg/firewall"
)

var (
	useStateFile = false
	logFile      *os.File
	cfg          *config.Config
)

// profiler
var (
	useProfiler = false
	wg          sync.WaitGroup
)

func init() {
	var err error
	// Open our config file
	cfg, err = config.LoadConfig()
	if err != nil {
		log.Fatalln(err)
	}

	// Open our Log
	if cfg.LogFilename != "-" && cfg.LogFilename != "stdout" {
		logFile, err := os.OpenFile(cfg.LogFilename,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(-1)
		}

		log.SetOutput(logFile)
	}

	if err := config.FixConfig(cfg); err != nil {
		log.Fatalln(err)
	}

	if cfg.StateFilename != "" {
		config.GetState().Init(cfg.StateFilename)
	}
	if useStateFile {
		if err := config.GetState().LoadFromFile(); err != nil {
			log.Println(err)
		}
	}

	anonymization.InitEncryption(cfg)
	//TODO debug
	//fmt.Println("Initializing firewall...")
	if _, err := firewall.InitializeFirewall("honeynet", "blacklist", "whitelist", cfg.DryRun, cfg.AddBaseObj); err != nil {
		log.Fatalln("failed to initialize firewall: ", err)
	}

	binIpOutput := cfg.UseNftables
	api.RegisterIpApis(cfg.Timestamp, cfg.Url, cfg.Token, cfg.Limit, binIpOutput)
	api.RegisterUriApis(cfg.Timestamp, cfg.Url, cfg.Token, cfg.Limit)

	if cfg.DryRun {
		os.Exit(0)
	}
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
	case syscall.SIGTERM:
		if err := config.GetState().SaveToFile(); err != nil {
			log.Println(err)
		}
		os.Exit(1)
	default:
		// no processing
	}
}

func installSignalHandler() chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	return c
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	defer logFile.Close()

	startProfiler(useProfiler)

	sigChan := installSignalHandler()

	log.Print("** client start")

	if err := eventLoop(ctx, cfg.Interval, sigChan); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	wg.Wait()
}

func eventLoop(ctx context.Context, interval time.Duration, sigChan chan os.Signal) error {
	var err error
	var cnt int

	// start right away
	currentTimeout := 1 * time.Nanosecond
	for ticker := time.NewTicker(currentTimeout); ; {
		select {
		case <-ctx.Done():
			return nil
		case sig := <-sigChan:
			signalHandler(sig)

		case <-ticker.C:
			cnt++
			// change the timeout to the one in the configuration
			for _, a := range api.Apis {
				err = a.Process()
				if err != nil {
					log.Printf(`failed to process API "%s": %s`, a.Name, err)
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
