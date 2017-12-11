package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
	"net"
	"os"
	"sync"
)

const (
	loading = iota
	available
	unavailable
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please enter a domain name")
		return
	}

	input := os.Args[1]
	tlds := []string{"com", "net", "dk", "org", "xxx", "io", "co.uk"}

	var state sync.Map
	for _, tld := range tlds {
		state.Store(tld, loading)
	}

	hasPrintedState := false

	mutex := &sync.Mutex{}

	printState := func() {
		mutex.Lock()
		if hasPrintedState {
			fmt.Printf("\033[%vF", len(tlds))
		} else {
			hasPrintedState = true
		}

		for _, tld := range tlds {
			name := input + "." + tld
			line := name + ": "
			value, _ := state.Load(tld)
			switch value {
			case available:
				line += color.GreenString("Available")
			case unavailable:
				line += color.RedString("Unavailable")
			}
			fmt.Println(line)
		}
		mutex.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(len(tlds) * 2)

	for i := range tlds {
		tld := tlds[i]
		name := input + "." + tld

		go func() {
			defer wg.Done()
			_, err := net.LookupHost(name)
			if err == nil {
				state.Store(tld, unavailable)
				printState()
			}
		}()

		go func() {
			defer wg.Done()
			rawResult, _ := whois.Whois(name)
			result, err := whois_parser.Parser(rawResult)
			if err == nil {
				if result.Registrar.DomainStatus != "" {
					state.Store(tld, unavailable)
					printState()
				} else {
					state.Store(tld, available)
					printState()
				}
			}
		}()
	}

	wg.Wait()
}
