/*
Yggkeygen is a tool for generating Yggdrasil network keys.
It can generate both regular keys and signing keys, with options to find
the strongest possible key by searching for a specified duration.

The tool uses all available CPU cores to generate keys as quickly as possible.
By default, it generates a single key and outputs its details.
*/
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"suah.dev/protect"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type keySet struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	count uint64
}

type keyOutput struct {
	Private string `json:"private"`
	Public  string `json:"public"`
	IP      string `json:"ip"`
}

func printHelp() {
	fmt.Fprintf(os.Stderr, `Usage: yggkeygen [options]

Yggkeygen generates Yggdrasil network keys. By default, it generates a single key
and outputs its details. The tool uses all available CPU cores to generate keys
as quickly as possible.

Options:
  -strong
        Generate the strongest possible key over 5 seconds
  -quiet
        Suppress all output except key information
  -json
        Output key information in JSON format
  -help
        Show this help message

Examples:
  yggkeygen              # Generate a single key
  yggkeygen -strong      # Search for 5 seconds to find the strongest key
  yggkeygen -quiet -json # Generate a single key, output only JSON
`)
	os.Exit(0)
}

func main() {
	if err := protect.Pledge("stdio"); err != nil {
		panic(err)
	}

	strongMode := flag.Bool("strong", false, "Generate the strongest possible key over 5 seconds")
	quietMode := flag.Bool("quiet", false, "Suppress all output except key information")
	jsonMode := flag.Bool("json", false, "Output key information in JSON format")
	helpMode := flag.Bool("help", false, "Show help message")
	flag.Parse()

	if *helpMode {
		printHelp()
	}

	threads := runtime.GOMAXPROCS(0)
	if !*quietMode {
		fmt.Println("Threads:", threads)
	}
	var totalKeys uint64
	totalKeys = 0
	var currentBest ed25519.PublicKey
	newKeys := make(chan keySet, threads)
	for i := 0; i < threads; i++ {
		go doKeys(newKeys)
	}

	outputKey := func(priv ed25519.PrivateKey, pub ed25519.PublicKey) {
		addr := address.AddrForKey(pub)
		if *jsonMode {
			output := keyOutput{
				Private: hex.EncodeToString(priv),
				Public:  hex.EncodeToString(pub),
				IP:      net.IP(addr[:]).String(),
			}
			jsonData, err := json.Marshal(output)
			if err != nil {
				panic(err)
			}
			fmt.Println(string(jsonData))
		} else {
			fmt.Println("Private:", hex.EncodeToString(priv))
			fmt.Println("Public:", hex.EncodeToString(pub))
			fmt.Println("IP:", net.IP(addr[:]).String())
		}
	}

	if *strongMode {
		if !*quietMode {
			fmt.Println("Running in strong mode - searching for best key over 5 seconds...")
		}
		timeout := time.After(5 * time.Second)
		var bestKeySet keySet
		for {
			select {
			case newKey := <-newKeys:
				if isBetter(currentBest, newKey.pub) || len(currentBest) == 0 {
					totalKeys += newKey.count
					currentBest = newKey.pub
					bestKeySet = newKey
				}
			case <-timeout:
				if !*quietMode {
					fmt.Printf("\nGenerated best key after trying %d keys:\n", totalKeys)
				}
				outputKey(bestKeySet.priv, bestKeySet.pub)
				return
			}
		}
	} else {
		// Default mode: generate a single key
		newKey := <-newKeys
		totalKeys += newKey.count
		if !*quietMode {
			fmt.Printf("Generated key after trying %d keys:\n", totalKeys)
		}
		outputKey(newKey.priv, newKey.pub)
	}
}

func isBetter(oldPub, newPub ed25519.PublicKey) bool {
	for idx := range oldPub {
		if newPub[idx] < oldPub[idx] {
			return true
		}
		if newPub[idx] > oldPub[idx] {
			break
		}
	}
	return false
}

func doKeys(out chan<- keySet) {
	bestKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	var count uint64
	count = 0
	for idx := range bestKey {
		bestKey[idx] = 0xff
	}
	for {
		pub, priv, err := ed25519.GenerateKey(nil)
		count++
		if err != nil {
			panic(err)
		}
		if !isBetter(bestKey, pub) {
			continue
		}
		bestKey = pub
		out <- keySet{priv, pub, count}
		count = 0
	}
}
