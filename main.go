/*
This file generates crypto keys.
It prints out a new set of keys each time if finds a "better" one.
By default, "better" means a higher NodeID (-> higher IP address).
This is because the IP address format can compress leading 1s in the address, to increase the number of ID bits in the address.
*/
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
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

func main() {
	if err := protect.Pledge("stdio"); err != nil {
		panic(err)
	}

	strongMode := flag.Bool("strong", false, "Generate the strongest possible key over 5 seconds")
	quietMode := flag.Bool("quiet", false, "Suppress all output except key information")
	flag.Parse()

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
				fmt.Println("Private:", hex.EncodeToString(bestKeySet.priv))
				fmt.Println("Public:", hex.EncodeToString(bestKeySet.pub))
				addr := address.AddrForKey(bestKeySet.pub)
				fmt.Println("IP:", net.IP(addr[:]).String())
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
		fmt.Println("Private:", hex.EncodeToString(newKey.priv))
		fmt.Println("Public:", hex.EncodeToString(newKey.pub))
		addr := address.AddrForKey(newKey.pub)
		fmt.Println("IP:", net.IP(addr[:]).String())
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
