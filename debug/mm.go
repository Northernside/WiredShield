package main

import (
	"crypto/rand"
	"log"
	"math/big"
	"net"
	"sync"
)

var ipv6Prefix = "2001:470:74f2::/48"

const workers = 4096
const totalIPs = (1 << 48) / workers

func worker(id int, wg *sync.WaitGroup, jobs <-chan int) {
	defer wg.Done()
	for i := range jobs {
		if i%1000000 == 0 {
			log.Printf("Worker %d: generated %d/%d ips (%d%%)", id, i, totalIPs, i*100/totalIPs)
		}

		ip := generateIpv6Address()
		if ip.To16() == nil {
			log.Fatalf("Worker %d: generated invalid ipv6 address: %v", id, ip)
		}
	}
}

func main() {
	jobs := make(chan int, workers*2)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go worker(w, &wg, jobs)
	}

	for i := 0; i < totalIPs; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
}

var (
	prefixLen   int
	dynBits     int
	prefixBytes []byte
)

func init() {
	_, ip, err := net.ParseCIDR(ipv6Prefix)
	if err != nil {
		log.Fatalf("could not parse ipv6 prefix: %v", err)
	}

	prefixLen, _ = ip.Mask.Size()
	dynBits = 128 - prefixLen
	prefixBytes = ip.IP[:prefixLen/8]
}

func generateIpv6Address() net.IP {
	randBits, _ := rand.Int(rand.Reader, big.NewInt(int64(dynBits+1))) // dynBits+1 weil soll mindestens eine ziffer haben ig

	suffixBits := int(randBits.Int64())
	suffixBytes := make([]byte, (suffixBits+7)/8) // remaining bits
	_, err := rand.Read(suffixBytes)
	if err != nil {
		log.Fatalf("could not generate random bytes (for suffix): %v", err)
	}

	fullIP := make([]byte, 16)
	copy(fullIP, prefixBytes)
	copy(fullIP[len(prefixBytes):], suffixBytes)

	return net.IP(fullIP)
}
