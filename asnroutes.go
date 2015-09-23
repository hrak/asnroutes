/*
asnroutes fetches all routes announced by an AS number from RADB
The routes are then aggregated by checking for overlapping subnets

The main goal for this tool is to create ACLs or firewall rules
*/
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hrak/asnroutes/netutils"
)

var (
	asns                   intSlice
	ipv4Ranges, ipv6Ranges ipRanges
)

type ipRanges []*net.IPNet

// Define a type named "intslice" as a slice of ints
type intSlice []int

// Now, for our new type, implement the two methods of
// the flag.Value interface...
// The first method is String() string
func (i *intSlice) String() string {
	return fmt.Sprintf("%d", *i)
}

// The second method is Set(value string) error
func (i *intSlice) Set(value string) error {
	if len(*i) > 0 {
		return errors.New("as flag already set")
	}
	for _, as := range strings.Split(value, ",") {
		tmp, err := strconv.Atoi(as)
		if err != nil {
			*i = append(*i, -1)
		} else {
			*i = append(*i, tmp)
		}
	}
	return nil
}

// Implement Sort interface for ipRanges
func (ranges *ipRanges) Add(iprange *net.IPNet) []*net.IPNet {
	*ranges = append(*ranges, iprange)
	return *ranges
}

func (slice ipRanges) Len() int {
	return len(slice)
}

func (slice ipRanges) Less(i, j int) bool {
	// Sort IP ranges by size based on netmask
	maskSize1, _ := slice[i].Mask.Size()
	maskSize2, _ := slice[j].Mask.Size()
	return maskSize1 < maskSize2
}

func (slice ipRanges) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Queries whois server for queryString and returns a slice of strings with the response
func whois(queryString, server string) ([]string, error) {
	conn, err := net.Dial("tcp", server+":43")

	if err != nil {
		return nil, fmt.Errorf("Error connecting to whois server %s: %v", server, err)
	}

	defer conn.Close()

	// send to socket
	fmt.Fprintf(conn, queryString+"\r\n")

	// listen for reply
	var result []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}
	return result, scanner.Err()
}

// Parses the whois output and filters out the routes
// Stores the result sorted by subnet size (desc) in global slices:
// 'ipv4Ranges' for all IPv4 routes
// 'ipv6Ranges' for all IPv6 routes
// returns error on error
func parseRanges(result []string) error {
	re, err := regexp.Compile(`route6{0,1}:\s+(.+)`)
	if err != nil {
		return fmt.Errorf("Error compiling regex: %s", err)
	}
	for _, line := range result {
		iprange := re.FindStringSubmatch(line)
		if iprange != nil {
			//fmt.Printf("%s\n", iprange[1])
			if _, network, err := net.ParseCIDR(iprange[1]); err != nil {
				return fmt.Errorf("Unexpected IP range format: %s (%s)", err, line)
			} else {
				if len(network.IP) == net.IPv4len {
					ipv4Ranges = ipv4Ranges.Add(network)
				} else {
					ipv6Ranges = ipv6Ranges.Add(network)
				}
			}
		}
	}
	sort.Sort(ipv4Ranges)
	sort.Sort(ipv6Ranges)
	return nil
}

// Aggregate routes by finding overlapping subnets
// We pass a pointer to the ipRanges slice to prevent a copy
func aggregateRanges(ranges *ipRanges) {
	// No need to check if there is only one range
	if len(*ranges) > 1 {
		for i := 0; i < len(*ranges); i++ {
			for j := 0; j < len(*ranges); j++ {
				if netutils.NetworkOverlaps((*ranges)[i], (*ranges)[j]) == true {
					//fmt.Printf("Overlaps: %s\n", (*ranges)[j].IP)
					*ranges, (*ranges)[len(*ranges)-1] = append((*ranges)[:j], (*ranges)[j+1:]...), nil
				}
			}
		}
	}
}

func main() {
	flag.Var(&asns, "as", "List of AS numbers (comma seperated)")
	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Printf("    %s -as 1234[,5678,...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
	} else {
		// For each ASN specified on cmdline, perform whois to RADB
		for i := 0; i < len(asns); i++ {
			result, err := whois(fmt.Sprintf("-i origin AS%d", asns[i]), "whois.radb.net")
			if err != nil {
				log.Fatal(err)
			}

			// Parse routes (IP ranges) from whois output & sort by subnet size
			err = parseRanges(result)
			if err != nil {
				log.Fatal(err)
			}
		}

		// Eliminate overlapping subnets
		aggregateRanges(&ipv4Ranges)
		aggregateRanges(&ipv6Ranges)

		// Output the result
		for ip := range ipv4Ranges {
			fmt.Println(ipv4Ranges[ip])
		}
		for ip := range ipv6Ranges {
			fmt.Println(ipv6Ranges[ip])
		}
	}
}
