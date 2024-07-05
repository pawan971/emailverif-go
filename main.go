package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

type DomainInfo struct {
	Domain      string
	HasMX       bool
	MXRecords   []*net.MX
	HasSPF      bool
	SPFRecord   string
	HasDMARC    bool
	DMARCRecord string
	DKIMRecords map[string]string
	ARecords    []string
	AAAARecords []string
	NSRecords   []*net.NS
	TXTRecords  []string
}

func main() {
	fmt.Printf("\nEnter a domain to lookup: ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domainInfo := checkDomain(scanner.Text())
		printResults(domainInfo)
		fmt.Printf("\nEnter another domain (or Ctrl+C to exit): ")
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v\n", err)
	}
}

func checkDomain(domain string) DomainInfo {
	info := DomainInfo{
		Domain:      domain,
		DKIMRecords: make(map[string]string),
	}

	mxRecords, _ := net.LookupMX(domain)
	info.HasMX = len(mxRecords) > 0
	info.MXRecords = mxRecords

	txtRecords, _ := net.LookupTXT(domain)
	info.TXTRecords = txtRecords
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			info.HasSPF = true
			info.SPFRecord = record
			break
		}
	}

	info.DMARCRecord = lookupDMARC(domain)
	info.HasDMARC = info.DMARCRecord != ""

	selectors := []string{"default", "google", "mail", "dkim"}
	for _, selector := range selectors {
		dkimRecords, err := net.LookupTXT(fmt.Sprintf("%s._domainkey.%s", selector, domain))
		if err == nil && len(dkimRecords) > 0 {
			info.DKIMRecords[selector] = dkimRecords[0]
		}
	}

	aRecords, _ := net.LookupIP(domain)
	for _, ip := range aRecords {
		if ipv4 := ip.To4(); ipv4 != nil {
			info.ARecords = append(info.ARecords, ipv4.String())
		} else {
			info.AAAARecords = append(info.AAAARecords, ip.String())
		}
	}

	info.NSRecords, _ = net.LookupNS(domain)

	// Reverse DNS Lookup for MX record IPs
	// for _, mx := range info.MXRecords {
	//     ips, _ := net.LookupIP(mx.Host)
	//     for _, ip := range ips {
	//         ptr, _ := reverseDNSLookup(ip.String())
	//         info.MXReverseDNS = append(info.MXReverseDNS, ptr)
	//     }
	// }

	// // Look up BIMI record
	// bimiRecords, _ := net.LookupTXT("default._bimi." + domain)
	// if len(bimiRecords) > 0 {
	//     info.BIMIRecord = bimiRecords[0]
	// }

	// // Look up TLS-RPT record
	// tlsRPTRecords, _ := net.LookupTXT("_smtp._tls." + domain)
	// if len(tlsRPTRecords) > 0 {
	//     info.TLSRPTRecord = tlsRPTRecords[0]
	// }

	return info
}

func lookupDMARC(domain string) string {
	dmarcDomain := "_dmarc." + domain
	for i := 0; i < 10; i++ { // Limit to 10 redirects to prevent infinite loops
		txtRecords, err := net.LookupTXT(dmarcDomain)
		if err != nil {
			return ""
		}

		for _, record := range txtRecords {
			if strings.HasPrefix(record, "v=DMARC1") {
				return record
			}
		}

		cname, err := net.LookupCNAME(dmarcDomain)
		if err != nil || cname == dmarcDomain {
			return ""
		}
		dmarcDomain = strings.TrimSuffix(cname, ".")
	}
	return ""
}

func printResults(info DomainInfo) {
	fmt.Printf("\n----------------------LOOKUP Results for %s:-----------------------\n", info.Domain)

	fmt.Printf("MX Records:\n")
	if info.HasMX {
		for _, mx := range info.MXRecords {
			fmt.Printf("  - %s (Priority: %d)\n", mx.Host, mx.Pref)
		}
	} else {
		fmt.Println("  No MX records found")
	}

	fmt.Printf("\nSPF Record:\n")
	if info.HasSPF {
		fmt.Printf("RAW: %s\n", info.SPFRecord)
		parseSPF(info.SPFRecord)
	} else {
		fmt.Println("  No SPF record found")
	}

	fmt.Printf("\nDMARC Record:\n")
	if info.HasDMARC {
		fmt.Printf("RAW: %s\n", info.DMARCRecord)
		parseDMARC(info.DMARCRecord)
	} else {
		fmt.Println("  No DMARC record found")
	}

	if len(info.DKIMRecords) > 0 {
		fmt.Println("\nDKIM Records:")
		for selector, record := range info.DKIMRecords {
			fmt.Printf("Selector: %s\n", selector)
			fmt.Printf("RAW: %s\n", record)
			parseDKIM(record)
		}
	} else {
		fmt.Println("\nNo DKIM records found")
	}

	fmt.Println("\nNameservers:")
	if len(info.NSRecords) > 0 {
		for _, ns := range info.NSRecords {
			fmt.Printf("  - %s\n", ns.Host)
		}
	} else {
		fmt.Println("  No NS records found")
	}

	fmt.Println("\nA Records:")
	if len(info.ARecords) > 0 {
		for _, record := range info.ARecords {
			fmt.Printf("  - %s\n", record)
		}
	} else {
		fmt.Println("  No A records found")
	}

	fmt.Println("\nAAAA Records:")
	if len(info.AAAARecords) > 0 {
		for _, record := range info.AAAARecords {
			fmt.Printf("  - %s\n", record)
		}
	} else {
		fmt.Println("  No AAAA records found")
	}

	fmt.Print("\nDo you want to see additional TXT records? (Y/N): ")
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response == "y" || response == "yes" {

		fmt.Println("\nAdditional TXT Records:")
		for _, record := range info.TXTRecords {
			if !strings.HasPrefix(record, "v=spf1") && record != info.DMARCRecord {
				fmt.Printf("  - %s\n", record)

			}
		}

		// fmt.Println("\nMX Reverse DNS:")
		// for i, ptr := range info.MXReverseDNS {
		// 	fmt.Printf("  MX %d: %s\n", i+1, ptr)
		// }

		// if info.BIMIRecord != "" {
		// fmt.Printf("\nBIMI Record: %s\n", info.BIMIRecord)
		// }

		// if info.TLSRPTRecord != "" {
		// fmt.Printf("\nTLS-RPT Record: %s\n", info.TLSRPTRecord)
		// }

	}

	fmt.Println("----------------------END---------------------------------")
}

func parseSPF(record string) {
	parts := strings.Fields(record)
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "ip4:"):
			fmt.Printf("  - Allowed IPv4: %s\n", strings.TrimPrefix(part, "ip4:"))
		case strings.HasPrefix(part, "ip6:"):
			fmt.Printf("  - Allowed IPv6: %s\n", strings.TrimPrefix(part, "ip6:"))
		case strings.HasPrefix(part, "include:"):
			fmt.Printf("  - Include domain: %s\n", strings.TrimPrefix(part, "include:"))
		case part == "~all":
			fmt.Println("  - Soft fail for all other")
		case part == "-all":
			fmt.Println("  - Hard fail for all other")
		}
	}
}

func parseDMARC(record string) {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "p="):
			fmt.Printf("  - Policy: %s\n", strings.TrimPrefix(part, "p="))
		case strings.HasPrefix(part, "sp="):
			fmt.Printf("  - Subdomain Policy: %s\n", strings.TrimPrefix(part, "sp="))
		case strings.HasPrefix(part, "pct="):
			fmt.Printf("  - Percent: %s\n", strings.TrimPrefix(part, "pct="))
		case strings.HasPrefix(part, "rua="):
			fmt.Printf("  - Aggregate reports: %s\n", strings.TrimPrefix(part, "rua="))
		case strings.HasPrefix(part, "ruf="):
			fmt.Printf("  - Forensic reports: %s\n", strings.TrimPrefix(part, "ruf="))
		case strings.HasPrefix(part, "fo="):
			fmt.Printf("  - Failure reporting options: %s\n", strings.TrimPrefix(part, "fo="))
		case strings.HasPrefix(part, "adkim="):
			value := strings.TrimPrefix(part, "adkim=")
			if value == "r" {
				fmt.Println("  - DKIM Alignment: Relaxed")
			} else if value == "s" {
				fmt.Println("  - DKIM Alignment: Strict")
			} else {
				fmt.Printf("  - DKIM Alignment: %s\n", value)
			}
		case strings.HasPrefix(part, "aspf="):
			value := strings.TrimPrefix(part, "aspf=")
			if value == "r" {
				fmt.Println("  - SPF Alignment: relaxed")
			} else if value == "s" {
				fmt.Println("  - SPF Alignment: strict")
			} else {
				fmt.Printf("  - SPF Alignment: %s\n", value)
			}
		}
	}
}

func parseDKIM(record string) {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "v="):
			fmt.Printf("  - Version: %s\n", strings.TrimPrefix(part, "v="))
		case strings.HasPrefix(part, "k="):
			fmt.Printf("  - Key type: %s\n", strings.TrimPrefix(part, "k="))
		case strings.HasPrefix(part, "p="):
			fmt.Printf("  - Public key: %s...\n", strings.TrimPrefix(part, "p=")[:20])
		case strings.HasPrefix(part, "a="):
			fmt.Printf("  - Algorithm: %s\n", strings.TrimPrefix(part, "a="))
		}
	}
}
