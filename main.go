package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

type DomainInfo struct {
	Domain      string
	HasMX       bool
	MXRecords   []*net.MX
	HasSPF      bool
	SPFRecord   string
	SPFData     []string
	HasDMARC    bool
	DMARCRecord string
	DMARCData   []string
	DKIMRecords map[string]string
	DKIMData    map[string][]string
	ARecords    []string
	AAAARecords []string
	NSRecords   []*net.NS
	TXTRecords  []string
	AdditionalTXT []string
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handler)
	fmt.Printf("Server listening on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Could not load template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		tmpl.Execute(w, nil)
		return
	}

	info := checkDomain(domain)
	tmpl.Execute(w, info)
}

func checkDomain(domain string) DomainInfo {
	info := DomainInfo{
		Domain:      domain,
		DKIMRecords: make(map[string]string),
		DKIMData:    make(map[string][]string),
	}

	mxRecords, _ := net.LookupMX(domain)
	info.HasMX = len(mxRecords) > 0
	info.MXRecords = mxRecords

	txtRecords, _ := net.LookupTXT(domain)
	info.TXTRecords = txtRecords
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			if !info.HasSPF {
				info.HasSPF = true
				info.SPFRecord = record
				info.SPFData = parseSPF(record)
			}
		} else {
			info.AdditionalTXT = append(info.AdditionalTXT, record)
		}
	}

	info.DMARCRecord = lookupDMARC(domain)
	if info.DMARCRecord != "" {
		info.HasDMARC = true
		info.DMARCData = parseDMARC(info.DMARCRecord)
	}

	selectors := []string{"default", "google", "mail", "dkim"}
	for _, selector := range selectors {
		dkimRecords, err := net.LookupTXT(fmt.Sprintf("%s._domainkey.%s", selector, domain))
		if err == nil && len(dkimRecords) > 0 {
			info.DKIMRecords[selector] = dkimRecords[0]
			info.DKIMData[selector] = parseDKIM(dkimRecords[0])
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


func parseSPF(record string) []string {
	parts := strings.Fields(record)
	var details []string
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "ip4:"):
			details = append(details, fmt.Sprintf("Allowed IPv4: %s", strings.TrimPrefix(part, "ip4:")))
		case strings.HasPrefix(part, "ip6:"):
			details = append(details, fmt.Sprintf("Allowed IPv6: %s", strings.TrimPrefix(part, "ip6:")))
		case strings.HasPrefix(part, "include:"):
			details = append(details, fmt.Sprintf("Include domain: %s", strings.TrimPrefix(part, "include:")))
		case part == "~all":
			details = append(details, "Soft fail for all other")
		case part == "-all":
			details = append(details, "Hard fail for all other")
		}
	}
	return details
}

func parseDMARC(record string) []string {
	parts := strings.Split(record, ";")
	var details []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "p="):
			details = append(details, fmt.Sprintf("Policy: %s", strings.TrimPrefix(part, "p=")))
		case strings.HasPrefix(part, "sp="):
			details = append(details, fmt.Sprintf("Subdomain Policy: %s", strings.TrimPrefix(part, "sp=")))
		case strings.HasPrefix(part, "pct="):
			details = append(details, fmt.Sprintf("Percent: %s", strings.TrimPrefix(part, "pct=")))
		case strings.HasPrefix(part, "rua="):
			details = append(details, fmt.Sprintf("Aggregate reports: %s", strings.TrimPrefix(part, "rua=")))
		case strings.HasPrefix(part, "ruf="):
			details = append(details, fmt.Sprintf("Forensic reports: %s", strings.TrimPrefix(part, "ruf=")))
		case strings.HasPrefix(part, "fo="):
			details = append(details, fmt.Sprintf("Failure reporting options: %s", strings.TrimPrefix(part, "fo=")))
		case strings.HasPrefix(part, "adkim="):
			value := strings.TrimPrefix(part, "adkim=")
			if value == "r" {
				details = append(details, "DKIM Alignment: Relaxed")
			} else if value == "s" {
				details = append(details, "DKIM Alignment: Strict")
			} else {
				details = append(details, fmt.Sprintf("DKIM Alignment: %s", value))
			}
		case strings.HasPrefix(part, "aspf="):
			value := strings.TrimPrefix(part, "aspf=")
			if value == "r" {
				details = append(details, "SPF Alignment: relaxed")
			} else if value == "s" {
				details = append(details, "SPF Alignment: strict")
			} else {
				details = append(details, fmt.Sprintf("SPF Alignment: %s", value))
			}
		}
	}
	return details
}

func parseDKIM(record string) []string {
	parts := strings.Split(record, ";")
	var details []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "v="):
			details = append(details, fmt.Sprintf("Version: %s", strings.TrimPrefix(part, "v=")))
		case strings.HasPrefix(part, "k="):
			details = append(details, fmt.Sprintf("Key type: %s", strings.TrimPrefix(part, "k=")))
		case strings.HasPrefix(part, "p="):
			val := strings.TrimPrefix(part, "p=")
			if len(val) > 20 {
				val = val[:20]
			}
			details = append(details, fmt.Sprintf("Public key: %s...", val))
		case strings.HasPrefix(part, "a="):
			details = append(details, fmt.Sprintf("Algorithm: %s", strings.TrimPrefix(part, "a=")))
		}
	}
	return details
}
