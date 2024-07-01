package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Enter a Domain: \n")

	for scanner.Scan() {
		checkDomain(scanner.Text())
	}

	fmt.Printf("Looking up the following: Domain,Has_MX,Has_SPF,SPF_Record,Has_DMARC,DMARC_Record ... ... ...\n")

	if error := scanner.Err(); error != nil {
		log.Fatal("Error: could not read from input : %v\n", error)

	}
}

func checkDomain(Domain string) {

	var Has_MX, Has_SPF, Has_DMARC bool
	var SPF_Record, DMARC_Record string

	MX_Records, error := net.LookupMX(Domain)

	if error != nil {
		log.Printf("Error: %v\n", error)
	}

	if len(MX_Records) > 0 {
		Has_MX = true
	}

	TXT_Record, error := net.LookupTXT(Domain)

	if error != nil {
		log.Printf("Error: %v\n", error)
	}

	for _, record := range TXT_Record {
		if strings.HasPrefix(record, "v=spf1") {
			Has_SPF = true
			SPF_Record = record
			break
		}
	}

	dmarcrecords, error := net.LookupTXT("_dmarc." + Domain)

	if error != nil {
		log.Printf("Error: %v\n", error)
	}

	for _, record := range dmarcrecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			Has_DMARC = true
			DMARC_Record = record
			break
		}
	}
	fmt.Print("\n----------------------LOOK Results:-----------------------\n")
	fmt.Printf("Domain:%v\n\nHas_MX:%v\nHas_SPF:%v\nSPF_Record:%v\nHas_DMARC:%v\nDMARC_Record:%v\n", Domain, Has_MX, Has_SPF, SPF_Record, Has_DMARC, DMARC_Record)
	fmt.Print("----------------------END---------------------------------\n\n")
	os.Exit(0)
}
