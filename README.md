# Email Domain Verifier

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/domain-email-verificator)](https://goreportcard.com/report/github.com/yourusername/domain-email-verificator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📧 Verify Email Domains with Ease!

Ever wondered if a domain is properly set up for email communication? Look no further! The Domain Email Verifier is here to demystify the world of MX, SPF, DMARC, and more.

### 🚀 Features

- Check for MX (Mail Exchanger) records
- Verify SPF (Sender Policy Framework) configuration
- Investigate DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies
- Lookup DKIM (DomainKeys Identified Mail) records
- Retrieve A, AAAA, NS, and TXT records
- User-friendly command-line interface
- Lightning-fast Go implementation

### 🛠 Installation

```bash
go get github.com/pawan971/emailverif-go
```
## 🏃‍♂️ Usage

### Run the program:
```bash
go run main.go
```
### Enter a domain when prompted:

```
Enter a Domain: 
example.com
```

### 🔍 What It Checks

MX Records: Ensure the domain can receive emails
SPF Records: Verify authorized email senders
DMARC Records: Check email authentication policies
DKIM Records: Check DKIM selectors and records
A Records: IPv4 addresses associated with the domain
AAAA Records: IPv6 addresses associated with the domain
NS Records: Nameserver records for the domain
TXT Records: All TXT records, including SPF and DMARC

### 🖥 Sample Output
```
----------------------LOOKUP Results for example.com:-----------------------
MX Records:
  - mx1.example.com (Priority: 10)
  - mx2.example.com (Priority: 20)

SPF Record:
RAW: v=spf1 include:_spf.example.com ~all
  - Allowed IPv4: _spf.example.com
  - Soft fail for all other

DMARC Record:
RAW: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  - Policy: reject
  - Aggregate reports: mailto:dmarc@example.com

DKIM Records:
Selector: default
RAW: v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA...
  - Version: DKIM1
  - Key type: rsa
  - Public key: MIGfMA0GCSqGSIb3DQEBA...

Nameservers:
  - ns1.example.com
  - ns2.example.com

A Records:
  - 192.0.2.1

AAAA Records:
  - 2001:db8::1

Do you want to see additional TXT records? (Y/N): Y

Additional TXT Records:
  - google-site-verification=abcdefg12345

----------------------END---------------------------------

```

### 🤓 Why Use This Tool?

- Email Deliverability: Ensure your domains are correctly configured
- Security: Verify SPF and DMARC settings to prevent email spoofing
- Troubleshooting: Quickly diagnose email-related issues

### 🎯 Future Enhancements

- Batch processing of multiple domains
- Export results to CSV or JSON
- Web interface for non-technical users
- Various services associated
- Reverse DNS Lookup for MX Servers
- BIMI Records
- TLS-RPT Record

### 🤝 Contributing
Pull requests are welcome!

### 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

Remember to check your email configurations regularly! 📬
