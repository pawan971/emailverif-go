# Domain Email Verifier

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/domain-email-verificator)](https://goreportcard.com/report/github.com/yourusername/domain-email-verificator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📧 Verify Email Domains with Ease!

Ever wondered if a domain is properly set up for email communication? Look no further! The Domain Email Verifier is here to demystify the world of MX, SPF, and DMARC records.

### 🚀 Features

- Check for MX (Mail Exchanger) records
- Verify SPF (Sender Policy Framework) configuration
- Investigate DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies
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

### 🖥 Sample Output
```
----------------------LOOKUP Results:-----------------------
Domain: example.com

Has_MX: true
Has_SPF: true
SPF_Record: v=spf1 include:_spf.example.com ~all
Has_DMARC: true
DMARC_Record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
----------------------END---------------------------------
```

### 🤓 Why Use This Tool?

- Email Deliverability: Ensure your domains are correctly configured
- Security: Verify SPF and DMARC settings to prevent email spoofing
- Troubleshooting: Quickly diagnose email-related issues

### 🎯 Future Enhancements

- Batch processing of multiple domains
- Detailed explanations of each record type
- Export results to CSV or JSON
- Web interface for non-technical users

### 🤝 Contributing
Pull requests are welcome!

### 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

### 
Built with reference to the instructions and guidance by - [Akhil Sharma](https://www.linkedin.com/in/akhilsails/)

Remember to check your email configurations regularly! 📬
