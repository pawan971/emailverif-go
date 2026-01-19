# Email Domain Verifier Web App

[![Go Report Card](https://goreportcard.com/badge/github.com/pawan971/emailverif-go)](https://goreportcard.com/report/github.com/pawan971/emailverif-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📧 Verify Email Domains with Ease!

Ever wondered if a domain is properly set up for email communication? Look no further! The Domain Email Verifier is a web application that demystifies the world of MX, SPF, DMARC, and more.

### 🚀 Features

- Check for MX (Mail Exchanger) records
- Verify SPF (Sender Policy Framework) configuration
- Investigate DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies
- Lookup DKIM (DomainKeys Identified Mail) records
- Retrieve A, AAAA, NS, and TXT records
- Simple and clean Web Interface
- Lightning-fast Go implementation

### 🛠 Installation & Running Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pawan971/emailverif-go.git
   cd emailverif-go
   ```

2. **Run the web server:**
   ```bash
   go run main.go
   ```

3. **Access the app:**
   Open your browser and navigate to `http://localhost:8080`.

### 🐳 Running with Docker

You can easily containerize and run the application using Docker.

1. **Build the Docker image:**
   ```bash
   docker build -t emailverif .
   ```

2. **Run the container:**
   ```bash
   docker run -p 8080:8080 emailverif
   ```

3. **Access the app:**
   Visit `http://localhost:8080` in your browser.

### 🌐 Hosting on the Internet

To host this application on the internet, you can use any cloud provider that supports Docker or Go applications.

#### Deploying to Fly.io (Example)
1. Install `flyctl`.
2. Run `fly launch` in the project directory.
3. Follow the prompts to deploy.

#### Deploying to Render
1. Connect your GitHub repository to Render.
2. Choose "Web Service".
3. Select "Docker" as the runtime.
4. Render will automatically build using the `Dockerfile`.

### 🔍 What It Checks

MX Records: Ensure the domain can receive emails
SPF Records: Verify authorized email senders
DMARC Records: Check email authentication policies
DKIM Records: Check DKIM selectors and records
A Records: IPv4 addresses associated with the domain
AAAA Records: IPv6 addresses associated with the domain
NS Records: Nameserver records for the domain
TXT Records: All TXT records, including SPF and DMARC

### 🤓 Why Use This Tool?

- Email Deliverability: Ensure your domains are correctly configured
- Security: Verify SPF and DMARC settings to prevent email spoofing
- Troubleshooting: Quickly diagnose email-related issues

### 🤝 Contributing
Pull requests are welcome!

### 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

Remember to check your email configurations regularly! 📬
