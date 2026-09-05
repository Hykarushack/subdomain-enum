# 🔍 Subdomain-Enum

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Stars](https://img.shields.io/github/stars/bug404found/subdomain-enum.svg?style=social)](https://github.com/bug404found/subdomain-enum)

**Fast subdomain enumeration and takeover detector for security professionals, bug bounty hunters, and penetration testers.**

## 🚀 The Problem We Solve

Subdomain enumeration is a critical first step in any security assessment, but traditional tools are often slow, noisy, and fail to detect takeover opportunities. **Subdomain-Enum** combines blazing-fast enumeration with intelligent takeover detection, helping you identify vulnerable subdomains that could compromise your target's security posture — all in a single, lightweight command.

## 📦 Installation

### Using pip
```bash
pip install subdomain-enum
```

### From source
```bash
git clone https://github.com/bug404found/subdomain-enum.git
cd subdomain-enum
pip install -r requirements.txt
```

## 💻 Usage

### Basic enumeration
```bash
subdomain-enum -d example.com
```

### Advanced usage with takeover detection
```bash
subdomain-enum -d example.com --takeover --threads 50 -o results.json
```

### Python API
```python
from subdomain_enum import SubdomainEnum

enumerator = SubdomainEnum("example.com")
subdomains = enumerator.run()
print(f"Found {len(subdomains)} subdomains")
```

## ✨ Features

- **⚡ High-speed enumeration** using concurrent DNS resolution with configurable thread pools
- **🕵️ Takeover detection** for 15+ cloud services (AWS, Azure, GitHub Pages, Heroku, etc.)
- **🔍 Multiple resolution sources** including certificate transparency logs and brute-force wordlists
- **📊 Clean output formats** supporting JSON, CSV, and plain text exports
- **🎯 Smart filtering** to eliminate false positives and wildcard subdomains
- **🔄 Recursive enumeration** for deep discovery of nested subdomains
- **📈 Real-time progress** with verbose and quiet modes for CI/CD integration
- **🛡️ Rate limiting** to avoid detection and respect target infrastructure

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate tests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## About

This project is maintained by [bug404found.com](https://bug404found.com/?utm_source=github&utm_medium=readme&utm_campaign=opensource&utm_content=subdomain-enum), a cybersecurity recruitment platform that connects talented security professionals with top companies through hands-on, practical labs. Whether you're looking to sharpen your offensive security skills or discover your next career opportunity in cybersecurity, bug404found offers real-world challenges that prepare you for the demands of modern security roles. Visit us to explore our platform and join a community of passionate security enthusiasts.