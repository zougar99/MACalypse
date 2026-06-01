# 📡 MACalypse — MACalypse — Network Identity Toolkit with 42 tools for Windows

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zougar99/MACalypse/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/zougar99/MACalypse?style=social)](https://github.com/zougar99/MACalypse)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)](https://github.com/zougar99/MACalypse)

> MACalypse — Network Identity Toolkit with 42 tools for Windows. MAC address spoofing, network scanning, DNS manipulation, and more.

---

## 📖 Table of Contents
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [Screenshots](#-screenshots)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features
- ✔ **42 Network Tools** — MAC spoofing, ARP scanning, DNS lookup, port scanning, packet analysis, and more
- ✔ **MAC Address Spoofing** — Change your MAC address with one click
- ✔ **Network Scanner** — Discover devices on your LAN with OS detection
- ✔ **DNS Tools** — Flush DNS, lookup, reverse DNS, DNSSEC check
- ✔ **WiFi Analyzer** — Scan nearby networks, signal strength, channels
- ✔ **Packet Capture** — Basic packet sniffing and analysis
- ✔ **Export Reports** — Save network scan results as HTML or CSV

---

## 🔮 How It Works

```
  Input ──► Processing Pipeline ──► Output
  ┌────────┐   ┌────────┐   ┌────────┐
  │ Data   │──►│ Engine │──►│ Result │
  │ Source │   │ Logic  │   │        │
  └────────┘   └────────┘   └────────┘
```

1. **Input** — Load data from file, API, or user input
2. **Process** — Core engine applies logic/analysis/transformation
3. **Output** — Results displayed in UI, saved to file, or sent via API

---

## 💻 Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ / C# |
| UI | CustomTkinter / WPF |
| Network | scapy + socket + winreg |
| Platform | Windows (Admin required for some tools) |

---

## 🚀 Installation

```bash
git clone https://github.com/zougar99/MACalypse.git
cd MACalypse
pip install -r requirements.txt
# Run as Administrator for MAC spoofing
```

---

## 📄 Configuration

Create a `config.yaml` or `.env` file in the project root:

```yaml
# Application settings
debug: false
port: 8080
theme: dark
language: en
```

---

## 🧰 Usage Guide

1. Run as Administrator: `python main.py`
2. Select a tool category (MAC / Scan / DNS / WiFi)
3. Configure parameters
4. Execute and view results
5. Export if needed

---

## 🖼 Screenshots

> *(Screenshots coming soon. PRs welcome!)*

---

## 🔄 Roadmap

- 🟢 Web dashboard
- 🟡 Mobile companion app
- ⚫ API access
- ⚫ Plugin system
- ⚫ Multi-language support

---

## ❓ FAQ

### Do I need Administrator rights?
For MAC spoofing and packet capture — yes.

### Is MAC spoofing reversible?
Yes — reboot or click **Restore Original** to revert.

---

## 🚧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **App won't start** | Check Python version (3.10+); run `pip install -r requirements.txt` |
| **No output** | Check logs in `logs/` folder; enable debug mode in config |
| **Performance issues** | Close other applications; reduce batch size in config |
| **Dependency errors** | Create fresh venv: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📐 License
Distributed under the **MIT License**. See [`LICENSE`](https://github.com/zougar99/MACalypse/blob/main/LICENSE) for more information.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/zougar99">zougar99</a>
</p>
