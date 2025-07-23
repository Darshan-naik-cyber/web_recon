# web_recon
# Web Recon - Automated Web Reconnaissance Tool

Web Recon is a lightweight Python tool designed to automate initial web reconnaissance tasks. It helps bug bounty hunters and penetration testers to quickly identify alive web hosts and perform directory brute-forcing using `ffuf`.

---

## 🚀 Features

- ✅ Check if hosts are alive using ICMP (ping)
- 🔍 Automatically run `ffuf` on live hosts to enumerate directories
- 🗂 Save all outputs in organized text and JSON files
- 🧪 Clean and minimal command-line interface

---

## 📁 Folder Structure

web_recon/
├── web_recon.py
├── requirements.txt
└── output/
├── alive.txt
├── ffuf_output.json
└── ...


---

## 📦 Requirements

### ✅ Python Modules
Install via pip:

pip install -r requirements.txt
🛠️ External Tools (Must be pre-installed)
ffuf — Fast web fuzzer.

ping (usually pre-installed on Linux)

Install ffuf on Kali:
sudo apt install ffuf -y
Or via Go:
go install github.com/ffuf/ffuf@latest

---
## 🔧 Usage
python3 web_recon.py -d <domain_name>

---

## 📜 License

This project is licensed under the MIT License. Feel free to use and modify it.

---

## 👨‍💻 Author
Developed by Darshan Naik aka darshanhackz
Security Researcher.

