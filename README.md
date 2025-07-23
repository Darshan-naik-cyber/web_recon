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


How to run the script 

$ python3 web_recon.py -d <sitename> 


