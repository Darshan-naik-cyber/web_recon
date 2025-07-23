#!/usr/bin/env python3

import subprocess
import sys
import os
import time
import json
from pathlib import Path
import argparse
from urllib.parse import urlparse


class WebSecurityRecon:
    def __init__(self, domain, output_dir="web_recon", threads=10):
        self.domain = domain
        self.threads = threads
        self.output_dir = Path(output_dir)

        # Output files
        self.subdomain_file = self.output_dir / "subdomains.txt"
        self.alive_file = self.output_dir / "alive.txt"
        self.wayback_file = self.output_dir / "waybackurls.txt"
        self.nuclei_file = self.output_dir / "nuclei_results.json"
        self.katana_file = self.output_dir / "katana_crawl.txt"
        self.js_files = self.output_dir / "js_files.txt"
        self.gau_file = self.output_dir / "gau_urls.txt"
        self.subdomain_takeover_file = self.output_dir / "subdomain_takeover.txt"
        self.ffuf_file = self.output_dir / "ffuf_results.json"

        # Create directories
        self.output_dir.mkdir(exist_ok=True)

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           Web Security Recon Tool                           ║
║                      Comprehensive Bug Hunting Suite                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def check_tool_installed(self, tool_name):
        try:
            subprocess.run([tool_name, "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def check_dependencies(self):
        tools = {
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "subjack": "go install github.com/haccer/subjack@latest"
        }

        print("[+] Checking dependencies...")
        missing = []
        for tool, install in tools.items():
            if not self.check_tool_installed(tool):
                print(f"    ✗ {tool} is missing")
                missing.append((tool, install))
            else:
                print(f"    ✓ {tool} is installed")

        if missing:
            print("\n[!] Missing tools:")
            for tool, cmd in missing:
                print(f"{tool}: {cmd}")
            return False
        return True

    def run_subfinder(self):
        print(f"\n[1/9] Running subfinder on {self.domain}")
        cmd = ["subfinder", "-d", self.domain, "-o", str(self.subdomain_file), "-all", "-silent"]
        try:
            subprocess.run(cmd, check=True)
            print("    ✓ Subdomain enumeration complete")
            return True
        except Exception as e:
            print(f"    ✗ subfinder failed: {e}")
            return False

    def run_httpx(self):
        print(f"\n[2/9] Running httpx")
        if not self.subdomain_file.exists():
            print("    ✗ subdomains.txt not found")
            return False

        cmd = [
            "httpx", "-l", str(self.subdomain_file),
            "-o", str(self.alive_file),
            "-title", "-tech-detect", "-status-code", "-content-length",
            "-silent", "-threads", str(self.threads)
        ]
        try:
            subprocess.run(cmd, check=True)
            print("    ✓ Alive domains identified")
            return True
        except Exception as e:
            print(f"    ✗ httpx failed: {e}")
            return False

    def run_waybackurls(self):
        print(f"\n[3/9] Running waybackurls")
        try:
            cmd = ["waybackurls", self.domain]
            with open(self.wayback_file, 'w') as f:
                subprocess.run(cmd, stdout=f, check=True)
            print("    ✓ Wayback URLs collected")
            return True
        except Exception as e:
            print(f"    ✗ waybackurls failed: {e}")
            return False

    def run_gau(self):
        print(f"\n[4/9] Running gau")
        try:
            cmd = ["gau", "--threads", str(self.threads), "--o", str(self.gau_file), self.domain]
            subprocess.run(cmd, check=True)
            print("    ✓ gau URLs collected")
            return True
        except Exception as e:
            print(f"    ✗ gau failed: {e}")
            return False

    def run_katana_crawl(self):
        print(f"\n[5/9] Running katana")
        if not self.alive_file.exists():
            print("    ✗ alive.txt not found")
            return False

        cmd = ["katana", "-list", str(self.alive_file), "-o", str(self.katana_file), "-d", "3", "-c", str(self.threads), "-silent", "-js-crawl"]
        try:
            subprocess.run(cmd, check=True)
            print("    ✓ Katana crawl complete")
            return True
        except Exception as e:
            print(f"    ✗ katana failed: {e}")
            return False

    def extract_js_files(self):
        print(f"\n[6/9] Extracting JS files")
        js_urls = set()

        if self.katana_file.exists():
            with open(self.katana_file, 'r') as f:
                for line in f:
                    if '.js' in line or '/js/' in line:
                        js_urls.add(line.strip())

        if self.wayback_file.exists():
            with open(self.wayback_file, 'r') as f:
                for line in f:
                    if '.js' in line or '/js/' in line:
                        js_urls.add(line.strip())

        if js_urls:
            with open(self.js_files, 'w') as f:
                for url in sorted(js_urls):
                    f.write(url + '\n')
            print(f"    ✓ Found {len(js_urls)} JavaScript files")
            return True
        else:
            print("    ✗ No JS files found")
            return False

    def run_nuclei_scan(self):
        print(f"\n[7/9] Running nuclei scan")
        if not self.alive_file.exists():
            print("    ✗ alive.txt not found")
            return False

        cmd = [
            "nuclei", "-l", str(self.alive_file),
            "-o", str(self.nuclei_file),
            "-json", "-c", str(self.threads),
            "-severity", "critical,high,medium", "-silent"
        ]
        try:
            subprocess.run(cmd, check=True)
            print("    ✓ Nuclei scan complete")
            return True
        except Exception as e:
            print(f"    ✗ nuclei failed: {e}")
            return False

    def run_subdomain_takeover(self):
        print(f"\n[8/9] Checking for subdomain takeover")
        if not self.subdomain_file.exists():
            print("    ✗ subdomains.txt not found")
            return False

        cmd = ["subjack", "-w", str(self.subdomain_file), "-o", str(self.subdomain_takeover_file), "-ssl", "-c", str(self.threads)]
        try:
            subprocess.run(cmd, check=True)
            print("    ✓ Subdomain takeover check complete")
            return True
        except Exception as e:
            print(f"    ✗ subjack failed: {e}")
            return False

    def run_directory_bruteforce(self):
        print(f"\n[9/9] Running ffuf directory bruteforce")
        if not self.alive_file.exists():
            print("    ✗ alive.txt not found")
            return False

        common_dirs = [
            "admin", "api", "login", "uploads", "img", "js", "css",
            "config", ".git", ".env", "dashboard", "assets"
        ]
        wordlist = self.output_dir / "common_dirs.txt"
        with open(wordlist, 'w') as f:
            for d in common_dirs:
                f.write(d + "\n")

        try:
            with open(self.alive_file, 'r') as f:
                first_url = f.readline().strip()
            if not first_url:
                print("    ✗ No URL in alive.txt")
                return False

            parsed = urlparse(first_url.split()[0])
            base_url = f"{parsed.scheme}://{parsed.netloc}/FUZZ"

            cmd = [
                "ffuf", "-u", base_url,
                "-w", str(wordlist),
                "-o", str(self.ffuf_file),
                "-of", "json",
                "-t", str(self.threads),
                "-mc", "200,204,301,302,307,403",
                "-fs", "0"
            ]
            subprocess.run(cmd, check=True)

            if self.ffuf_file.exists():
                with open(self.ffuf_file, 'r') as f:
                    results = json.load(f)
                    found = len(results.get("results", []))
                    print(f"    ✓ Found {found} valid paths")
                return True
            else:
                print("    ✗ ffuf output not found")
                return False
        except Exception as e:
            print(f"    ✗ ffuf failed: {e}")
            return False

    def start(self):
        self.print_banner()
        if not self.check_dependencies():
            return

        steps = [
            self.run_subfinder,
            self.run_httpx,
            self.run_waybackurls,
            self.run_gau,
            self.run_katana_crawl,
            self.extract_js_files,
            self.run_nuclei_scan,
            self.run_subdomain_takeover,
            self.run_directory_bruteforce
        ]

        for func in steps:
            success = func()
            if not success:
                print(f"[!] Step '{func.__name__}' failed or was skipped.")

        print("\n[✓] Web Security Recon Complete!")
        print(f"[+] All results saved in: {self.output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Security Recon Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default="web_recon", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
    args = parser.parse_args()

    recon = WebSecurityRecon(args.domain, args.output, args.threads)
    recon.start()

