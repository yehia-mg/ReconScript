# Subdomain Recon Tool

A Python script that enumerates subdomains for a target domain, filters them by
DNS resolution and HTTP status (200 / 302 / other), then discovers API
endpoints via crawling and web archive lookups — saving everything neatly
organized into separate output files.

> ⚠️ **Only use this tool against domains you are authorized to test**
> (your own infrastructure, or a domain in scope of an authorized bug bounty
> program). Any other use is entirely your own responsibility.

## Pipeline

```
subfinder + assetfinder + amass  →  merge + deduplicate
            │
            ▼
          dnsx   (filter out non-resolving domains)
            │
            ▼
          httpx  (classify: 200 / 302 / other)
            │
            ▼
   katana + waybackurls  (endpoint discovery)
            │
            ▼
     API endpoint filtering (regex)
            │
            ▼
   saved to collected_subdomains/scan_N*.txt
```

## Output

Each run (scan) gets an auto-incrementing number inside the
`collected_subdomains/` folder:

| File | Content |
|---|---|
| `scan_N.txt` | All collected & resolved subdomains |
| `scan_N_200.txt` | Domains returning HTTP 200 |
| `scan_N_302.txt` | Domains returning HTTP 302 |
| `scan_N_other.txt` | Everything else (other status codes) |
| `scan_N_api.txt` | Discovered API-looking endpoints/subdomains |

## Requirements

- Python 3.8+
- The following tools must be installed and available on your `PATH`:
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [assetfinder](https://github.com/tomnomnom/assetfinder)
  - [amass](https://github.com/owasp-amass/amass)
  - [dnsx](https://github.com/projectdiscovery/dnsx)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [katana](https://github.com/projectdiscovery/katana)
  - [waybackurls](https://github.com/tomnomnom/waybackurls)

## Installation — Linux (any distro)

### 1) Install core prerequisites (Go, Git, Python)

**Debian / Ubuntu / Kali (and derivatives, `apt`):**
```bash
sudo apt update
sudo apt install golang-go git python3 python3-pip -y
```

**Fedora / RHEL / CentOS (`dnf`):**
```bash
sudo dnf install golang git python3 python3-pip -y
```

**Arch / Manjaro (`pacman`):**
```bash
sudo pacman -S go git python python-pip --noconfirm
```

> If the Go version from your package manager is outdated, you can install
> the latest version manually from [go.dev/dl](https://go.dev/dl/) instead.

### 2) Install the recon tools (same commands on any Linux distro)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

### 3) Add the Go bin directory to PATH

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```
> If you use zsh instead of bash, replace `~/.bashrc` with `~/.zshrc`.

### 4) Verify everything installed correctly
```bash
subfinder -version
assetfinder --help
amass -version
dnsx -version
httpx -version
katana -version
waybackurls -h
```

---

## Installation — Windows

### 1) Install core prerequisites
- Install **Go**: https://go.dev/dl/ (choose the Windows installer)
- Install **Git**: https://git-scm.com/download/win
- Install **Python 3**: https://www.python.org/downloads/windows/ (make sure to check "Add Python to PATH" during setup)

### 2) Install the recon tools
Open PowerShell and run:
```powershell
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

### 3) Add the Go bin directory to PATH
Binaries are placed automatically in `%USERPROFILE%\go\bin`. To add it to PATH:
1. Open Windows Search and type "Environment Variables", then open it
2. Under "User variables", select `Path` and click **Edit**
3. Click **New** and enter: `%USERPROFILE%\go\bin`
4. Click OK on all windows, then open a **new** PowerShell/CMD window (close the old one)

### 4) Verify everything installed correctly
```powershell
subfinder -version
assetfinder --help
amass -version
dnsx -version
httpx -version
katana -version
waybackurls -h
```

**No-Go alternative:** if you don't want to install Go, you can download the
prebuilt `.exe` binaries directly from each tool's GitHub Releases page
(subfinder, httpx, dnsx, katana, amass all provide Windows binaries), place
them in a single folder (e.g. `C:\tools\recon\`), and add that folder to PATH
using the same steps above.

## Usage

```bash
# Single domain
python recon.py -d example.com

# Multiple domains from a file (one per line)
python recon.py -l domains.txt

# Custom output folder
python recon.py -d example.com -o my_results
```

## Notes

- The script is "fail-soft": if a tool isn't installed or times out, it's
  skipped and the pipeline continues with the rest instead of crashing.
- No per-tool timeouts are enforced — tools run until they finish naturally,
  since large scopes (hundreds of subdomains, big Wayback archives) can
  legitimately take a long time. `amass` and `waybackurls` in particular can
  run for a while on large targets; this is expected.
- `dnsx`, `httpx`, and `katana` — the tools that send requests directly to
  the target — are rate-limited by default (see `RATE_LIMITS` inside
  `recon.py`) to stay respectful of the target and within typical bug-bounty
  program limits. Passive-only tools (`subfinder`, `assetfinder`,
  `amass -passive`, `waybackurls`) query third-party sources instead of the
  target directly, so they aren't rate-limited.
- The `collected_subdomains/` folder is listed in `.gitignore` so scan
  results are never accidentally pushed to GitHub.

## License

Free to use for educational purposes and authorized security testing.
