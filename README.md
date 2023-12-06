# Recon88r Script

This script is designed for performing reconnaissance tasks on a target domain. It includes various modules for subdomain enumeration, port scanning, template-based scanning, XSS, JS Files Analysis, Seaching for exposed panels.

## Prerequisites

Before using the script, make sure you have the following tools and dependencies installed:

- Python 3.x
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [PureDNS](https://github.com/d3mondev/puredns)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [HTTPX](https://github.com/projectdiscovery/httpx)
- [Gau](https://github.com/lc/gau)
- [kxss](https://github.com/tomnomnom/hacks/tree/main/kxss)
- [Notify](https://github.com/projectdiscovery/notify) 
- [Wordlists](https://github.com/h0tak88r/Wordlists)
- [nuclei_templates](https://github.com/h0tak88r/nuclei_templates)

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/h0tak88r/Recon88r.git
   ```

2. Navigate to the script directory:

   ```bash
   cd Recon88r
   ```

3. Set up a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use 'venv\Scripts\activate'
   ```

4. Install the required Prerequisites :

   ```bash
   bash install.sh
   ```

5. Modify the `absolute_path` variable in the script to point to your desired working directory:

   ```python
   absolute_path = os.path.abspath(os.path.expanduser("/path/to/your/working/directory"))
   ```

## Usage

Run the script with the desired options to perform reconnaissance tasks. Below are some examples:

```bash
python recon88r.py -d example.com -se -p -nt -nf -ep -js -xss -wh your_discord_webhook_url
```

### Available Options:

- `-d, --domain`: Target domain for reconnaissance (required).
- `-se, --subenum`: Perform subdomain enumeration.
- `-p, --portscan`: Perform port scanning.
- `-nt, --new-templates`: Scan with newly added templates to the nuclei templates repo.
- `-nf, --nuclei-full`: Perform a full nuclei scan.
- `-ep, --exposed-panels`: Perform Panels dorking with nuclei templates.
- `-js, --js-exposures`: Perform JS Exposures.
- `-sl, --subs-file`: Path to the subdomains file.
- `-xss, --xss-scan`: Perform XSS scans.
- `-wh, --webhook`: Webhook URL for Discord.

## Contributing

If you encounter any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.
