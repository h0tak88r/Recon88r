import subprocess
import requests
from requests import post
import os
import re
import glob
import argparse
import tempfile
import requests
import concurrent.futures

# The working directory, edit the below line for yours
absolute_path = os.path.abspath(os.path.expanduser("/workspaces/recon_vps"))

# function to handle running commands and working with pipelines.
def run_command(command, input_data=None):
    return subprocess.run(command, input=input_data, stdout=subprocess.PIPE, text=True, check=True)

def validate_domain(domain):
    """
    Validates the domain name using a regular expression.
    """
    pattern = re.compile(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([a-zA-Z]{2,})$')
    if not pattern.match(domain):
        raise ValueError('Invalid domain name')
    return domain

def xss_scan(domain):
    """
    Scans a domain for XSS vulnerabilities.
    """
    gau = run_command(["gau", domain])
    xss_scan  = run_command(["kxss"], input_data= gau.stdout)
    xss_scan_output = run_command(["notify", "-bulk"], input_data= xss_scan.stdout)

def fetch_subdomains(url, domain):
    """
    Fetches subdomains from a given URL and returns them as a set.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        pattern = re.compile(rf'((?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.{domain})')
        return set(pattern.findall(response.text))
    except requests.exceptions.RequestException:
        return set()

def fetch_all_subdomains(domain):
    """
    Fetches subdomains from all URLs concurrently and returns them as a set.
    """
    urls = [
        f'https://rapiddns.io/subdomain/{domain}?full=1#result',
        f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey',
        f'https://crt.sh/?q=%.{domain}',
        f'https://crt.sh/?q=%.%.{domain}',
        f'https://crt.sh/?q=%.%.%.{domain}',
        f'https://crt.sh/?q=%.%.%.%.{domain}',
        f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
        f'https://api.hackertarget.com/hostsearch/?q={domain}',
        f'https://urlscan.io/api/v1/search/?q={domain}',
        f'https://jldc.me/anubis/subdomains/{domain}',
    ]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(fetch_subdomains, url, domain) for url in urls]
        subdomains = set()
        for future in concurrent.futures.as_completed(futures):
            subdomains |= future.result()

    return subdomains

# Arguments Functions --------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description='Reconnaissance script with various modules.')

    # Specify the available command-line options
    parser.add_argument('-d', '--domain', type=validate_domain, required=True, help='Target domain for reconnaissance')
    parser.add_argument('-se', '--subenum', action='store_true', help='Perform subdomain enumeration')
    parser.add_argument('-p', '--portscan', action='store_true', help='Perform port scanning')
    parser.add_argument('-nt', '--new-templates', action='store_true', help='Scan with newly added templates to the nuclei templates repo')
    parser.add_argument('-nf', '--nuclei-full', action='store_true', help='Perform a full nuclei scan')
    parser.add_argument('-ep', '--exposed-panels', action='store_true', help='Perform Panels dorking with nuclei templates')
    parser.add_argument('-js', '--js-exposures', action='store_true', help='Perform JS Exposures')
    parser.add_argument('-sl', '--subs-file', help='Path to the subdomains file')
    parser.add_argument('-xss', '--xss-scan', action='store_true', help='Perform xss scans')
    parser.add_argument('-wh', '--webhook', help='Webhook URL for Discord')

    try:
        return parser.parse_args()
    except argparse.ArgumentError as e:
        print(f"Error: {e}")
        parser.print_help()
        exit(1)

def recon(target_domain, perform_subenum=False, perform_portscan=False, perform_nuclei_new=False, perform_nuclei_full=False, perform_exposed_panels=False, perform_js_exposure=False, subs_file=None, perform_xss_scan=False, webhook=None):

    if perform_subenum:
        print("[+] Performing subdomain enumeration")
        print("[+] Passive Subdomain Enumeration ....")
        run_command(["rm", "-r", f"{absolute_path}/subs/"])
        run_command(["mkdir", f"{absolute_path}/subs/"])

        # Fetch subdomains from all sources
        subdomains = fetch_all_subdomains(target_domain)
        
        # Write subdomains to a file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            tmp_file.writelines(f'{subdomain}\n' for subdomain in sorted(subdomains))
            tmp_file.flush()

        # Move temporary file to final output file
        output_file = f'{absolute_path}/subs/{args.domain}.txt'
        try:
            with open(output_file, 'x') as file:
                pass
        except FileExistsError:
            pass
        with open(output_file, 'w') as file:
            with open(tmp_file.name, 'r') as tmp_file:
                file.writelines(tmp_file.readlines())

        print(f'Passive Subdomains saved to {output_file}')

        print(f"[+] Running subfinder on {target_domain}")
        run_command(["subfinder", "-d", target_domain, "--all", "--silent", "-config", f"{absolute_path}/subfinder-config.yaml", "-o", f"{absolute_path}/subs/subfinder.txt"])

        # Active Subdomain Enumeration
        print("[+] Active subdomain enumeration")
        print("[+] DNS Brute forcing using puredns")
        try:
            run_command(["puredns", "bruteforce", f"{absolute_path}/Wordlists/dns/dns_2m.txt", target_domain, "-r", f"{absolute_path}/Wordlists/dns/valid_resolvers.txt", "-w", f"{absolute_path}/subs/dns_bf.txt", "--skip-wildcard-filter", "--skip-validation"])
        except Exception as e:
            print(f"Error while running puredns. Details: {e}")
        return None

        print("[+] tls proping")
        try:
            cero_cmd = ["cero", target_domain]
            cero_output = run_command(cero_cmd)
            sed_cmd = ["sed", 's/^*.//']
            sed_output = run_command(sed_cmd, input_data=cero_output.stdout)
            grep_cmd = ["grep", "\\."]
            grep_output = run_command(grep_cmd, input_data=sed_output.stdout)
            sort_cmd = ["sort", "-u"]
            sort_output = run_command(sort_cmd, input_data=grep_output.stdout)
            grep_domain_cmd = ["grep", f".{target_domain}$"]
            grep_domain_output = run_command(grep_domain_cmd, input_data=sort_output.stdout)

            # Redirect output to a file
            with open(f"{absolute_path}/subs/tls_probing.txt", "w") as tls_probing_file:
                tls_probing_file.write(grep_domain_output.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error while performing tls proping . Output: {e.output}")
        return None

        # Filtering out the results
        print("[+] Filtering out the results")   
        subs_files = glob.glob(f"{absolute_path}/subs/*")
        cat_command = ["cat"] + subs_files
        sort_command = ["sort", "-u"]
        output_file = f"{absolute_path}/subs/all_subs_filtered.txt"

        cat_process = subprocess.run(cat_command, stdout=subprocess.PIPE, text=True, check=True)
        sort_process = subprocess.run(sort_command, input=cat_process.stdout, stdout=subprocess.PIPE, text=True, check=True)

        with open(output_file, "w") as file:
            file.write(sort_process.stdout)
        
        print("[+] Running puredns for resolving the subs and output in all_subs_resolved.txt ")
        
        try:
            run_command(["puredns", "resolve", f"{absolute_path}/subs/all_subs_filtered.txt", "-r", f"{absolute_path}/Wordlists/dns/valid_resolvers.txt", "-w", f"{absolute_path}/subs/all_subs_resolved.txt", "--skip-wildcard-filter", "--skip-validation"])
        except Exception as e:
            print(f"Error while running puredns. Details: {e}")
        return None

        print("[+] Running httpx for filtering the subs and output in filtered_hosts.txt ")
        run_command(["httpx", "-l", f"{absolute_path}/subs/all_subs_filtered.txt", "-random-agent", "-retries", "2", "-o", f"{absolute_path}/subs/filtered_hosts.txt"])
        
        if webhook:
            print("[+] Sending the output file all_subs_filtered.txt to Discord")
            with open(f"{absolute_path}/subs/all_subs_filtered.txt", "rb") as file:
                post(webhook, files={'file': file})
    
    elif subs_file:
        # Use the provided subdomains file for other operations
        print(f"[+] Using provided subdomains file: {subs_file}")
        run_command(["rm", "-r", f"{absolute_path}/subs/"])
        run_command(["mkdir", f"{absolute_path}/subs/"])
        cat_command = ["cat", subs_file]
        sort_command = ["sort", "-u"]
        output_file = f"{absolute_path}/subs/all_subs_filtered.txt"

        cat_process = subprocess.run(cat_command, stdout=subprocess.PIPE, text=True, check=True)
        sort_process = subprocess.run(sort_command, input=cat_process.stdout, stdout=subprocess.PIPE, text=True, check=True)

        with open(output_file, "w") as file:
            file.write(sort_process.stdout)

        print("[+] Running httpx for filtering the subs and output in filtered_hosts.txt ")
        run_command(["httpx", "-l", f"{absolute_path}/subs/all_subs_filtered.txt", "-random-agent", "-retries", "2", "-o", f"{absolute_path}/subs/filtered_hosts.txt"])

    if perform_portscan:
        print("[+] Performing port scanning")
        naabu_command = run_command(["naabu", "-list", f"{absolute_path}/subs/all_subs_filtered.txt", "-top-ports", "1000"])
        naabu_output = run_command(["notify", "-bulk"], input_data=naabu_command.stdout)

    if perform_nuclei_new:
        print("[+] Scan with newly added templates to the nuclei templates repo ")
        ntscan = run_command(["nuclei", "-l",  f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei-templates/", "-nt", "-es", "info"])
        ntscan_output = run_command(["notify", "-bulk"], input_data=ntscan.stdout)

    if perform_nuclei_full:
        print("[+] Scan with the full nuclei template")
        pt_scan = run_command(["nuclei", "-l", f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei_templates/Others", "-es", "info"])
        pt_output = run_command(["notify", "-bulk"], input_data=pt_scan.stdout)
        
    if perform_js_exposure:
        print("[+] Scanning js files")
        resolved_domains_output = run_command(["cat", f"{absolute_path}/subs/all_subs_resolved.txt"])
        all_urls = run_command(["gau"], input_data=resolved_domains_output.stdout)
        js_files_filter = run_command(["grep", "\\.js$"], input_data=all_urls.stdout)
        js_files_output = run_command(["sort", "-u"], input_data=js_files_filter.stdout)
        js_scan = run_command(["nuclei", "-t", f"{absolute_path}/nuclei_templates/js/information-disclosure-in-js-files.yaml"], input_data=js_files_output.stdout)
        js_scan_output = run_command(["notify", "-bulk"], input_data=js_scan.stdout)

    if perform_exposed_panels:
        print("[+] Scanning for exposed panels")
        panels = run_command(["nuclei", "-l", f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei_templates/Panels"])
        panels_output = run_command(["notify", "-bulk"], input_data=panels.stdout)

    if perform_xss_scan:
        print("[+] Scanning for xss")
        xss_scan(target_domain)


if __name__ == "__main__":
    args = parse_args()

    # Call the recon function with the provided arguments
    recon(args.domain, args.subenum, args.portscan, args.new_templates, args.nuclei_full, args.exposed_panels, args.js_exposures, args.subs_file, args.xss_scan, args.webhook)
