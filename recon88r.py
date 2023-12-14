import subprocess
import requests
import os
import re
import glob
import argparse
import tempfile
import concurrent.futures
import shlex

banner ="""

  _____                       ___   ___       
 |  __ \                     / _ \ / _ \      
 | |__) |___  ___ ___  _ __ | (_) | (_) |_ __ 
 |  _  // _ \/ __/ _ \| '_ \ > _ < > _ <| '__|
 | | \ \  __/ (_| (_) | | | | (_) | (_) | |   
 |_|  \_\___|\___\___/|_| |_|\___/ \___/|_|   
                                              
                                              

"""
print(banner)



# Get the directory of the currently running script
absolute_path = os.path.dirname(os.path.abspath(__file__))

# Arguments Functions --------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description='Reconnaissance script with various modules.')

    # Specify the available command-line options
    parser.add_argument('-d', '--domain', type=validate_domain, help='Target domain for reconnaissance')
    parser.add_argument('-ps', '--passive', action='store_true', help='Perform passive subdomain enumeration')
    parser.add_argument('-ac', '--active', action='store_true', help='Perform active scan phase')
    parser.add_argument('-p', '--portscan', action='store_true', help='Perform port scanning')
    parser.add_argument('-nt', '--new-templates', action='store_true', help='Scan with newly added templates to the nuclei templates repo')
    parser.add_argument('-nf', '--nuclei-full', action='store_true', help='Perform a full nuclei scan')
    parser.add_argument('-ep', '--exposed-panels', action='store_true', help='Perform Panels dorking with nuclei templates')
    parser.add_argument('-js', '--js-exposures', action='store_true', help='Perform JS Exposures')
    parser.add_argument('-sl', '--subs-file', help='Path to the subdomains file')
    parser.add_argument('-xss', '--xss-scan', action='store_true', help='Perform xss scans')
    parser.add_argument('-wh', '--webhook', help='Webhook URL for Discord')
    parser.add_argument('-f', '--fuzzing', action='store_true' , help='fuzzing with h0tak88r.txt wordlist')

    try:
        return parser.parse_args()
    except argparse.ArgumentError as e:
        print(f"Error: {e}")
        parser.print_help()
        exit(1)

def send_file_to_discord(webhook_url, file_path):
    """
    Send a file to Discord via webhook.
    """
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(webhook_url, files=files)

            if response.status_code == 200:
                print(f"File '{file_path}' successfully sent to Discord.")
            else:
                print(f"Failed to send file to Discord. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")


def run_command(command, input_data=None, capture_output=True):
    try:
        result = subprocess.run(command, input=input_data, capture_output=capture_output, text=True, check=True)
        return result.stdout.strip() if capture_output else None
    except subprocess.CalledProcessError as e:
        print(f"Error while running command {command}: {e}")
        print("Command Output:")
        print(e.output.decode())
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def validate_domain(domain):
    """
    Validates the domain name using a regular expression.
    """
    pattern = re.compile(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.)?([a-zA-Z]{2,})$')
    if not pattern.match(domain):
        raise ValueError('Invalid domain name')
    return domain

def xss_scan(domain):
    """
    Scans a domain for XSS vulnerabilities.
    """
    gau = run_command(["gau", domain])
    if gau:
        xss_scan_cmd = ["kxss"]
        xss_scan_output = run_command(xss_scan_cmd, input_data=gau)
        if xss_scan_output:
            notify_cmd = ["notify", "-bulk"]
            run_command(notify_cmd, input_data=xss_scan_output)

def fetch_subdomains(url, domain):
    """
    Fetches subdomains from a given URL and returns them as a set.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        pattern = re.compile(rf'((?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.{domain})')
        return set(pattern.findall(response.text))
    except requests.exceptions.RequestException as e:
        print(f"Error fetching subdomains from {url}: {e}")
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

def write_subdomains_to_file(subdomains, output_file):
    with open(output_file, 'w') as file:
        for subdomain in sorted(subdomains):
            file.write(f'{subdomain}\n')

def subdomain_enumeration(target_domain, perform_passive, perform_active):
    print("[+] Performing subdomain enumeration")

    if perform_passive:
        print("[+] Passive Subdomain Enumeration ....")
        subs_directory = f"{absolute_path}/subs/"
        run_command(["rm", "-r", subs_directory])
        run_command(["mkdir", subs_directory])

        # Fetch subdomains from all sources
        subdomains = fetch_all_subdomains(target_domain)

        # Write subdomains to a file
        temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        try:
            write_subdomains_to_file(subdomains, temp_file.name)
            output_file = f'{subs_directory}/{target_domain}.txt'
            write_subdomains_to_file(subdomains, output_file)
            print(f'[+] Passive Subdomains saved to {output_file}')
        finally:
            os.unlink(temp_file.name)

        # Running subfinder on the target domain
        print(f'[+] Running passive subdomains using subfinder for {target_domain}')
        subfinder_output = run_command(["subfinder", "-d", target_domain, "--all", "--silent"])
        if subfinder_output:
            subfinder_file = f"{subs_directory}/subfinder.txt"
            write_subdomains_to_file(subfinder_output.split('\n'), subfinder_file)

    if perform_active:
        # Actie Subdomain Enumeration using DNS brute forcing with puredns
        print("[+] Actie Subdomain Enumeration using DNS brute forcing with puredns")
        try:
            run_command(["puredns", "bruteforce", f"{absolute_path}/Wordlists/dns/dns_2m.txt", target_domain, "-r", f"{absolute_path}/Wordlists/dns/valid_resolvers.txt", "-w", f"{subs_directory}/dns_bf.txt", "--skip-wildcard-filter", "--skip-validation"])
        except Exception as e:
            print(f"Error while running puredns for DNS brute forcing: {e}")

        # TLS Probing
        print("[+] tls probing")
        cero_output = run_command(["cero", target_domain])
        if cero_output:
            sed_output = run_command(["sed", 's/^*.//'], input_data=cero_output)
            grep_output = run_command(["grep", "\\."], input_data=sed_output)
            sort_output = run_command(["sort", "-u"], input_data=grep_output)
            grep_domain_output = run_command(["grep", f".{target_domain}$"], input_data=sort_output)

            if not grep_domain_output:
                print("[!] Warning: No results from TLS probing. Subdomain enumeration may not have provided any domains.")
            else:
                with open(f"{subs_directory}/tls_probing.txt", "w") as tls_probing_file:
                    tls_probing_file.write(grep_domain_output)

def filter_and_resolve_subdomains():
    print("[+] Filtering out the results")
    subs_files = glob.glob(f"{absolute_path}/subs/*")

    # Read all content from subdomain files
    all_subs_content = ""
    for file_path in subs_files:
        with open(file_path, 'r') as file:
            all_subs_content += file.read()

    # Use Python's sort for sorting
    sorted_subs_content = "\n".join(sorted(set(all_subs_content.split('\n'))))

    output_file = f"{absolute_path}/subs/all_subs_filtered.txt"
    
    with open(output_file, "w") as file:
        file.write(sorted_subs_content)

    print("[+] Running puredns for resolving the subs and output in all_subs_resolved.txt")

    try:
        run_command(["puredns", "resolve", output_file, "-r", f"{absolute_path}/Wordlists/dns/valid_resolvers.txt", "-w", f"{absolute_path}/subs/all_subs_resolved.txt", "--skip-wildcard-filter", "--skip-validation"])
    except Exception as e:
        print(f"Error while running puredns for resolving subdomains: {e}")

    print("[+] Running httpx for filtering the subs and output in filtered_hosts.txt")
    run_command(["httpx", "-l", output_file, "-random-agent", "-retries", "2", "-o", f"{absolute_path}/subs/filtered_hosts.txt"])


def port_scanning():
    print("[+] Performing port scanning")
    naabu_command = run_command(["naabu", "-list", f"{absolute_path}/subs/all_subs_filtered.txt", "-top-ports", "1000"])
    if naabu_command:
        run_command(["notify", "-bulk"], input_data=naabu_command)

def scan_with_new_nuclei_templates():
    print("[+] Scan with newly added templates to the nuclei templates repo")
    ntscan = run_command(["nuclei", "-l",  f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei-templates/", "-nt", "-es", "info"])
    if ntscan:
        run_command(["notify", "-bulk"], input_data=ntscan)

def full_nuclei_scan():
    print("[+] Scan with the full nuclei template")
    pt_scan = run_command(["nuclei", "-l", f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei_templates/Others", "-es", "info"])
    if pt_scan:
        run_command(["notify", "-bulk"], input_data=pt_scan)

def js_exposure_scan():
    print("[+] Scanning js files")
    resolved_domains_output = run_command(["cat", f"{absolute_path}/subs/all_subs_resolved.txt"])
    if resolved_domains_output:
        all_urls = run_command(["gau"], input_data=resolved_domains_output)
        js_files_filter = run_command(["grep", "\\.js$"], input_data=all_urls)
        js_files_output = run_command(["sort", "-u"], input_data=js_files_filter)
        js_scan = run_command(["nuclei", "-t", f"{absolute_path}/nuclei_templates/js/information-disclosure-in-js-files.yaml"], input_data=js_files_output)
        if js_scan:
            run_command(["notify", "-bulk"], input_data=js_scan)

def exposed_panels_scan():
    print("[+] Scanning for exposed panels")
    panels = run_command(["nuclei", "-l", f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei_templates/Panels"])
    if panels:
        run_command(["notify", "-bulk"], input_data=panels)


def fuzzing():
    print("[+] Fuzzing with h0tak88r.txt Wordlist:")
    print("[+] Please make sure that the config file for nuclei has allow-local-file-access: true")
    try:
        h0tak88r_fuzzing = run_command(["nuclei", "-l", f"{absolute_path}/subs/filtered_hosts.txt", "-t", f"{absolute_path}/nuclei_templates/fuzzing/h0tak88r/"])
        if h0tak88r_fuzzing:
            run_command(["notify", "-bulk"], input_data=h0tak88r_fuzzing)
    except Exception as e:
        print(f"An error occurred during fuzzing: {e}")

def recon(target_domain, perform_passive=False, perform_active=False, perform_portscan=False, perform_nuclei_new=False, perform_nuclei_full=False, perform_exposed_panels=False, perform_js_exposure=False, subs_file=None, perform_xss_scan=False, webhook=None, perform_fuzzing=False):
    try:
        if target_domain:
            subdomain_enumeration(target_domain, perform_passive, perform_active)
            filter_and_resolve_subdomains()
        if subs_file:
            # Use the provided subdomains file for other operations
            print(f"[+] Using provided subdomains file: {subs_file}")
            print("[+] Filtering dupliacates...")
            subs_directory = f"{absolute_path}/subs/"
            run_command(["rm", "-r", subs_directory])
            run_command(["mkdir", subs_directory])

            with open(subs_file, 'r') as file:
                subdomains = set(file.read().splitlines())

            sorted_subdomains = sorted(subdomains)

            with open(f"{subs_directory}/all_subs_filtered.txt", 'w') as output_file:
                for subdomain in sorted_subdomains:
                    output_file.write(f'{subdomain}\n')

            print("[+] Running httpx for filtering the subs and output in filtered_hosts.txt ")
            run_command(["httpx", "-l", f"{subs_directory}/all_subs_filtered.txt", "-random-agent", "-retries", "2", "-o", f"{subs_directory}/filtered_hosts.txt"])

        if webhook:
            send_file_to_discord(webhook, f"{absolute_path}/subs/all_subs_filtered.txt" )
        
        if perform_portscan:
            port_scanning()

        if perform_nuclei_new:
            scan_with_new_nuclei_templates()

        if perform_nuclei_full:
            full_nuclei_scan()

        if perform_js_exposure:
            js_exposure_scan()

        if perform_exposed_panels:
            exposed_panels_scan()

        if perform_xss_scan:
            print("[+] Scanning for XSS")
            xss_scan(target_domain)
        if perform_fuzzing:
	        fuzzing()

    except Exception as e:
        print(f"An error occurred during reconnaissance: {e}")

if __name__ == "__main__":
    args = parse_args()
    if not args.subs_file:
        # If no subs file is provided, the domain is required
        if not args.domain:
            print("Error: Target domain is required.")
            exit(1)
    
    recon(args.domain, args.passive, args.active, args.portscan, args.new_templates, args.nuclei_full, args.exposed_panels, args.js_exposures, args.subs_file, args.xss_scan, args.webhook, args.fuzzing)
