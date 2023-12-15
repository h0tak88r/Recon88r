#!/bin/bash

banner() {
cat << "EOF"
  _____                       ___   ___       
 |  __ \                     / _ \ / _ \      
 | |__) |___  ___ ___  _ __ | (_) | (_) |_ __ 
 |  _  // _ \/ __/ _ \| '_ \ > _ < > _ <| '__|
 | | \ \  __/ (_| (_) | | | | (_) | (_) | |   
 |_|  \_\___|\___\___/|_| |_|\___/ \___/|_|   
                                              
EOF
}

cleanup_subs_directory() {
    echo "[+] Cleaning up the subs directory"
    rm -rf subs/
    mkdir subs
}

passive_subdomain_enumeration() {
    echo "[+] Performing passive subdomain enumeration"
    target_domain=$1

    urls=(
        "https://rapiddns.io/subdomain/$target_domain?full=1#result"
        "http://web.archive.org/cdx/search/cdx?url=*.$target_domain/*&output=text&fl=original&collapse=urlkey"
        "https://crt.sh/?q=%.$target_domain"
        "https://crt.sh/?q=%.%.$target_domain"
        "https://crt.sh/?q=%.%.%.$target_domain"
        "https://crt.sh/?q=%.%.%.%.$target_domain"
        "https://otx.alienvault.com/api/v1/indicators/domain/$target_domain/passive_dns"
        "https://api.hackertarget.com/hostsearch/?q=$target_domain"
        "https://urlscan.io/api/v1/search/?q=$target_domain"
        "https://jldc.me/anubis/subdomains/$target_domain"
        "https://www.google.com/search?q=site%3A$target_domain&num=100"
        "https://www.bing.com/search?q=site%3A$target_domain&count=50"
    )

    for url in "${urls[@]}"; do
        curl -s "$url" | grep -o '([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.'"$target_domain"'' >> "subs/passive.txt"
    done

    cat "subs/passive.txt" | sort -u > "subs/quick_passive.txt"
    rm "subs/passive.txt"
    subfinder -d $target_domain --all --silent > "subs/subfinder.txt"
}

active_subdomain_enumeration() {
    echo "[+] Performing active subdomain enumeration"
    target_domain=$1

    puredns bruteforce "Wordlists/dns/dns_2m.txt" "$target_domain" -r "Wordlists/dns/valid_resolvers.txt" -w "subs/dns_bf.txt" --skip-wildcard-filter --skip-validation
    cero "$target_domain" | sed 's/^*.//' | grep "\." | sort -u | grep ".$target_domain$" > "subs/tls_probing.txt"
    cat "subs/"* | sort -u > "subs/all_subs_filtered.txt"
    puredns resolve "subs/all_subs_filtered.txt" -r "Wordlists/dns/valid_resolvers.txt" -w "subs/all_subs_resolved.txt" --skip-wildcard-filter --skip-validation
    cat "subs/all_subs_filtered.txt" | httpx -random-agent -retries 2 -o "subs/filtered_hosts.txt"
}

send_file_to_discord() {
    local webhook_url="$1"
    local file_path="$2"

    if [ -f "$file_path" ]; then
        curl -X POST -F "file=@$file_path" "$webhook_url"
        echo "File '$file_path' successfully sent to Discord."
    else
        echo "Error: File '$file_path' not found."
    fi
}

perform_port_scanning() {
    echo "[+] Performing port scanning"
    naabu -list subs/all_subs_filtered.txt -top-ports 1000 | notify -bulk
}

perform_exposed_panels_scan() {
    echo "[+] Performing exposed panels scan"
    cat subs/filtered_hosts.txt | nuclei -t nuclei_templates/panels | notify -bulk
}

perform_js_exposure_scan() {
    echo "[+] Performing JS exposure scan"
    gau "$TARGET_DOMAIN"  | grep "\\.js$" | sort -u | tee JS.txt
    nuclei -l JS.txt -t nuclei_templates/js/information-disclosure-in-js-files.yaml | notify -bulk
}

scan_with_new_nuclei_templates() {
    echo "[+] Scan with newly added templates to the nuclei templates repo"
    cat subs/filtered_hosts.txt | nuclei -t nuclei-templates/ -nt -es info | notify -bulk
}

perform_full_nuclei_scan() {
    echo "[+] Performing a full nuclei scan"
    cat subs/filtered_hosts.txt | nuclei -t nuclei_templates/Others -es info | notify -bulk
}

xss_scan() {
    echo "[+] Scanning for XSS"
    gau "$TARGET_DOMAIN" | kxss | notify --bulk
}

fuuzing() {
  echo "[+] Fuzzing using h0tak88r_fuzz.txt wordlist"
  nuclei -t nuclei_templates/fuzzing/h0tak88r/ -l subs/filtered_hosts.txt  | notify -bulk
}

recon() {
    target_domain=$1
    passive_subdomain_enumeration "$target_domain"
    active_subdomain_enumeration "$target_domain"
    send_file_to_discord "https://discord.com/api/webhooks/1052205480681951252/_hAFDr4MN8Z1iPsusHi0vFEb9Q_DtLAF-mnUGKO7ZSemNHP9OxjcN0i30gSVKZjdNPmb" "subs/all_subs_filtered.txt"
    send_file_to_discord "https://discord.com/api/webhooks/1052205480681951252/_hAFDr4MN8Z1iPsusHi0vFEb9Q_DtLAF-mnUGKO7ZSemNHP9OxjcN0i30gSVKZjdNPmb" "subs/filtered_hosts.txt"
    xss_scan
    perform_port_scanning
    perform_exposed_panels_scan
    perform_js_exposure_scan
    scan_with_new_nuclei_templates
    perform_full_nuclei_scan
    fuuzing
}

TARGET_DOMAIN=$1
banner
cleanup_subs_directory
recon "$TARGET_DOMAIN"
