#!/bin/bash

# Function to install Go tools
install_go_tools() {
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/d3mondev/puredns/v2@latest
    go install github.com/glebarez/cero@latest
    go install github.com/Emoe/kxss@latest
    go install github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
}

# Function to install massdns
install_massdns() {
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns
    make
    sudo make install
    cd ..
}

# Clone nuclei_templates and nuclei-templates repositories
git clone https://github.com/h0tak88r/nuclei_templates.git
git clone https://github.com/projectdiscovery/nuclei-templates.git

# Install Go tools
install_go_tools

# Install massdns
install_massdns

# Clone Wordlists repository
git clone --depth 1 https://github.com/h0tak88r/Wordlists.git &
wait

# Copy .gau.toml to user's home directory
cp .gau.toml $HOME/.gau.toml

# Add the line for local file access to Nuclei configuration
echo "allow-local-file-access: true" >> ~/.config/nuclei/config.yaml
