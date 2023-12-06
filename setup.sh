go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/glebarez/cero@latest
go install github.com/Emoe/kxss@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
git clone https://github.com/h0tak88r/nuclei_templates.git
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install
cd ..
git clone --no-checkout https://github.com/h0tak88r/Wordlists.git
cp .gau.toml $HOME/.gau.toml

