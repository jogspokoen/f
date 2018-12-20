#!/bin/bash
apt-get update;
apt-get -y install screen python3 python-dev python3-dev python-pip git tor proxychains mc nmap ipython build-essential autoconf libtool pkg-config python-dev libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev libcurl4-openssl-dev;
# pip install -r dnscan/requirements.txt;
pip install virtualenvwrapper netaddr requests scrapy wfuzz dnspython;
source /usr/local/bin/virtualenvwrapper.sh;
mkdir ~/tools;
git clone https://github.com/jogspokoen/dnscan tools/dnscan;
git clone https://github.com/kost/dvcs-ripper tools/dvcs-ripper;
git clone https://github.com/sbp/gin tools/gin;
# seting up vim
mkdir -p ~/.vim/colors;
git clone https://github.com/VundleVim/Vundle.vim.git ~/.vim/bundle/Vundle.vim
wget https://raw.githubusercontent.com/jogspokoen/f/master/http-git2.nse -O /usr/share/nmap/scripts/http-git2.nse;
wget https://raw.githubusercontent.com/jogspokoen/f/master/.vimrc -O ~/.vimrc;
wget https://raw.githubusercontent.com/jogspokoen/f/master/monokai.vim -O ~/.vim/colors/monokai.vim;
vim +PluginInstall +qall;