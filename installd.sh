#!/bin/bash
TEMP=/tmp/answer$$
whiptail --title "Antoninianus [D]"  --menu  "Ubuntu 16.04/18.04 Daemon Node :" 20 0 0 1 "Compile antoninianusd Ubuntu 16.04" 2 "Update antoninianusd 16.04 to latest" 3 "Compile antoninianusd Ubuntu 18.04" 4 "Update antoninianusd 18.04 to latest" 2>$TEMP
choice=`cat $TEMP`
case $choice in
1) echo 1 "Compiling antoninianusd Ubuntu 16.04"

echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get --assume-yes install git unzip build-essential libssl-dev libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev obfs4proxy libcurl4-openssl-dev

echo "Installing Antoninianus Wallet"
git clone https://github.com/carsenk/antoninianus
cd antoninianus || exit
git checkout master
git pull

cd src
make -f makefile.unix

sudo yes | cp -rf antoninianusd /usr/bin/

echo "Copied to /usr/bin for ease of use"

echo "Populate antoninianus.conf"
mkdir ~/.antoninianus
echo -e "daemon=1\listen=1\rpcuser=user\rpcpassword=changethispassword\nativetor=0\naddnode=antoninianus.host\naddnode=antoninianus.win\naddnode=antoninianus.pro\naddnode=triforce.black" > ~/.antoninianus/antoninianus.conf

echo "Get Chaindata"
cd ~/.antoninianus || exit
rm -rf database txleveldb smsgDB
wget https://gitlab.com/antoninianus/chain/raw/master/chaindata2290877.zip
unzip chaindata2290877.zip
rm -rf chaindata2290877.zip
echo "Back to Compiled antoninianusd Binary Folder"
cd ~/antoninianus/src
                ;;
2) echo 2 "Update antoninianusd"
echo "Updating Antoninianus Wallet"
cd ~/antoninianus || exit
git checkout master
git pull

cd src
make -f makefile.unix

sudo yes | cp -rf antoninianusd /usr/bin/

echo "Copied to /usr/bin for ease of use"

echo "Back to Compiled antoninianusd Binary Folder"
cd ~/antoninianus/src
                ;;
3) echo 3 "Compile antoninianusd Ubuntu 18.04"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get --assume-yes install git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev obfs4proxy libssl-dev libcurl4-openssl-dev

echo "Downgrade libssl-dev"
sudo apt-get install make
wget https://www.openssl.org/source/openssl-1.0.1j.tar.gz
tar -xzvf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j
./config
make depend
sudo make install
sudo ln -sf /usr/local/ssl/bin/openssl `which openssl`
cd ~
openssl version -v

echo "Installing Antoninianus Wallet"
git clone https://github.com/carsenk/antoninianus
cd antoninianus
git checkout master
git pull

cd src
make OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib -f makefile.unix

sudo yes | cp -rf antoninianusd /usr/bin/

echo "Copied to /usr/bin for ease of use"

echo "Populate antoninianus.conf"
mkdir ~/.antoninianus
echo -e "daemon=1\listen=1\rpcuser=user\rpcpassword=changethispassword\nativetor=0\naddnode=antoninianus.host\naddnode=antoninianus.win\naddnode=antoninianus.pro\naddnode=triforce.black" > ~/.antoninianus/antoninianus.conf

echo "Get Chaindata"
cd ~/.antoninianus
rm -rf database txleveldb smsgDB
wget https://gitlab.com/antoninianus/chain/raw/master/chaindata2290877.zip
unzip chaindata2290877.zip
rm -rf chaindata2290877.zip
echo "Back to Compiled antoninianusd Binary Folder"
cd ~/antoninianus/src
                ;;
4) echo 4 "Update antoninianusd 18.04"
echo "Updating Antoninianus Wallet"
cd ~/antoninianus || exit
git checkout master
git pull

cd src
make OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib -f makefile.unix

sudo yes | cp -rf antoninianusd /usr/bin/

echo "Copied to /usr/bin for ease of use"

echo "Back to Compiled antoninianusd Binary Folder"
cd ~/antoninianus/src
                ;;
esac
echo Selected $choice
