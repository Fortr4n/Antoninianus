#!/bin/bash
TEMP=/tmp/answer$$
whiptail --title "Antoninianus [D]"  --menu  "Ubuntu 16.04/18.04 QT Wallet :" 20 0 0 1 "Compile Antoninianus QT Ubuntu 16.04" 2 "Update Antoninianus QT 16.04 to v3.4 latest" 3 "Compile Antoninianus QT Ubuntu 18.04" 4 "Update Antoninianus QT 18.04 to v3.4 latest" 2>$TEMP
choice=`cat $TEMP`
case $choice in
1) echo 1 "Compiling Antoninianus QT Ubuntu 16.04"

echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libssl-dev libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake  libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Installing Antoninianus Wallet"
git clone https://github.com/carsenk/antoninianus
cd antoninianus || exit
git checkout master
git pull

#echo "Change line in antoninianus-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/antoninianus/antoninianus-qt.pro

qmake "USE_QRCODE=1" "USE_UPNP=1" antoninianus-qt.pro
make

echo "Populate antoninianus.conf"
mkdir ~/.antoninianus
echo -e "nativetor=0\naddnode=antoninianus.host\naddnode=antoninianus.win\naddnode=antoninianus.pro\naddnode=triforce.black" > ~/.antoninianus/antoninianus.conf

echo "Get Chaindata"
cd ~/.antoninianus || exit
rm -rf database txleveldb smsgDB
#wget http://d.hashbag.cc/chaindata.zip
#unzip chaindata.zip
wget hhttps://denarii.cloud/chaindata.zip
unzip chaindata.zip
rm -rf chaindata.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/antoninianus/src
                ;;
2) echo 2 "Update Antoninianus QT"
echo "Updating Antoninianus Wallet"
cd ~/antoninianus || exit
git checkout master
git pull

#echo "Change line in antoninianus-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/antoninianus/antoninianus-qt.pro

qmake "USE_QRCODE=1" "USE_UPNP=1" antoninianus-qt.pro
make
echo "Back to Compiled QT Binary Folder"
cd ~/antoninianus
                ;;
3) echo 3 "Compile Antoninianus QT Ubuntu 18.04"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Downgrade libssl-dev"
sudo apt-get install make
wget https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
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

#echo "Change line in antoninianus-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/antoninianus/antoninianus-qt.pro

qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib antoninianus-qt.pro
make

echo "Populate antoninianus.conf"
mkdir ~/.antoninianus
echo -e "nativetor=0\naddnode=antoninianus.host\naddnode=antoninianus.win\naddnode=antoninianus.pro\naddnode=triforce.black" > ~/.antoninianus/antoninianus.conf

echo "Get Chaindata"
cd ~/.antoninianus
rm -rf database txleveldb smsgDB
#wget http://d.hashbag.cc/chaindata.zip
#unzip chaindata.zip
wget https://denarii.cloud/chaindata.zip
unzip chaindata.zip
rm -rf chaindata.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/antoninianus/src
                ;;
4) echo 4 "Update Antoninianus QT 18.04"
echo "Updating Antoninianus Wallet"
cd ~/antoninianus || exit
git checkout master
git pull

#echo "Change line in antoninianus-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/antoninianus/antoninianus-qt.pro

qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib antoninianus-qt.pro
make
echo "Back to Compiled QT Binary Folder"
cd ~/antoninianus
                ;;
esac
echo Selected $choice
