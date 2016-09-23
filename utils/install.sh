#!/bin/bash

echo "     __          _      ___   _ _ "  
echo "  /\ \ \/\/\    /_\    / _ \ (_|_) " 
echo " /  \/ /    \   /_\   / /_)/ | | | " 
echo "/ /\  / /\/\ \/  _  \/ ___/  | | | " 
echo "\_\ \/\/    \/\_/ \_/\/      |_|_| " 
                                   

echo ""
echo "               [~] Installing Nmapii ..."
sleep 5
echo ""
echo "[~] Installing Modules via python-pip"
pip install -r requirements.txt
sleep 3
cd ..
cd nse 
cp ms15-034.nse /usr/share/nmap/scripts
cp phpipam.nse /usr/share/nmap/scripts
cd ..

chmod +x nmapii
cp nmapii /usr/bin
rm -rf nampii
cd ..
cp -r nmapii /home/

echo ""
echo "[~] Creating directories for logs collection"

cd /
cd home/
rm -rf .nmapii-logs
mkdir .nmapii-logs
cd .nmapii-logs
echo 
mkdir basic/
mkdir SSL/
mkdir CVE-MS/
mkdir IRC/
mkdir MSF/
mkdir MYSQL/
mkdir MS-SQL/
mkdir SMB/
mkdir VNC/
mkdir TELNET/
mkdir FTP/
mkdir SSH/
mkdir other_vulns/

echo ""
echo "[~] You can now tune up to Nmapii !! ;) All Settings have been made !! "
sleep 2
cd /
clear