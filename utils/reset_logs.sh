#!/bin/bash
echo ""
echo -e "  [~] Please Wait [~]"
echo ""
sleep 2
echo -e "  [~] Checking For Log Files"
sleep 2

cd /
cd home/
rm -rf .nmapii-logs
mkdir .nmapii-logs
cd .nmapii-logs

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
echo "  [~] All Logs Has Been Re-Set..."
sleep 2
echo ""
echo "  [~] Getting Back To Nmapii"
echo ""
#cd /
#sudo python ~/nmapii/nmapii.py