#!/bin/bash
#vless (Wegare)
clear
udp2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $7}')" 
host2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $1}')" 
port2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $2}')" 
bug2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $5}')" 
user2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $4}')" 
#path2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $3}')" 
#aid2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $6}')" 
ws2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $8}')" 
#tls2="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $9}')" 
#protocol2="$(cat /root/akun/vless.txt | grep -i protocol | cut -d= -f2 | tail -n1)" 
echo "Inject vless by wegare"
echo "1. Sett Profile"
echo "2. Start Inject"
echo "3. Stop Inject"
echo "4. Enable auto booting & auto rekonek"
echo "5. Disable auto booting & auto rekonek"
echo "e. exit"
read -p "(default tools: 2) : " tools
[ -z "${tools}" ] && tools="2"
if [ "$tools" = "1" ]; then

echo "Masukkan host/ip" 
read -p "default host/ip: $host2 : " host
[ -z "${host}" ] && host="$host2"

echo "Masukkan port" 
read -p "default port: $port2 : " port
[ -z "${port}" ] && port="$port2"

echo "Masukkan user id" 
read -p "default user id: $user2 : " user
[ -z "${user}" ] && user="$user2"

echo "Masukkan bug" 
read -p "default bug: $bug2 : " bug
[ -z "${bug}" ] && bug="$bug2"

read -p "ingin menggunakan port udpgw y/n " pilih
if [ "$pilih" = "y" ]; then
echo "Masukkan port udpgw" 
read -p "default udpgw: $udp2 : " udp
[ -z "${udp}" ] && udp="$udp2"
badvpn="--socks-server-addr 127.0.0.1:1080 --udpgw-remote-server-addr 127.0.0.1:$udp"
elif [ "$pilih" = "Y" ]; then
echo "Masukkan port udpgw" 
read -p "default udpgw: $udp2 : " udp
[ -z "${udp}" ] && udp="$udp2"
badvpn="--socks-server-addr 127.0.0.1:1080 --udpgw-remote-server-addr 127.0.0.1:$udp"
else
badvpn="--socks-server-addr 127.0.0.1:1080"
fi
#echo "Masukkan protocol" 
#read -p "default protocol: $protocol2 : " protocol
##[ -z "${protocol}" ] && protocol="$protocol2"

##echo "Masukkan alterld/aid" 
#read -p "default alterld/aid: $aid2 : " aid
##[ -z "${aid}" ] && aid="$aid2"

##echo "Masukkan path" 
##read -p "default path: $path2 : " path
##[ -z "${path}" ] && path="$path2"

echo "Pilih method flow ws/tcp" 
read -p "default flow: $ws2 : " ws
[ -z "${ws}" ] && ws="$ws2"

##echo "Pilih method tls tls/none" 
#read -p "default tls: $tls2 : " tls
##[ -z "${tls}" ] && tls="$tls2"

echo "$host
$port
path
$user
$bug
aid
$udp
$ws
tls" > /root/akun/vless.txt
cat <<EOF> /root/akun/vless.json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    }
  ],
  "log": {
    "loglevel": "warning"
  },
  "outbounds": [
    {
      "mux": {
        "concurrency": -1,
        "enabled": false
      },
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$host",
            "port": $port,
            "users": [
              {
                "alterId": 0,
                "encryption": "none",
                "flow": "xtls-rprx-direct",
                "id": "$user",
                "level": 8,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "$ws",
        "security": "xtls",
        "xtlsSettings": {
          "allowInsecure": true,
          "serverName": "$bug"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF
cat <<EOF> /usr/bin/gproxy-vless
badvpn-tun2socks --tundev tun1 --netif-ipaddr 10.0.0.2 --netif-netmask 255.255.255.0 $badvpn --udpgw-connection-buffer-size 65535 --udpgw-transparent-dns &
EOF
chmod +x /usr/bin/gproxy-vless
echo "Sett Profile Sukses"
sleep 2
clear
/usr/bin/vless
elif [ "${tools}" = "2" ]; then
ipmodem="$(route -n | grep -i 0.0.0.0 | head -n1 | awk '{print $2}')" 
echo "ipmodem=$ipmodem" > /root/akun/ipmodem.txt
udp="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $7}')" 
host="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $1}')" 
route="$(cat /root/akun/ipmodem.txt | grep -i ipmodem | cut -d= -f2 | tail -n1)"

xray -c /root/akun/vless.json &
sleep 3
ip tuntap add dev tun1 mode tun
ifconfig tun1 10.0.0.1 netmask 255.255.255.0
/usr/bin/gproxy-vless
route add 8.8.8.8 gw $route metric 0
route add 8.8.4.4 gw $route metric 0
route add $host gw $route metric 0
route add default gw 10.0.0.2 metric 0
echo "
#!/bin/bash
#vless (Wegare)
host=$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $1}')
fping -l $host" > /usr/bin/ping-vless
chmod +x /usr/bin/ping-vless
/usr/bin/ping-vless > /dev/null 2>&1 &
sleep 5
elif [ "${tools}" = "3" ]; then
host="$(cat /root/akun/vless.txt | tr '\n' ' '  | awk '{print $1}')" 
route="$(cat /root/akun/ipmodem.txt | grep -i ipmodem | cut -d= -f2 | tail -n1)" 
#killall screen
killall -q badvpn-tun2socks xray ping-vless fping
route del 8.8.8.8 gw "$route" metric 0 2>/dev/null
route del 8.8.4.4 gw "$route" metric 0 2>/dev/null
route del "$host" gw "$route" metric 0 2>/dev/null
ip link delete tun1 2>/dev/null
killall dnsmasq 
/etc/init.d/dnsmasq start > /dev/null
sleep 2
echo "Stop Suksess"
sleep 2
clear
/usr/bin/vless
elif [ "${tools}" = "4" ]; then
cat <<EOF>> /etc/crontabs/root

# BEGIN AUTOREKONEKVLESS
*/1 * * * *  autorekonek-vless
# END AUTOREKONEKVLESS
EOF
sed -i '/^$/d' /etc/crontabs/root 2>/dev/null
/etc/init.d/cron restart
echo "Enable Suksess"
sleep 2
clear
/usr/bin/vless
elif [ "${tools}" = "5" ]; then
sed -i "/^# BEGIN AUTOREKONEKVLESS/,/^# END AUTOREKONEKVLESS/d" /etc/crontabs/root > /dev/null
/etc/init.d/cron restart
echo "Disable Suksess"
sleep 2
clear
/usr/bin/vless
elif [ "${tools}" = "e" ]; then
clear
exit
else 
echo -e "$tools: invalid selection."
exit
fi