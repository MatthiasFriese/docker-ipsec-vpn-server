#!/bin/sh
#
# Docker script to configure and start an IPsec VPN server
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC! THIS IS ONLY MEANT TO BE RUN
# IN A CONTAINER!
#
# This file is part of IPsec VPN Docker image, available at:
# https://github.com/hwdsl2/docker-ipsec-vpn-server
#
# Copyright (C) 2016-2020 Lin Song <linsongui@gmail.com>
# Based on the work of Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr()  { echo "Error: $1" >&2; exit 1; }
nospaces() { printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
onespace() { printf '%s' "$1" | tr -s ' '; }
noquotes() { printf '%s' "$1" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"; }
noquotes2() { printf '%s' "$1" | sed -e 's/" "/ /g' -e "s/' '/ /g"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

if [ ! -f "/.dockerenv" ] && [ ! -f "/run/.containerenv" ] && ! head -n 1 /proc/1/sched | grep -q '^run\.sh '; then
  exiterr "This script ONLY runs in a container (e.g. Docker, Podman)."
fi

if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
cat 1>&2 <<'EOF'
Error: This Docker image should be run in privileged mode.
    For detailed instructions, please visit:
    https://github.com/hwdsl2/docker-ipsec-vpn-server

EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

if uname -r | grep -q cloud && [ ! -e /dev/ppp ]; then
  echo >&2
  echo "Error: /dev/ppp is missing. Debian 10 users, see: https://git.io/vpndebian10" >&2
fi

NET_IFACE=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
[ -z "$NET_IFACE" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
[ -z "$NET_IFACE" ] && NET_IFACE=eth0

mkdir -p /opt/src
vpn_env="/opt/src/vpn.env"
vpn_gen_env="/opt/src/vpn-gen.env"
if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  if [ -f "$vpn_env" ]; then
    echo
    echo 'Retrieving VPN credentials...'
    . "$vpn_env"
  elif [ -f "$vpn_gen_env" ]; then
    echo
    echo 'Retrieving previously generated VPN credentials...'
    . "$vpn_gen_env"
  else
    echo
    echo 'VPN credentials not set by user. Generating random PSK and password...'
    VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 20)
    VPN_USER=vpnuser
    VPN_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)

    printf '%s\n' "VPN_IPSEC_PSK='$VPN_IPSEC_PSK'" > "$vpn_gen_env"
    printf '%s\n' "VPN_USER='$VPN_USER'" >> "$vpn_gen_env"
    printf '%s\n' "VPN_PASSWORD='$VPN_PASSWORD'" >> "$vpn_gen_env"
    chmod 600 "$vpn_gen_env"
  fi
fi

# Remove whitespace and quotes around VPN variables, if any
VPN_IPSEC_PSK=$(nospaces "$VPN_IPSEC_PSK")
VPN_IPSEC_PSK=$(noquotes "$VPN_IPSEC_PSK")
VPN_USER=$(nospaces "$VPN_USER")
VPN_USER=$(noquotes "$VPN_USER")
VPN_PASSWORD=$(nospaces "$VPN_PASSWORD")
VPN_PASSWORD=$(noquotes "$VPN_PASSWORD")
VPN_LEFT_NAME=$(nospaces "$VPN_LEFT_NAME")
VPN_LEFT_NAME=$(noquotes "$VPN_LEFT_NAME")
VPN_LEFT_IP_SUBNET=$(nospaces "$VPN_LEFT_IP_SUBNET")
VPN_LEFT_IP_SUBNET=$(noquotes "$VPN_LEFT_IP_SUBNET")
VPN_RIGHT_NAME=$(nospaces "$VPN_RIGHT_NAME")
VPN_RIGHT_NAME=$(noquotes "$VPN_RIGHT_NAME")
VPN_RIGHT_IP_SUBNET=$(nospaces "$VPN_RIGHT_IP_SUBNET")
VPN_RIGHT_IP_SUBNET=$(noquotes "$VPN_RIGHT_IP_SUBNET")

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit your 'env' file and re-enter them."
fi

if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

case $VPN_SHA2_TRUNCBUG in
  [yY][eE][sS])
    echo
    echo "Setting sha2-truncbug to yes in ipsec.conf..."
    SHA2_TRUNCBUG=yes
    ;;
  *)
    SHA2_TRUNCBUG=no
    ;;
esac

# Create IPsec config
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
    protostack=netkey

conn mysubnet
     also=mytunnel
     leftsubnet=$VPN_LEFT_IP_SUBNET
     rightsubnet=$VPN_RIGHT_IP_SUBNET
     auto=start

conn mytunnel
    left=$VPN_LEFT_NAME
    right=$VPN_RIGHT_NAME
    authby=secret

include /etc/ipsec.d/*.conf
EOF

if uname -r | grep -qi 'coreos'; then
  sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
fi

if grep -qs ike-frag /etc/ipsec.d/ikev2.conf; then
  sed -i 's/^[[:space:]]\+ike-frag=/  fragmentation=/' /etc/ipsec.d/ikev2.conf
fi

# Specify IPsec PSK
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

# Create xl2tpd config
#cat > /etc/xl2tpd/xl2tpd.conf <<EOF
#[global]
#port = 1701

#[lns default]
#ip range = $L2TP_POOL
#local ip = $L2TP_LOCAL
#require chap = yes
#refuse pap = yes
#require authentication = yes
#name = l2tpd
#pppoptfile = /etc/ppp/options.xl2tpd
#length bit = yes
#EOF

# Set xl2tpd options
#cat > /etc/ppp/options.xl2tpd <<EOF
#+mschap-v2
#ipcp-accept-local
#ipcp-accept-remote
#noccp
#auth
#mtu 1280
#mru 1280
#proxyarp
#lcp-echo-failure 4
#lcp-echo-interval 30
#connect-delay 5000
#ms-dns $DNS_SRV1
#EOF

# Create VPN credentials
#cat > /etc/ppp/chap-secrets <<EOF
#"$VPN_USER" l2tpd "$VPN_PASSWORD" *
#EOF

#VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
#cat > /etc/ipsec.d/passwd <<EOF
#$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
#EOF

# Update sysctl settings
SYST='/sbin/sysctl -e -q -w'
$SYST kernel.msgmnb=65536 2>/dev/null
$SYST kernel.msgmax=65536 2>/dev/null
$SYST net.ipv4.ip_forward=1 2>/dev/null
$SYST net.ipv4.conf.all.accept_redirects=0 2>/dev/null
$SYST net.ipv4.conf.all.send_redirects=0 2>/dev/null
$SYST net.ipv4.conf.all.rp_filter=0 2>/dev/null
$SYST net.ipv4.conf.default.accept_redirects=0 2>/dev/null
$SYST net.ipv4.conf.default.send_redirects=0 2>/dev/null
$SYST net.ipv4.conf.default.rp_filter=0 2>/dev/null
$SYST "net.ipv4.conf.$NET_IFACE.send_redirects=0" 2>/dev/null
$SYST "net.ipv4.conf.$NET_IFACE.rp_filter=0" 2>/dev/null

# Create IPTables rules
#if ! iptables -t nat -C POSTROUTING -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE 2>/dev/null; then
#  iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
#  iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
#  iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#  iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
#  iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
#  iptables -I INPUT 6 -p udp --dport 1701 -j DROP
#  iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
#  iptables -I FORWARD 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#  iptables -I FORWARD 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
#  iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
#  iptables -I FORWARD 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#  iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
  # Uncomment to disallow traffic between VPN clients
  # iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
  # iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
#  iptables -A FORWARD -j DROP
#  iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE
#  iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
#fi

case $VPN_ANDROID_MTU_FIX in
  [yY][eE][sS])
    echo
    echo "Applying fix for Android MTU/MSS issues..."
    iptables -t mangle -A FORWARD -m policy --pol ipsec --dir in \
      -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 \
      -j TCPMSS --set-mss 1360
    iptables -t mangle -A FORWARD -m policy --pol ipsec --dir out \
      -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 \
      -j TCPMSS --set-mss 1360
    echo 1 > /proc/sys/net/ipv4/ip_no_pmtu_disc
    ;;
esac

# Update file attributes
chmod 600 /etc/ipsec.secrets /etc/ipsec.d/passwd

# Check for new Libreswan version
swan_ver_ts="/opt/src/swan_ver_ts"
swan_ver_old="/opt/src/swan_ver_old"
if [ ! -f "$swan_ver_ts" ] || [ "$(find $swan_ver_ts -mmin +10080)" ]; then
  touch "$swan_ver_ts"
  os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
  swan_ver_cur=4.1
  swan_ver_url="https://dl.ls20.com/v1/docker/$os_arch/swanver?ver=$swan_ver_cur"
  swan_ver_latest=$(wget -t 3 -T 15 -qO- "$swan_ver_url")
  if ! printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9])\.([0-9]|[1-9][0-9])$'; then
    swan_ver_latest=$swan_ver_cur
  fi
  if [ "$swan_ver_cur" != "$swan_ver_latest" ]; then
    touch "$swan_ver_old"
  else
    [ -f "$swan_ver_old" ] && rm -f "$swan_ver_old"
  fi
fi
if [ -f "$swan_ver_old" ]; then
  echo
  echo "Note: A newer Libreswan version $swan_ver_latest is available."
  echo "To update this Docker image, see: https://git.io/updatedockervpn"
fi

cat <<EOF

================================================

IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $PUBLIC_IP
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD
EOF

if [ -n "$VPN_ADDL_USERS" ] && [ -n "$VPN_ADDL_PASSWORDS" ]; then
  count=1
  addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -d ' ' -f 1)
  addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -d ' ' -f 1)
cat <<'EOF'

Additional VPN users (username | password):
EOF
  while [ -n "$addl_user" ] && [ -n "$addl_password" ]; do
cat <<EOF
$addl_user | $addl_password
EOF
    count=$((count+1))
    addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -s -d ' ' -f "$count")
    addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -s -d ' ' -f "$count")
  done
fi

cat <<'EOF'

Write these down. You'll need them to connect!

Important notes:   https://git.io/vpnnotes2
Setup VPN clients: https://git.io/vpnclients
IKEv2 guide:       https://git.io/ikev2docker

================================================

EOF

# Start services
mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid

exec /usr/local/sbin/ipsec start -D
#exec /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf
