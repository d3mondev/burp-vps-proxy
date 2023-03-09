#!/bin/bash
apt update && apt install dante-server

cat > /etc/danted.conf << EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody
internal: 0.0.0.0 port=1080
external: eth0
socksmethod: username
clientmethod: none
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}
EOF

useradd -r -s /bin/false burp-vps-proxy
echo 'burp-vps-proxy:CHANGEME' | chpasswd

systemctl restart danted.service
