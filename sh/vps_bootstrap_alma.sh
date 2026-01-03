#!/usr/bin/env bash
set -e

### CONFIG ###
SSH_PORT=5413
SSH_USER="mubdiur_87ui980_vf"

echo "=== System update ==="
dnf update -y
dnf install -y curl vim sudo firewalld

echo "=== Create sudo user ==="
if ! id "$SSH_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$SSH_USER"
  passwd "$SSH_USER"
  usermod -aG wheel "$SSH_USER"
fi

echo "=== Ensure sudo for wheel ==="
grep -q "^%wheel ALL=(ALL) ALL" /etc/sudoers || \
  echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers

echo "=== Harden SSH ==="
cat <<EOF > /etc/ssh/sshd_config
Port $SSH_PORT
Protocol 2

PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

AllowUsers $SSH_USER

MaxAuthTries 3
LoginGraceTime 20
AllowTcpForwarding no
X11Forwarding no
PermitEmptyPasswords no
EOF

systemctl restart sshd

echo "=== Enable firewalld ==="
systemctl enable --now firewalld

firewall-cmd --set-default-zone=public
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

firewall-cmd --permanent --add-rich-rule="
rule family=\"ipv4\" port port=\"${SSH_PORT}\" protocol=\"tcp\" limit value=\"3/m\" accept"

firewall-cmd --permanent --add-icmp-block=echo-request
firewall-cmd --reload

echo "=== Kernel hardening ==="
cat <<EOF > /etc/sysctl.d/99-security.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

sysctl --system

echo "=== Install Docker (Dokploy dependency) ==="
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

echo "=== Install CrowdSec ==="
curl -s https://install.crowdsec.net | sh
dnf install -y crowdsec crowdsec-firewalld

systemctl enable --now crowdsec
systemctl enable --now crowdsec-firewalld

cscli collections install crowdsecurity/sshd
cscli collections install crowdsecurity/base-http-scenarios
cscli collections install crowdsecurity/http-cve

systemctl restart crowdsec

echo "=== Bootstrap completed ==="
echo "NEXT STEPS:"
echo "1) Test SSH login: ssh $SSH_USER@SERVER_IP -p $SSH_PORT"
echo "2) Verify sudo works: sudo whoami"
echo "3) THEN lock root password: passwd -l root"
