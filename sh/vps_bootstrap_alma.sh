#!/usr/bin/env bash
set -euo pipefail

################################
# CONFIG
################################
SSH_PORT=5413
SSH_USER="mubdiur_87ui980_vf"

################################
# PRECHECK
################################
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root."
  exit 1
fi

echo "=== AlmaLinux 9 Secure Bootstrap ==="

################################
# SYSTEM UPDATE
################################
echo "Updating system..."
dnf update -y
dnf install -y \
  curl vim sudo firewalld \
  policycoreutils-python-utils \
  epel-release

################################
# CREATE SUDO USER
################################
if ! id "$SSH_USER" &>/dev/null; then
  echo "Creating user: $SSH_USER"
  useradd -m -s /bin/bash "$SSH_USER"
  usermod -aG wheel "$SSH_USER"
  
  echo "Please set the password for $SSH_USER:"
  passwd "$SSH_USER"
else
  echo "User $SSH_USER already exists."
fi

################################
# ENSURE SUDO WORKS
################################
# Ensure the wheel group has sudo access
if ! grep -q "^%wheel ALL=(ALL) ALL" /etc/sudoers; then
  echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
fi

################################
# SSH HARDENING
################################
echo "Configuring SSH..."

# Backup existing config
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%F)"

# Write new config
cat <<EOF > /etc/ssh/sshd_config
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers ${SSH_USER}
MaxAuthTries 3
LoginGraceTime 20
PermitEmptyPasswords no
AllowTcpForwarding no
X11Forwarding no
PrintLastLog yes
EOF

################################
# SELINUX FIX FOR CUSTOM SSH PORT
################################
# Check if port is already allowed to avoid error
if ! semanage port -l | grep -q "ssh_port_t.*${SSH_PORT}"; then
  echo "Adding SELinux rule for SSH port ${SSH_PORT}..."
  semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}
else
  echo "SELinux rule for port ${SSH_PORT} already exists."
fi

################################
# FIREWALL SETUP
################################
echo "Configuring Firewall..."
systemctl enable --now firewalld

# Reset to default zone public
firewall-cmd --set-default-zone=public

# Remove standard SSH service (port 22)
firewall-cmd --permanent --remove-service=ssh

# Allow HTTP/HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Add Rich Rule for Custom SSH Port (Rate Limited)
# NOTE: We do NOT use --add-port here, because we want the rich rule to handle the access.
firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='${SSH_PORT}' protocol='tcp' limit value='3/m' accept"

# Block Ping (Optional)
firewall-cmd --permanent --add-icmp-block=echo-request

firewall-cmd --reload

################################
# VALIDATE & RESTART SSH
################################
echo "Restarting SSH..."
sshd -t
systemctl restart sshd

################################
# KERNEL HARDENING
################################
echo "Applying Kernel Hardening..."
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

################################
# CROWDSEC INSTALL
################################
echo "Installing CrowdSec..."

# 1. Install Repository
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash

# 2. Install Agent AND Firewall Bouncer
# Note: Installing the bouncer usually automatically registers it with the local API
dnf install -y crowdsec crowdsec-firewall-bouncer-nftables

systemctl enable --now crowdsec

################################
# CROWDSEC CONFIGURATION
################################
echo "Configuring CrowdSec..."
cscli collections install crowdsecurity/linux
cscli collections install crowdsecurity/ssh
cscli collections install crowdsecurity/base-http-scenarios
cscli hub update

systemctl restart crowdsec

################################
# DONE
################################
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

echo
echo "=== BOOTSTRAP COMPLETE ==="
echo
echo "NEXT STEPS:"
echo "1) KEEP THIS TERMINAL OPEN."
echo "2) Open a NEW terminal and test connection:"
echo "   ssh ${SSH_USER}@${SERVER_IP} -p ${SSH_PORT}"
echo
echo "3) Verify sudo works inside the new session."
echo "4) Only AFTER verifying login, run:"
echo "   passwd -l root"
echo
echo "5) Check CrowdSec Status:"
echo "   cscli metrics"