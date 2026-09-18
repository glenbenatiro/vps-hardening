#!/usr/bin/env bash
# audit.sh - READ-ONLY security audit for a Debian/Ubuntu VPS. Makes NO changes.
#
# Companion to HARDENING.md. Run it, then hand the log to Claude Code with
# scripts/analyze-prompt.md to get a PASS/ATTENTION/FAIL assessment.
#
# Usage:   sudo bash audit.sh        (prompts for your password)
# Output:  writes a timestamped log NEXT TO this script and prints the path.
# It only reads config/logs and writes that one log file (chmod 600). Nothing else changes.

set +e
TS=$(date +%Y%m%d-%H%M%S)
HOST=$(hostname)
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
OUT="${SCRIPT_DIR:-.}/security-audit-${HOST}-${TS}.log"

if [ "$(id -u)" -ne 0 ]; then
  echo "This audit needs root for the full picture. Re-run:  sudo bash $0"
  exit 1
fi

# Hand log ownership to the invoking user UP FRONT, so it is readable (e.g. by your
# Claude Code) even if the script is interrupted mid-scan.
touch "$OUT" 2>/dev/null
if [ -n "$SUDO_USER" ]; then chown "$SUDO_USER":"$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" "$OUT" 2>/dev/null; fi
chmod 600 "$OUT" 2>/dev/null

exec > >(tee "$OUT") 2>&1
sec(){ printf '\n\n========== %s ==========\n' "$1"; }

echo "SECURITY AUDIT (read-only) | host=$HOST | $(date)"
echo "Nothing is changed by this script. Log: $OUT"

sec "SYSTEM"
uname -a; grep -E 'PRETTY_NAME|VERSION_ID' /etc/os-release; uptime
echo "reboot-required: $( [ -f /var/run/reboot-required ] && echo YES || echo no )"

sec "SSH - effective config (sshd -T)"
sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam|authenticationmethods|permitemptypasswords|allowusers|allowgroups|maxauthtries|logingracetime|clientalive|x11forwarding|listenaddress|ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms)' | sort
sec "SSH - PAM stack (TOTP present?)"
grep -Ev '^\s*#|^\s*$' /etc/pam.d/sshd 2>/dev/null
echo "pam_google_authenticator lines: $(grep -c pam_google_authenticator /etc/pam.d/sshd 2>/dev/null)"
sec "SSH - activation mechanism + listeners"
echo "ssh / ssh.socket / sshd active: $(systemctl is-active ssh ssh.socket sshd 2>/dev/null | paste -sd' ')"
ss -tlnp 2>/dev/null | grep -iE 'sshd|:22 |ssh.socket' || echo "(no sshd listener matched)"
echo "--- port/socket config found (sshd_config + ssh.socket drop-ins) ---"
grep -rniE 'ListenStream|^\s*Port' /etc/systemd/system/ssh.socket.d/ /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null

sec "HOST FIREWALL (UFW)"
ufw status verbose 2>&1

sec "DOCKER-USER iptables chain (the ONLY thing that governs container ports - see HARDENING.md 10.12)"
for _ipt in iptables ip6tables; do
  echo "--- $_ipt ---"
  $_ipt -S DOCKER-USER 2>/dev/null || { echo "(no DOCKER-USER chain / $_ipt unavailable)"; continue; }
  $_ipt -S DU-INBOUND 2>/dev/null | sed 's/^/    /'
done

# UFW's INPUT rules never see container traffic: Docker DNATs in nat PREROUTING, so the packet is
# FORWARDed, and FORWARD jumps to DOCKER-USER/DOCKER-FORWARD before any ufw-*-forward chain.
# An empty DOCKER-USER while containers publish publicly is therefore a real hole, not a style nit.
_pub=0
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE '0\.0\.0\.0|\[::\]' && _pub=1
fi
# Count real rules, not a specific implementation: an inline default-deny and a sub-chain jump
# are both valid. What matters is that SOMETHING terminates in DROP on the container path.
_rules=$(iptables -S DOCKER-USER 2>/dev/null | grep -c '^-A' || true)
_drop=$( { iptables -S DOCKER-USER 2>/dev/null; iptables -S DU-INBOUND 2>/dev/null; } | grep -c -- '-j DROP' || true)
if [ "$_pub" -eq 1 ] && [ "${_rules:-0}" -eq 0 ]; then
  echo "FINDING: containers publish on 0.0.0.0/[::] but DOCKER-USER is EMPTY."
  echo "         UFW does NOT cover these ports. Any published port is reachable from the internet"
  echo "         unless an edge firewall happens to block it. See HARDENING.md 10.12."
elif [ "$_pub" -eq 1 ] && [ "${_drop:-0}" -eq 0 ]; then
  echo "FINDING: DOCKER-USER has rules but nothing terminates in DROP - it is not a default-deny."
else
  echo "OK: DOCKER-USER default-deny present, or no publicly published container ports."
fi

# --dport matches the CONTAINER port (post-DNAT), not the published one. A rule written that way
# silently allows -p <anyport>:80 and silently blocks a proxy published as 80:8000.
if { iptables -S DOCKER-USER 2>/dev/null; iptables -S DU-INBOUND 2>/dev/null; } | grep -q -- '--dport'; then
  echo "FINDING: DOCKER-USER/DU-INBOUND matches on --dport. After DNAT that is the CONTAINER port, not the"
  echo "         published one. Use --ctorigdstport instead. See HARDENING.md 10.12."
fi

# ufw_start()/ufw_stop() flush AND delete every non-builtin filter chain when this is yes,
# which destroys DOCKER-USER, every DOCKER-* chain and DU-INBOUND.
if grep -qE '^MANAGE_BUILTINS=yes' /etc/default/ufw 2>/dev/null; then
  echo "FINDING: MANAGE_BUILTINS=yes in /etc/default/ufw - a ufw reload will DELETE the Docker chains."
fi
unset _pub _rules _drop _ipt

echo "NOTE: a cloud/provider firewall is edge/panel-side and is NOT visible here. Verify it separately."
echo "NOTE: IPv6 - with no v6 DNAT and forwarding=0, [::] published ports are served by the userland"
echo "      docker-proxy via INPUT and are governed by UFW, not DOCKER-USER. Check before asserting:"
echo "      forwarding=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '?')" \
     "v6_nat_rules=$(ip6tables -t nat -S DOCKER 2>/dev/null | grep -c '^-A')"

sec "ALL LISTENING SOCKETS (interpret: public 0.0.0.0/[::] vs loopback vs tailscale)"
ss -tulnp 2>/dev/null

sec "DOCKER - container port bindings (0.0.0.0 = public-intent, 127.0.0.1 = loopback)"
if command -v docker >/dev/null; then
  docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}' 2>&1
  echo "--- containers publishing on 0.0.0.0 (each must be justified + allowed at the edge) ---"
  docker ps --format '{{.Names}}: {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0|\[::\]' || echo "(none)"
  echo "--- docker daemon TCP socket (want: none) ---"; ss -tlnp 2>/dev/null | grep -E ':2375|:2376' || echo "(no docker tcp socket - good)"
  # Credential-shaped env vars in containers. Plaintext in the container config and readable by
  # anyone who can reach the docker socket - and docker-group membership is root-equivalent.
  # NAMES AND COUNTS ONLY. Never print values: redaction patterns always miss a case
  # (PASS vs PASSWORD, PWD, CRED, DSN...) and one miss writes a live secret into this log.
  echo "--- containers carrying credential-shaped env vars (names only; prefer file-based secrets) ---"
  _found=0
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    keys=$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
           | cut -d= -f1 \
           | grep -iE '(PASS|PASSWD|PASSWORD|SECRET|TOKEN|KEY|CRED|AUTH|DSN)' | sort -u | tr '\n' ' ')
    if [ -n "$keys" ]; then echo "$c: $keys"; _found=1; fi
  done
  if [ "$_found" -eq 0 ]; then echo "(none)"; fi
  unset _found keys
else echo "(docker not installed)"; fi

sec "FAIL2BAN"
if command -v fail2ban-client >/dev/null; then
  fail2ban-client status 2>&1
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
    echo "--- jail: $j ---"; fail2ban-client status "$j" 2>&1 | grep -iE 'currently|total|banned|port|file list'
    fail2ban-client get "$j" journalmatch 2>/dev/null | tail -1 | sed 's/^/  journalmatch: /'
  done
else echo "(fail2ban not installed)"; fi

sec "UNATTENDED-UPGRADES"
dpkg -l unattended-upgrades 2>/dev/null | tail -1
echo "service enabled: $(systemctl is-enabled unattended-upgrades 2>/dev/null)"
echo "--- 20auto-upgrades ---"; cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
echo "--- automatic-reboot setting ---"; grep -iE 'Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -vE '^\s*//' || echo "(Automatic-Reboot not set)"
echo "upgradable packages: $(apt list --upgradable 2>/dev/null | grep -c upgradable)"

sec "APPARMOR"
aa-status 2>&1 | head -6
echo "apparmor service: $(systemctl is-active apparmor 2>/dev/null)"
aa-status 2>/dev/null | grep -q docker-default && echo "docker-default profile: present" || echo "docker-default profile: (not loaded / no docker)"

sec "SYSCTL hardening (values that should be set - see HARDENING.md 8.3-8.5)"
sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects \
  net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians \
  fs.protected_hardlinks fs.protected_symlinks fs.suid_dumpable \
  kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled \
  kernel.randomize_va_space 2>&1

sec "ACCOUNTS - UID 0 (should be ONLY root)"
awk -F: '$3==0{print $1" (uid 0)"}' /etc/passwd
sec "ACCOUNTS - users with a login shell"
awk -F: '$7 ~ /(bash|zsh|sh|fish)$/{print $1" -> "$7}' /etc/passwd
sec "ACCOUNTS - empty passwords (CRITICAL if any appear)"
awk -F: '($2==""){print $1" HAS EMPTY PASSWORD"}' /etc/shadow; echo "(check complete)"
sec "ACCOUNTS - lock/password status of shell users"
for u in $(awk -F: '$7 ~ /(bash|zsh|sh|fish)$/{print $1}' /etc/passwd); do passwd -S "$u" 2>/dev/null; done
sec "ACCOUNTS - root password status (want: L = locked)"
passwd -S root 2>/dev/null

sec "SUDOERS (Defaults + look for NOPASSWD / overly broad grants)"
grep -E '^Defaults' /etc/sudoers 2>/dev/null
echo "--- /etc/sudoers.d/* ---"
for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "# $f"; grep -Ev '^\s*#|^\s*$' "$f"; }; done
echo "--- NOPASSWD grants (review each) ---"; grep -rIE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "(none)"

sec "SSH authorized_keys (who can log in; key material NOT printed)"
for h in /root /home/*; do ak="$h/.ssh/authorized_keys"; [ -f "$ak" ] && { echo "# $ak"; awk '{print "  "$1" ... "$NF}' "$ak"; }; done
sec "SSH private keys on this box - encrypted? (UNENCRYPTED = pivot risk if the box is breached)"
for h in /root /home/*; do
  for k in "$h"/.ssh/*; do
    [ -f "$k" ] || continue
    grep -qiE 'PRIVATE KEY' "$k" 2>/dev/null || continue
    if ssh-keygen -y -P '' -f "$k" >/dev/null 2>&1; then echo "  UNENCRYPTED: $k"; else echo "  encrypted:   $k"; fi
  done
done
sec "SSH outbound reach (blast radius - what this box's keys can log in to)"
for h in /root /home/*; do cfg="$h/.ssh/config"; [ -f "$cfg" ] && { echo "# $cfg"; grep -E '^\s*(Host|IdentityFile) ' "$cfg"; }; done

sec "SECRETS AT REST - group/other-readable .env or key files (PERMS only, not contents)"
find /home /srv /root -maxdepth 5 \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' -o -name 'credentials*.json' -o -name 'service-account*.json' \) ! -name '*.example' -type f -not -path '*/node_modules/*' -perm /044 -exec stat -c '%a %U:%G %n' {} \; 2>/dev/null | head -40
echo "(only group/other-readable ones are listed; empty list = good)"

sec "FORGOTTEN SERVICES (headless-server blind spots)"
echo "--- remote-desktop packages (want: empty) ---"
dpkg -l 2>/dev/null | grep -Ei 'nomachine|xrdp|x11vnc|tigervnc|vino|anydesk|teamviewer' || echo "(none)"
echo "--- avahi/mDNS ---"; systemctl is-active avahi-daemon 2>/dev/null
echo "--- users with lingering enabled (persistent --user services) ---"; loginctl list-users 2>/dev/null

sec "TAILSCALE (if installed)"
if command -v tailscale >/dev/null; then tailscale status 2>&1 | head -15; systemctl is-enabled tailscaled 2>/dev/null; else echo "(tailscale not installed)"; fi

sec "SIGNS OF COMPROMISE - recent logins"
last -a -n 20 2>/dev/null | head -20
echo "--- accounts that have ever logged in (lastlog) ---"; lastlog 2>/dev/null | grep -vi 'Never logged in'
sec "SIGNS OF COMPROMISE - successful SSH logins grouped by source"
grep -hE 'Accepted ' /var/log/auth.log* 2>/dev/null | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -20
sec "SIGNS OF COMPROMISE - brute-force volume"
echo "total failed-password lines: $(grep -hE 'Failed password' /var/log/auth.log* 2>/dev/null | wc -l)"
grep -hE 'Failed password|Invalid user' /var/log/auth.log* 2>/dev/null | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -10
sec "SIGNS OF COMPROMISE - cron & timers"
echo "--- per-user crontabs ---"; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "[$u]: $c"; done; echo "(end crontabs)"
echo "--- /etc/cron.d ---"; ls -la /etc/cron.d 2>/dev/null
echo "--- /etc/crontab (non-comment) ---"; grep -vhE '^\s*#|^\s*$' /etc/crontab 2>/dev/null
echo "--- enabled timers ---"; systemctl list-timers --all 2>/dev/null | head -15
echo "--- .service files modified in last 30 days ---"; find /etc/systemd/system /lib/systemd/system -name '*.service' -mtime -30 2>/dev/null
sec "SIGNS OF COMPROMISE - processes running from /tmp /dev /var/tmp"
ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp/|/dev/|/var/tmp/' || echo "(none - good)"

sec "HOST IDS / AV present? (info only - not required on a hardened Linux box)"
for t in rkhunter chkrootkit aide auditd debsums lynis clamav; do command -v "$t" >/dev/null 2>&1 && echo "  $t: installed" || echo "  $t: not installed"; done

# SUID scan LAST on purpose: it is the slowest section, so every other check is already
# written to the log before it starts. Docker/snap image trees + big user caches are pruned
# (they never hold host SUID binaries), and it is hard-capped at 90s so it can never hang.
sec "SUID BINARIES on the host (image trees + caches pruned for speed; 90s cap)"
timeout 90 find / -xdev \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /snap -o -path /var/lib/snapd -o -name node_modules -o -name .cache -o -name .vscode-server -o -name .git -o -name .nvm \) -prune -o -perm -4000 -type f -print 2>/dev/null | sort
echo "(if this list looks cut off, the scan hit its 90s cap - re-run or widen it)"

sec "DONE"
echo "Read-only audit complete. NO changes were made to this system."
echo "Log written to: $OUT"
echo "Next: open Claude Code in this folder and paste scripts/analyze-prompt.md to grade the log."
