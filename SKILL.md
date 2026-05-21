---
name: vps-hardening
description: Audit a Debian/Ubuntu VPS's current security posture and walk the user through hardening it. Use when the user asks to "harden / secure / audit / lockdown my VPS", or is setting up a new server, or asks "how secure is my server" or similar. Pairs with HARDENING.md (canonical reference). Strongly safety-rail oriented — lockout is the failure mode to avoid.
---

# VPS Hardening Skill

You are walking the user through hardening a Linux VPS. The reference doc is [HARDENING.md](HARDENING.md) — read it first if you need the *why* behind any control. This skill file is the *procedure*.

**Hard rules — don't break these:**

1. **Never restart sshd without `sudo sshd -t` succeeding first.** Syntax errors in sshd_config can prevent the daemon from starting.
2. **Never make SSH or firewall changes without confirming the user has cloud-console access** (Contabo Web Console, Hetzner Cloud Console, AWS EC2 Instance Connect, etc.) as a recovery path.
3. **Always have the user keep their current SSH session open** during sshd config changes. They open a *new* session in a separate terminal to verify before closing the original.
4. **Never lock the root password before confirming the user's unprivileged sudo works** (run `sudo -v` as that user).
5. **Never bind sshd to a Tailscale IP** until Tailscale is verified up + persistent across reboots.
6. **Never disable UFW or remove its SSH rule** without immediately replacing it.
7. **Get explicit per-tier approval before executing changes** — don't bundle multiple tiers into one big run.
8. **Sudo via Claude Code's bash:** if `sudo` prompts for a password, the bash tool can't supply one (no tty). Either ask the user to run sudo commands in their own shell, OR have them paste a single composite script (heredoc) into a sudo-cached terminal.

---

## Workflow

### Phase 1 — Discovery (read-only audit)

Run the audit script to assess current state. **No changes in this phase.**

If sudo is available without password prompt, run directly. Otherwise, give the user this composite script to paste into a sudo-cached terminal and paste output back:

```bash
sudo bash -s <<'AUDIT' 2>&1 | tee /tmp/vps-audit.txt
echo "=== OS ==="
. /etc/os-release && echo "$PRETTY_NAME"
uname -r
uptime

echo; echo "=== EFFECTIVE SSHD ==="
sshd -T | grep -Ei '^(port|permitroot|passwordauth|pubkey|kbdinteractive|usepam|authenticationmethods|permitempty|maxauth|x11|allowtcp|allowusers|allowgroups|logingrace|clientalive|listenaddress|ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms)' | sort

echo; echo "=== PAM SSHD ==="
grep -Ev '^\s*#|^\s*$' /etc/pam.d/sshd

echo; echo "=== UFW ==="
ufw status verbose 2>&1 || echo "(ufw not installed)"

echo; echo "=== FAIL2BAN ==="
systemctl is-active fail2ban 2>&1
fail2ban-client status 2>&1
[ -f /etc/fail2ban/jail.local ] && grep -Ev '^\s*#|^\s*$' /etc/fail2ban/jail.local

echo; echo "=== UNATTENDED-UPGRADES ==="
systemctl is-active unattended-upgrades 2>&1
grep -E 'Automatic-Reboot|Allowed-Origins' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | head -10
ls /var/run/reboot-required 2>&1

echo; echo "=== APPARMOR ==="
aa-status 2>&1 | head -5

echo; echo "=== TAILSCALE ==="
tailscale status 2>&1 | head -10
tailscale ip -4 2>&1

echo; echo "=== LISTENING SOCKETS (TCP + UDP) ==="
ss -tulnp
echo "--- public-bound only (justify every line) ---"
ss -tulnp | grep -E '0\.0\.0\.0:|\[::\]:' || echo "(nothing bound to a public interface)"

echo; echo "=== USERS WITH SHELLS ==="
getent passwd | awk -F: '$7 ~ /(bash|zsh|sh|fish)$/ {print $1":"$3":"$7}'

echo; echo "=== FORGOTTEN SERVICES (headless blind spots) ==="
loginctl list-users 2>&1
echo "--- remote-desktop packages (want: empty) ---"
dpkg -l 2>/dev/null | grep -Ei 'nomachine|xrdp|x11vnc|tigervnc|vino|anydesk|teamviewer' || echo "(none)"
echo "--- avahi/mDNS ---"
systemctl is-active avahi-daemon 2>&1

echo; echo "=== SUDOERS.D ==="
ls -la /etc/sudoers.d/
for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "# $f" && grep -Ev '^\s*#|^\s*$' "$f"; done

echo; echo "=== EMPTY PASSWORDS ==="
awk -F: '$2==""{print "EMPTY:"$1}' /etc/shadow

echo; echo "=== ROOT ACCOUNT ==="
passwd -S root

echo; echo "=== FAILED LOGINS (last 10) ==="
lastb -i -n 10 2>&1 | head -12

echo; echo "=== SYSCTL HARDENING ==="
sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
       net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians \
       net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route \
       fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks \
       kernel.kptr_restrict kernel.dmesg_restrict \
       kernel.unprivileged_bpf_disabled kernel.randomize_va_space 2>&1

echo; echo "=== DOCKER (if present) ==="
which docker >/dev/null 2>&1 && {
  cat /etc/docker/daemon.json 2>/dev/null || echo "(no daemon.json)"
  ss -tlnp 2>/dev/null | grep -E ':2375|:2376' || echo "(no docker tcp socket — good)"
}

echo; echo "=== ~/.ssh PERMS ==="
ls -la ~/.ssh 2>&1
echo "--- what this box's keys can reach (blast radius) ---"
grep -E '^\s*(Host|IdentityFile) ' ~/.ssh/config 2>/dev/null || echo "(no ~/.ssh/config)"
echo "--- other credential stores present ---"
ls -d ~/.aws ~/.config/gcloud ~/.kube ~/.docker/config.json 2>/dev/null || echo "(none)"

echo; echo "=== DONE ==="
AUDIT
```

> **Note:** `systemd --user` services don't appear above — the script runs under
> `sudo` (root's user manager), not the login user's. If `loginctl list-users`
> shows a human user with lingering enabled, have them run
> `systemctl --user list-units --type=service` **in their own shell** to surface
> per-user daemons (see [HARDENING.md §7.7](HARDENING.md#77-remove-forgotten--unnecessary-services-headless-server-blind-spots)).

### Phase 2 — Map findings to controls

Compare audit output against [HARDENING.md](HARDENING.md) sections. For each control:
- ✅ Already implemented — note + move on
- ⚠️ Partial — note what's missing
- ❌ Missing — add to recommendations

**On an existing box, first justify every open port.** Before mapping controls,
walk the `LISTENING SOCKETS` + `UFW` output per [HARDENING.md §4.4](HARDENING.md#44-auditing-an-already-running-box--justify-every-open-port):
for each public listener and each UFW ALLOW rule, name the service behind it and
decide keep / scope-down / remove. Forgotten daemons (remote-desktop tools,
mDNS, stray `--user` services) surface here, not in the from-scratch checklist.

Categorise findings into tiers:
- **Tier 0 — Critical fix** (e.g. password auth still enabled, exposed Docker socket, empty password)
- **Tier 1 — High value, low risk** (chmod, sysctl, lock root, auto-reboot config)
- **Tier 2 — High value, requires SSH restart** (crypto tightening, AllowUsers, ListenAddress)
- **Tier 3 — Nice to have** (recidive jail, lynis, auditd, monthly cron)

### Phase 3 — Present findings + ask for approval

Show the user a structured summary:

```
## Audit summary

### Already in place ✅
- SSH key-only auth
- TOTP via PAM
- (etc.)

### Recommended hardening
**Tier 0 (must-fix):** none / list any critical
**Tier 1 (zero risk):** chmod ssh config, sysctl drop-in, lock root, auto-reboot
**Tier 2 (SSH restart):** crypto tightening, AllowUsers, X11=no
**Tier 3 (optional):** recidive jail, lynis baseline

Where do you want to start?
```

**Get explicit approval before executing.** Don't bundle.

### Phase 4 — Pre-flight safety

Before any change touching SSH, firewall, sudoers, or PAM, confirm with the user:

1. **Cloud-provider console access** — "Can you log into your provider's web console right now? (Contabo Web Console / Hetzner Cloud / AWS EC2 / etc.)" — this is the recovery path.
2. **Two SSH sessions open** — for sshd changes.
3. **Backup of critical configs:**
   ```bash
   sudo mkdir -p /root/hardening-backup-$(date +%F)
   sudo cp -a /etc/ssh /etc/sudoers /etc/sudoers.d /etc/pam.d/sshd \
              /etc/ufw /etc/fail2ban \
              /root/hardening-backup-$(date +%F)/
   ```

### Phase 5 — Execute, tier by tier

For each tier:

1. State exactly what's about to change (file paths, config keys, expected diff).
2. Show the user the command(s).
3. Have them run it (or run via bash if sudo available).
4. Verify immediately:
   - SSH changes → `sudo sshd -t` → restart → **open second session** → confirm login → only then close original.
   - Sysctl → `sudo sysctl --system` → re-read the keys to confirm new values.
   - UFW → `sudo ufw status verbose` → confirm rules + still able to SSH.
5. Get user confirmation that step worked before moving to next.

### Phase 6 — Final verification

Run the verification script from [HARDENING.md §11](HARDENING.md#11-post-hardening-verification-checklist). All items should be green.

Have user run `ssh-audit` from a tailnet peer or external host:
```bash
pipx install ssh-audit
ssh-audit -p <port> <vps-ip-or-tailscale-ip>
```

Confirm public unreachability:
```bash
nc -vz <public-ip> <port>     # should TIME OUT
```

---

## SSHD restart safety pattern (use every time)

```bash
# In your CURRENT session (don't close it):
sudo sshd -t                                # validates config, exits 0 if ok
sudo systemctl restart ssh                  # restart

# In a NEW terminal:
ssh -p <port> user@vps                      # confirm new session works

# If new session works → close the old one. If not → fix in old session.
```

---

## Tier-by-tier execution recipes

### Tier 1 — Zero-risk safe batch

These don't touch SSH, network, or auth — can be applied without a held-open session.

```bash
sudo bash -s <<'TIER1' 2>&1
# 1. Lock root password (only if confirmed sudo works)
sudo -nv 2>/dev/null && passwd -l root || echo "(skip: confirm sudo works first)"

# 2. Sysctl hardening
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Network
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 1
fs.suid_dumpable = 0
# Kernel info-leak
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 2
net.core.bpf_jit_harden = 2
kernel.randomize_va_space = 2
EOF
sysctl --system

# 3. Auto-reboot for unattended-upgrades
if ! grep -q 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
  cat >> /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
fi

echo "Tier 1 done."
TIER1

# As the user (not sudo): fix ~/.ssh/config perms
chmod 600 ~/.ssh/config 2>/dev/null
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys ~/.ssh/id_* 2>/dev/null
chmod 644 ~/.ssh/*.pub ~/.ssh/known_hosts 2>/dev/null
```

### Tier 2 — SSH crypto + hygiene (requires sshd restart)

**Pre-conditions:** Two open SSH sessions. Cloud console available.

```bash
sudo tee /etc/ssh/sshd_config.d/99-local.conf <<'EOF'
# Auth (already enforced by main config typically; reaffirming)
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AuthenticationMethods publickey,keyboard-interactive
KbdInteractiveAuthentication yes
UsePAM yes

# Restrict
AllowUsers <YOUR-USERNAME>
MaxAuthTries 3
LoginGraceTime 30

# Hygiene
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2

# Modern crypto only
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF

# Replace <YOUR-USERNAME> first!
sudo sed -i 's/<YOUR-USERNAME>/glenbenatiro/' /etc/ssh/sshd_config.d/99-local.conf  # or whatever

# Validate
sudo sshd -t
# If exit 0 → restart
sudo systemctl restart ssh

# Now open a NEW terminal and verify before closing the old one.
```

### Tier 3 — fail2ban recidive + tooling

```bash
# Add recidive jail
sudo tee -a /etc/fail2ban/jail.local <<'EOF'

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
sudo systemctl restart fail2ban

# Install audit tools
sudo apt install -y lynis
# Run baseline (interactive scrolling output)
sudo lynis audit system

# From a tailnet peer / your laptop:
pipx install ssh-audit
ssh-audit -p <port> <vps-ip>
```

### Tier 4 — Bind sshd to private interface (defence in depth)

**Only after Tailscale is confirmed reliable across reboots.** This is the highest-risk hardening — Tailscale failure = SSH lockout (recoverable via cloud console).

```bash
TS4=$(tailscale ip -4)
TS6=$(tailscale ip -6)
sudo tee -a /etc/ssh/sshd_config.d/99-local.conf <<EOF

ListenAddress $TS4
ListenAddress $TS6
EOF
sudo sshd -t && sudo systemctl restart ssh

# Verify in new session before closing existing.
sudo ss -tlnp | grep ssh
# Should show LISTEN only on Tailscale IPs, not 0.0.0.0
```

### Reboot — apply kernel updates

When ready (compose stack has `restart: always`):
```bash
sudo reboot
# Reconnect after ~60s. Verify:
uptime
ls /var/run/reboot-required 2>&1     # not found
```

---

## Things to ask the user up-front

Before you start, gather:

1. **Distro + version** — `cat /etc/os-release`. This skill targets Debian/Ubuntu; RHEL-family substitutes (`dnf`, `firewalld`, `selinux`) live in HARDENING.md but recipes need adapting.
2. **Are you on the VPS already, or remote SSH-ing in?** Affects how risky changes are.
3. **Cloud provider** — for recovery console specifics.
4. **Are you using Tailscale / WireGuard / direct public SSH?** Affects ListenAddress + UFW recipe.
5. **Is this a fresh VPS or one with running services?** Fresh = follow Phases 3–10 of HARDENING.md. Running = audit first, deltas only.
6. **Single-admin or multi-admin?** Affects AllowUsers recipe.
7. **Public-facing services?** (HTTP, mail, etc.) Affects UFW rules + fail2ban jails.

---

## When NOT to use this skill

- For RHEL/Fedora/CentOS specifically — recipes assume `apt`, `ufw`, AppArmor. Adapt manually using HARDENING.md as a reference.
- For Kubernetes nodes — those have their own playbook; node hardening intersects with kubelet, CRI socket, etc.
- For "audit only, don't recommend changes" — skip Phase 4–6, just do Phase 1–3.
- For incident response after a suspected compromise — that's a different playbook (preserve logs, snapshot disks, isolate before changing anything).

---

## Reference

Full deep-dive on every control's *what / why / how / verify*: [HARDENING.md](HARDENING.md).
