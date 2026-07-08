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
9. **Before changing the SSH port, run `systemctl is-active ssh.socket`.** On Ubuntu 24.04+ SSH is often socket-activated: the port lives in the `ssh.socket` unit, not `sshd_config` (editing `Port` there does nothing), and a bare `ListenStream=<port>` binds **IPv6-only** and drops IPv4 — a silent lockout. Use the socket-aware recipe (HARDENING.md §5.3).
10. **A cloud/provider firewall is edge-side and Docker can't bypass it.** When a public port is genuinely needed (including any Docker `0.0.0.0` publish), remind the user to allow it in the provider panel — and prefer `127.0.0.1` binding so it never needs to be public (HARDENING.md §4.1, §10.3).
11. **Verify SSH auth with `sshd -T`, not the drop-in file — cloud images silently override you.** Ubuntu cloud images (incl. Contabo) ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` with `PasswordAuthentication yes`, which wins by *first-match* over a `99-local.conf`. Fix `50-cloud-init.conf` itself, set `ssh_pwauth: false` in `/etc/cloud/cloud.cfg.d/`, and confirm the *effective* value with `sudo sshd -T | grep -i passwordauth` (HARDENING.md §5.2).

---

## Workflow

### Phase 1 — Discovery (read-only audit)

The canonical audit is **[`scripts/audit.sh`](scripts/audit.sh)** — a read-only script that checks everything below and writes a timestamped log next to itself. **No changes in this phase.**

```bash
sudo bash scripts/audit.sh          # writes security-audit-<host>-<ts>.log in scripts/
```

Then read that log and grade it against HARDENING.md (or hand the log to Claude Code with [`scripts/analyze-prompt.md`](scripts/analyze-prompt.md)). If `sudo` needs a password, the bash tool can't supply one — have the user run the line in their own shell and paste the log path back. If the repo isn't on the box, copy `scripts/audit.sh` over first.

The script covers: OS; effective sshd + PAM (TOTP); **SSH activation mechanism (classic vs `ssh.socket`)** + listeners; UFW; DOCKER-USER; all listening sockets; Docker `0.0.0.0` publishes + daemon socket; fail2ban; unattended-upgrades + auto-reboot; AppArmor; sysctl hardening; accounts (UID 0 / empty passwords / root lock / sudoers NOPASSWD); authorized_keys; **private-key encryption status + outbound blast radius**; world/group-readable secrets; forgotten services (remote-desktop / avahi / lingering); Tailscale; and signs-of-compromise (logins by source, brute-force volume, cron/timers, recently-modified units, processes from `/tmp`, SUID).

> **Note:** the script runs under `sudo` (root's user manager), so `systemd --user` services of the *login* user won't fully show. If it reports a human user with lingering enabled, have them run `systemctl --user list-units --type=service` **in their own shell** (see [HARDENING.md §7.7](HARDENING.md#77-remove-forgotten--unnecessary-services-headless-server-blind-spots)).

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
- **Tier 0 — Critical fix** (e.g. password auth still enabled, exposed Docker socket, DB/service published on `0.0.0.0`, empty password)
- **Tier 1 — High value, low risk** (chmod, sysctl, lock root, auto-reboot config)
- **Tier 2 — High value, requires SSH restart** (crypto tightening, AllowUsers, custom port, ListenAddress)
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

Run the verification script from [HARDENING.md §11](HARDENING.md#11-post-hardening-verification-checklist) (or re-run `scripts/audit.sh`). All items should be green.

Have user run `ssh-audit` from a tailnet peer or external host:
```bash
pipx install ssh-audit
ssh-audit -p <port> <vps-ip-or-tailscale-ip>
```

Confirm public unreachability **from a network that isn't the box's own** (a box can't reliably test its own external reachability — hairpin/Docker NAT lie; see HARDENING.md §11):
```bash
nc -vz <public-ip> <port>     # from an outside network — should TIME OUT
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

# 2b. Make two of the above actually STICK (they get silently reverted otherwise):
#     apport re-enables fs.suid_dumpable=2 at boot; UFW's IPT_SYSCTL resets log_martians=0 on start.
systemctl disable --now apport 2>/dev/null || true
sed -i 's/^enabled=1/enabled=0/' /etc/default/apport 2>/dev/null || true
sed -i 's#^net/ipv4/conf/all/log_martians=0#net/ipv4/conf/all/log_martians=1#' /etc/ufw/sysctl.conf 2>/dev/null || true
sed -i 's#^net/ipv4/conf/default/log_martians=0#net/ipv4/conf/default/log_martians=1#' /etc/ufw/sysctl.conf 2>/dev/null || true

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
sudo sed -i 's/<YOUR-USERNAME>/youruser/' /etc/ssh/sshd_config.d/99-local.conf  # or whatever

# Validate
sudo sshd -t
# If exit 0 → restart
sudo systemctl restart ssh

# Now open a NEW terminal and verify before closing the old one.
```

### Tier 2b — Change the SSH port (socket-aware; the migration is the lockout risk)

**Pre-conditions:** Two open SSH sessions + cloud console. First detect the mechanism:
```bash
systemctl is-active ssh.socket    # active → socket-activated; inactive → classic sshd_config
```

**Classic sshd** — add the new port *alongside* 22, prove it, then drop 22:
```bash
sudo ufw allow <NEW-PORT>/tcp
printf 'Port 22\nPort <NEW-PORT>\n' | sudo tee /etc/ssh/sshd_config.d/49-ssh-port.conf
sudo sshd -t && sudo systemctl restart ssh
# NEW terminal: ssh -p <NEW-PORT> user@vps   → confirm, THEN set the drop-in to just Port <NEW-PORT>,
# reload, and: sudo ufw delete allow 22/tcp
```

**Socket-activated sshd (Ubuntu 24.04+)** — port lives in `ssh.socket`; list BOTH address families (base socket is `BindIPv6Only=ipv6-only`):
```bash
sudo ufw allow <NEW-PORT>/tcp
sudo install -d /etc/systemd/system/ssh.socket.d
printf '[Socket]\nListenStream=0.0.0.0:<NEW-PORT>\nListenStream=[::]:<NEW-PORT>\n' \
  | sudo tee /etc/systemd/system/ssh.socket.d/10-add-port.conf
sudo systemctl daemon-reload && sudo systemctl restart ssh.socket
sudo ss -tlnp | grep -E ':22 |:<NEW-PORT> '     # expect 22 + <NEW-PORT>, each on 0.0.0.0 AND [::]
# NEW terminal: ssh -p <NEW-PORT> user@vps  → confirm, THEN drop 22:
printf '[Socket]\nListenStream=\nListenStream=0.0.0.0:<NEW-PORT>\nListenStream=[::]:<NEW-PORT>\n' \
  | sudo tee /etc/systemd/system/ssh.socket.d/10-add-port.conf
sudo systemctl daemon-reload && sudo systemctl restart ssh.socket
sudo ufw delete allow 22/tcp
```
If fail2ban is installed, set `port = <NEW-PORT>` in its `[sshd]` jail afterward (HARDENING.md §9.1).

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

### Tier 4 — Make SSH reachable only over the private network (defence in depth)

Two ways, pick per the box:

**(a) Cloud firewall (preferred if the provider has one; HARDENING.md §4.1.1).** Simply *don't* allow the SSH port at the edge, but do allow Tailscale's UDP 41641. SSH then arrives only over the tunnel; the public internet can't reach the port at all. No sshd change, no boot-order risk.

**(b) Bind sshd to the Tailscale IP.** **Only after Tailscale is confirmed reliable across reboots** — Tailscale failure = SSH lockout (recoverable via cloud console). On socket-activated hosts set this on the socket, not sshd_config:
```bash
TS4=$(tailscale ip -4); TS6=$(tailscale ip -6)
# classic sshd:
sudo tee -a /etc/ssh/sshd_config.d/99-local.conf <<EOF

ListenAddress $TS4
ListenAddress $TS6
EOF
sudo sshd -t && sudo systemctl restart ssh
sudo ss -tlnp | grep ssh          # LISTEN only on Tailscale IPs, not 0.0.0.0
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
3. **Cloud provider — and does it have a cloud firewall?** For recovery-console specifics, and because a default-deny provider firewall (AWS SG, Hetzner/DO/Vultr, **Contabo Cloud Firewall**) is your Docker-proof edge layer (§4.1).
4. **Are you using Tailscale / WireGuard / direct public SSH?** Affects ListenAddress + UFW/edge recipe.
5. **Is this a fresh VPS or one with running services?** Fresh = follow Phases 3–10 of HARDENING.md. Running = audit first, deltas only.
6. **Single-admin or multi-admin?** Affects AllowUsers recipe.
7. **Public-facing services?** (HTTP, mail, WebRTC media, etc.) Affects UFW/edge rules + fail2ban jails.

---

## When NOT to use this skill

- For RHEL/Fedora/CentOS specifically — recipes assume `apt`, `ufw`, AppArmor. Adapt manually using HARDENING.md as a reference.
- For Kubernetes nodes — those have their own playbook; node hardening intersects with kubelet, CRI socket, etc.
- For "audit only, don't recommend changes" — skip Phase 4–6, just do Phase 1–3.
- For incident response after a suspected compromise — that's a different playbook (preserve logs, snapshot disks, isolate before changing anything).

---

## Reference

Full deep-dive on every control's *what / why / how / verify*: [HARDENING.md](HARDENING.md).
