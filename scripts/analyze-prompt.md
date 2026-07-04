# Audit analysis prompt

Paste everything below the line into Claude Code running **on the VPS you audited**, after you've run
`audit.sh`. It only reads the log the script produced; it changes nothing. It grades the box against
[`../HARDENING.md`](../HARDENING.md).

---

You are reviewing a READ-ONLY security audit of the Ubuntu/Debian VPS you are running on. I ran
`audit.sh` (in this `scripts/` folder) with sudo; it wrote its log into this same folder, named
`security-audit-<hostname>-<timestamp>.log`.

Read the most recent `security-audit-*.log` in this folder — do **not** run the audit yourself and do
**not** change anything — and produce a security assessment mapped to the controls in `../HARDENING.md`.

**First, establish this box's intended exposure** so you can judge "extra" ports fairly. Ask me (or infer
from context) the **expected public port set** and the **SSH access model**:
- Public web box: typically `80` + `443`, plus any deliberately-published service ports (e.g. a WebRTC
  media server's `7881/tcp` + `7882/udp`).
- SSH: is it **public on a custom port**, or **tailnet-only** (no public SSH port; reachable only over
  Tailscale)? On a tailnet-only box there should be **no** public SSH listener.
- Note: a cloud/provider firewall is edge-side and does **not** appear in the log (HARDENING.md §4.1) —
  treat edge filtering as confirmed separately; judge the on-box picture.

**Assess each item PASS / ATTENTION / FAIL, with one line of evidence quoted from the log:**

1. **SSH** (§5) — root login disabled, password auth disabled, pubkey enabled, listening only on the
   intended port/interface (no stray `:22`), TOTP present if expected (§6), modern crypto (§7.5).
2. **Host firewall** (§4.3) — UFW active, default deny incoming.
3. **Exposed ports** (§4.4, §10.3) — only the expected public set. Flag ANY other `0.0.0.0`/`[::]`
   listener or Docker `0.0.0.0` publish; say whether it maps to an allowed/intended port or should be
   rebound to `127.0.0.1`.
4. **fail2ban** (§9.1) — active; `[sshd]` jail present and (if SSH is public) scoped to the right port.
5. **Unattended-upgrades** (§8.1) — enabled; note if `Automatic-Reboot` is unset and if updates/reboot
   are pending.
6. **OS hardening** (§8.2–8.5) — AppArmor active; the sysctl network/fs/kernel values are set.
7. **Accounts** (§3.2, §8.6, §8.7) — only `root` at UID 0; no empty passwords; root password locked; no
   unexpected `NOPASSWD` sudoers.
8. **On-box credentials** (§8.8) — flag every **UNENCRYPTED** private key (pivot risk) and note what each
   reaches; flag any account-wide GitHub key vs a scoped deploy key.
9. **authorized_keys** — every entry expected/known; flag anything unrecognized.
10. **Secrets at rest** — flag any group/other-readable `.env` or key files.
11. **Forgotten services** (§7.7) — flag remote-desktop daemons, avahi/mDNS, or unexpected lingering
    `--user` services.
12. **Signs of compromise** (§9.2) — are recent logins all from expected sources? Any surprising
    successful-login source, user cron job, recently-modified systemd unit, process from `/tmp`/`/dev`,
    or unusual SUID binary? State explicitly whether it looks clean.

**Output:** a compact per-item table (PASS / ATTENTION / FAIL + quoted evidence), then a prioritized
"Fix these" list tiered as in `../SKILL.md` (Tier 0 critical → Tier 3 nice-to-have), then a one-sentence
signs-of-compromise verdict. Cite a log line for every claim; do not assert anything the log doesn't show.
