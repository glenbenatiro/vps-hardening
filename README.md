# vps-hardening

A reusable VPS hardening playbook + Claude Code skill, distilled from a real audit of an Ubuntu 24.04 box on Contabo.

Works two ways: **harden a fresh server** top-to-bottom, or **audit an existing one** — enumerating what's actually open and justifying every listening port and firewall rule (§4.4), which is where forgotten daemons, stray credentials, and exposed admin UIs surface.

## What's in here

| File | Purpose |
|---|---|
| **[HARDENING.md](HARDENING.md)** | The comprehensive reference doc. Each control has *what / why / how / verify*. Read top-to-bottom for a fresh server, or jump to the relevant section as a lookup. |
| **[SKILL.md](SKILL.md)** | A Claude Code skill that walks an LLM (or a human) through auditing + hardening a VPS interactively, with safety rails. References HARDENING.md as the canonical reference. |
| **README.md** | This file. |

## Two ways to use it

### 1. Manual

Read [HARDENING.md](HARDENING.md). Follow §9 (execution order) on a fresh VPS, or use individual sections to fill gaps on an existing one. Run §10 to verify.

### 2. AI-assisted (Claude Code skill)

Install the skill once:

```bash
# Clone or symlink this folder into ~/.claude/skills/
ln -s ~/Projects/vps-hardening ~/.claude/skills/vps-hardening
```

Then in Claude Code, invoke `/vps-hardening` (or just describe the task — Claude Code will pick up the skill from its frontmatter description). Claude will:

1. Run a read-only audit of the current server.
2. Map findings to controls in HARDENING.md.
3. Show you a tiered list of recommendations.
4. Walk you through changes one tier at a time, with safety rails (cloud-console check, two-session SSH pattern, sshd validation before restart).

The skill is opinionated about safety — it won't bundle multiple tiers, won't restart sshd without `sshd -t` succeeding, and won't bind sshd to a Tailscale IP without explicit confirmation that Tailscale is reliable on that host.

## Scope

- **Targets:** Debian / Ubuntu (tested on Ubuntu 24.04 LTS). Mostly portable to Debian 12+, Ubuntu 22.04+. Notes for RHEL-family inline where commands diverge.
- **Audience:** solo dev / small-team running 1–10 VPS instances. Personal projects, side-business infra, hobby services.
- **Out of scope:** enterprise compliance (CIS L2, STIG, PCI-DSS), centralised log shipping, HIDS at scale, K8s node hardening.

## Threat model in one paragraph

A public IPv4 address is constantly probed by automated bots looking for default-port SSH, weak passwords, exposed services, and known CVEs. This playbook makes those attacks impossible (key+TOTP auth, SSH on a private overlay, automatic patching) and contains the blast radius if a service-level vulnerability is ever exploited (UFW + AppArmor + sysctl). A determined targeted attacker can still find paths in; this isn't a state-actor playbook. It is a "make sure you're not the easy mark" playbook.

## Conventions

- Each control in HARDENING.md follows **What → Why → How → Verify** so it works as both a reference and an executable runbook.
- Code blocks are copy-paste ready. Where a command needs customisation, the placeholder is `<ANGLE-BRACKETS>`.
- Verification is always given — never trust a config change until you've confirmed the new behaviour.

## Contributing back to your own infra

This repo is meant to be a starting point. Fork it for your own use:
- Add controls specific to services you run (e.g. mail server hardening, database hardening).
- Tune the SSH crypto allowlist if you have legacy clients to support.
- Add provider-specific recovery notes (AWS SSM, Hetzner Rescue System, etc.).
