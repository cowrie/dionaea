# Security Policy

## Important Context

Dionaea is a **honeypot** — it is designed to be attacked. It intentionally exposes
vulnerable-looking services to attract and study malicious activity.

That said, vulnerabilities in dionaea itself (e.g., allowing an attacker to escape
the honeypot and compromise the host) are serious issues.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them via [GitHub Security Advisories](https://github.com/cowrie/dionaea/security/advisories/new).

Include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You should receive a response within 7 days.

## Scope

Issues we care about:

- Host compromise (sandbox/chroot escape)
- Remote code execution on the honeypot host
- Privilege escalation beyond the dionaea process
- Denial of service against the honeypot itself (not the emulated services)
- Information disclosure of host system details

Issues that are **out of scope** (by design):

- Vulnerabilities in the emulated services (that's the point)
- Weak cryptography in honeypot-facing TLS (intentional)
- Attacks against the fake services themselves
