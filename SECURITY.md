# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities by emailing **v.stryy@xeonerix.xyz** with the subject line **[bgpeek security]**.

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected version(s) and deployment method (Docker / pip)
- Potential impact

## Response timeline

- **Acknowledgment:** within 7 days
- **Initial assessment:** within 14 days
- **Fix and disclosure:** we aim to release a patch within 90 days of confirmed vulnerabilities

## Scope

The following are in scope:

- Authentication and authorization bypass
- SQL injection, command injection, SSRF
- Credential exposure or leakage
- Privilege escalation between roles
- SSH key or password disclosure

The following are out of scope:

- Denial of service (rate limiting is configurable)
- Issues in dependencies (report upstream, but let us know)
- Social engineering

## Credit

We are happy to credit security researchers in release notes and the changelog upon request.
