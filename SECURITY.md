# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, please report it responsibly.

Email: vojtech@pastyrik.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

## Scope

- Authentication bypass (collector token validation)
- Injection vulnerabilities in notification formatting
- Secret leakage in logs or error messages
- Protobuf deserialization issues

## Out of scope

- Denial of service via high alert volume (rate limiting is not implemented)
- Vulnerabilities in upstream dependencies (report to the respective projects)
