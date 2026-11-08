# Security

## Deployment model

- The application has no runtime dependency on an external cloud service or CDN.
- RouterOS credentials are supplied at runtime and must never be embedded in an image or committed to Git.
- Use a dedicated RouterOS user with only `read,api` permissions and restrict it to the container IP.
- Restrict dashboard access to trusted LAN networks. Never publish the dashboard or RouterOS API directly to the internet.
- Generate a unique TLS private key for each installation. Do not commit certificates containing a private key.
- Dashboard passwords are hashed with PBKDF2-SHA256. Sessions are server-side, expire automatically, and state-changing requests require a CSRF token.
- Apply memory limits to the RouterOS container. Collector failures are isolated from routing and packet forwarding.

## Sensitive files

The supplied `.gitignore` excludes databases, RouterOS exports and backups, `.env` files, private keys, certificates, container images and RouterOS packages. Always review `git status` and scan the staged snapshot before pushing.

## Reporting a vulnerability

Open a GitHub security advisory for the repository if private reporting is enabled. Avoid publishing working credentials, router exports, packet captures, database files, MAC addresses or internal hostnames in a public issue.
