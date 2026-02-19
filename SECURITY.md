# Security Policy

Pinchana DLP was built from the ground up with a zero-trust architecture to protect user session cookies and host infrastructure. We take the security of this project extremely seriously.

## Supported Versions

Currently, only the latest commit on the `main` branch is officially supported for security updates. 

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| `< 1.0` | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it privately. You can do this by:
1. Using [GitHub's Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository (if enabled).
2. Contacting the maintainers directly.

Please include the following in your report:
* A description of the vulnerability and its impact.
* Steps to reproduce the issue.
* Any potential mitigation or patch if you have one.

We will acknowledge receipt of your vulnerability report as soon as possible and strive to send you regular updates about our progress.

## Threat Model & Scope

When evaluating vulnerabilities, please consider our defined threat model.

### In Scope (Considered a Vulnerability)
* **API Compromise:** Any bug that allows an unauthenticated user to execute code on the API container or host.
* **Database Access:** Any bug that allows a Worker container or external user to access the `backend_net` or Redis database.
* **Container Escape:** Any bug that allows a compromised `yt-dlp`/`ffmpeg` process inside the Worker to break out of the Docker container and access the host machine.
* **Cryptographic Flaws:** Weaknesses in the X25519/AES-GCM implementation that would allow the API (or an eavesdropper) to decrypt user session cookies.
* **Lateral Movement:** A compromised Worker successfully attacking another active Worker container.

### Out of Scope (Not a Vulnerability)
* **Worker RCE via Media Files:** If a maliciously crafted media file exploits `ffmpeg` and achieves Remote Code Execution (RCE) *inside* the ephemeral Worker container, this is **expected behavior** and the system is functioning as designed. The Worker is an unprivileged, isolated, ephemeral sandbox specifically built to absorb this exact attack. (Unless the RCE leads to a container escape, which *is* in scope).
* **Denial of Service (DoS) via valid workloads:** While we set resource quotas, exhausting the host's resources by legitimately submitting hundreds of heavy `yt-dlp` jobs is an infrastructure scaling issue, not a security vulnerability.
* **yt-dlp parsing bugs:** Upstream bugs in `yt-dlp` that cause downloads to fail are not security issues.

## Security Best Practices for Operators

If you are hosting Pinchana DLP, ensure you:
1. **Change the Default Passwords:** Always change the `REDIS_PASSWORD` and `INTERNAL_TOKEN` in your `.env` file before deploying to production.
2. **Use a Reverse Proxy with TLS/SSL:** The API itself binds to HTTP. You **must** deploy it behind a reverse proxy (like Nginx, Traefik, or Caddy) that enforces HTTPS. Sending encrypted cookies over plain HTTP exposes the payload to network-level tampering.
3. **Keep Docker Updated:** The security of the ephemeral workers relies heavily on the Docker daemon's isolation capabilities. Keep your host OS and Docker engine up to date.
