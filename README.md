# Pinchana DLP 🔒

**Secure, Isolated, and End-to-End Encrypted (E2EE) Media Downloader API**

Pinchana DLP (Data Loss Prevention) is a highly secure, container-isolated API wrapper around `yt-dlp`. It is specifically engineered to safely download media on behalf of a user using their authenticated session cookies, while mathematically guaranteeing that the central API server can *never* read or leak those cookies.

---

## 🛑 The Problem

Tools like `yt-dlp` often require valid session cookies to download age-restricted, private, or premium content (e.g., YouTube Premium, Netflix, Crunchyroll). 

In a traditional architecture, a user sends their plaintext cookies to a backend API, which passes them to `yt-dlp`. This creates massive security vulnerabilities:
1. **Man-in-the-Middle (Database)**: If the backend database (e.g., Redis) is compromised, all user session cookies are stolen.
2. **Container Escapes**: `yt-dlp` relies on `ffmpeg` to process media. Maliciously crafted video files have historically been used to trigger zero-day exploits in `ffmpeg` (Remote Code Execution). If an attacker compromises the `yt-dlp` process, they can steal the cookies of *other* users currently processing on the same server.

## 🛡️ The Pinchana DLP Solution

Pinchana DLP assumes the API server is fundamentally untrusted. It solves the aforementioned problems using **Zero-Trust Cryptography** and **Air-gapped Ephemeral Containers**.

### 1. End-to-End Encryption (E2EE)
Plaintext cookies **never** touch the API or the Redis database.
- The client and the isolated worker container perform an **Elliptic-Curve Diffie-Hellman (ECDH)** key exchange using `X25519`.
- The client derives a shared secret, salts it using **HKDF (SHA256)**, and encrypts the cookies using **AES-GCM**.
- The API only routes the *ciphertext*. Only the specific ephemeral worker holding the private key in its volatile RAM can decrypt the cookies.

### 2. Ephemeral, Non-Root Workers
Every single download job spins up a completely isolated, brand-new Docker container.
- The worker runs as an unprivileged, **non-root user**.
- It decrypts the cookies into a temporary directory (`tmpfs`/RAM-backed when possible), runs `yt-dlp`, and saves the final `.mp4`/`.webm` to a shared volume.
- Once the download completes (or fails), the container is **immediately destroyed**, permanently wiping the decrypted cookies and the private key from existence.

### 3. Network Air-Gapping

The system utilizes strict Docker bridge networks to prevent lateral movement.
- **`backend_net`**: Houses the API and Redis. It has `internal: true`, meaning absolutely zero outbound or inbound internet access.
- **`worker_net`**: Houses the API and the Ephemeral Workers. 
- **Result**: Even if an attacker achieves Remote Code Execution (RCE) inside a worker via a malicious video, they cannot ping Redis, they cannot read other jobs, and they are trapped as a non-root user in a container that will be killed in minutes.

### 4. NordVPN Integration (Optional)

To avoid IP-based rate limits and blocks from target sites, Pinchana DLP supports automatic NordVPN OVPN TCP profile rotation via the [Gluetun](https://github.com/qmcgaw/gluetun) proxy sidecar.

#### How It Works

1. **Gluetun Container**: A dedicated VPN container connects to NordVPN using your credentials and exposes an HTTP proxy on port `8888`.
2. **Worker Integration**: The worker detects the `PROXY_URL` environment variable and routes all `yt-dlp` traffic through the VPN proxy.
3. **Automatic Rotation**: Each job may use a different NordVPN server, helping avoid rate limits.

#### Configuration

Add your NordVPN credentials to your `.env` file:

```env
NORDVPN_USER=your_nordvpn_username
NORDVPN_PASS=your_nordvpn_password
NORDVPN_COUNTRY=US  # Optional: Preferred country (default: any)
PROXY_URL=http://vpn:8888  # Already set by default
```

### 5. Deno & yt-dlp-ejs Support

To handle modern JavaScript challenges (like those used by YouTube to block automated tools), the Pinchana worker includes **Deno** and the **yt-dlp-ejs** component.
- **Automated Solutions**: When `yt-dlp` encounters a JS challenge, it invokes Deno to solve it in real-time.
- **Remote Components**: The worker is configured to securely fetch the latest EJS logic from GitHub as needed.

### 6. Resource Quotas & Error Sanitization

- **Quotas**: Worker containers are strictly capped (e.g., `512MB` RAM, limited CPU quota). This prevents a single malicious or stuck `yt-dlp` job from causing a Denial of Service (DoS) by hogging host resources.
- **Sanitization**: Error messages reported to the API are automatically sanitized. Video IDs, full URLs, and internal job paths are redacted to prevent leaking sensitive information in logs.

---

## 🚀 Getting Started

### Prerequisites
* Docker & Docker Compose Plugin
* Python 3.10+ (for the client-side encryption example)

### Quick Start
We provide a setup script that creates your environment file, builds the isolated worker image, and starts the API in detached mode.

```bash
./start.sh
```

### Configuration (`.env`)
You can configure the deployment by editing the `.env` file generated by `start.sh`:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `REDIS_PASSWORD` | Secures the internal Redis database. | `YourSuperSecurePasswordHere123!` |
| `INTERNAL_TOKEN` | Secret used for API <-> Worker authentication. | `change_me_to_a_random_secret_string` |
| `API_BIND_HOST` | Local IP to bind the API to. Use `0.0.0.0` for public. | `127.0.0.1` |
| `API_PORT` | Port to expose the API on. | `8080` |
| `API_ROOT_PATH` | Set this if hosting behind a reverse proxy subpath (e.g., `/tool`). | *(empty)* |
| `HOST_DATA_DIR` | Absolute path on the host to store downloaded files. | `./data` |

---

## 🔐 How to Communicate with the API (Client Guide)

Because of the strict security model, submitting a job is not a simple REST `POST`. The client must participate in a cryptographic handshake.

### The Handshake Lifecycle:
1. **Allocate (`POST /v1/jobs/allocate`)**: The client asks the API for a worker. The API spins up a container. The container boots, generates a brand-new X25519 keypair, and registers its public key with the API.
2. **Encrypt**: The client generates its *own* ephemeral X25519 keypair, derives a shared AES-GCM secret using the worker's public key, and encrypts the raw Netscape cookies.
3. **Submit (`POST /v1/jobs/{job_id}/submit`)**: The client submits the video URL and the *encrypted* cookies to the API.
4. **Process**: The worker pulls the encrypted payload from the API, decrypts the cookies into memory, runs `yt-dlp`, saves the file, and exits (destroying itself).
5. **Download (`GET /v1/jobs/{job_id}/file`)**: The client polls the API for status updates and downloads the final file once `READY`.

### Python Client Example

Below is a complete, working example of a client script that securely encrypts your cookies, triggers a download, and saves the file.

```python
import os
import time
import base64
import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

API_URL = "http://127.0.0.1:8080"
VIDEO_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
COOKIES_TXT = """# Netscape HTTP Cookie File
.youtube.com	TRUE	/	TRUE	2145916800	SESSION_TOKEN	dummy_value
"""

def main():
    print("1. Allocating Job (waiting for worker to spin up...)")
    resp = requests.post(f"{API_URL}/v1/jobs/allocate")
    resp.raise_for_status()
    allocation = resp.json()
    
    job_id = allocation["jobId"]
    key_id = allocation["keyId"]
    worker_pub_b64 = allocation["workerPubKey"]
    print(f"   Job ID: {job_id}")

    print("2. Generating Client Keys & Encrypting Cookies...")
    # Generate ephemeral client keypair
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes_raw()

    # Load worker's public key
    worker_pub_bytes = base64.b64decode(worker_pub_b64)
    worker_pub_key = x25519.X25519PublicKey.from_public_bytes(worker_pub_bytes)

    # ECDH Key Agreement (X25519)
    shared_secret = client_priv.exchange(worker_pub_key)

    # Derive AES-GCM Key using HKDF
    nonce = os.urandom(16) # Used as both HKDF salt and AES-GCM nonce
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=b"pinchana-dlp-cookies",
    )
    aes_key = hkdf.derive(shared_secret)

    # Encrypt Cookies (AES-GCM)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, COOKIES_TXT.encode("utf-8"), None)

    print("3. Submitting Job...")
    payload = {
        "url": VIDEO_URL,
        "quality": "1080p", # Options: best, 1080p, 720p, 480p, 360p, audio
        "cookiesEnc": {
            "keyId": key_id,
            "clientPubKey": base64.b64encode(client_pub).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
    }
    requests.post(f"{API_URL}/v1/jobs/{job_id}/submit", json=payload).raise_for_status()

    print("4. Polling for Completion...")
    while True:
        status_resp = requests.get(f"{API_URL}/v1/jobs/{job_id}")
        status_data = status_resp.json()
        status = status_data["status"]
        
        if status == "READY":
            print(f"   Success! Downloading file...")
            download_resp = requests.get(f"{API_URL}/v1/jobs/{job_id}/file", stream=True)
            
            # Save file locally
            content_disp = download_resp.headers.get("content-disposition", "")
            filename = content_disp.split("filename=")[-1].strip('"') or f"{job_id}.mp4"
            
            with open(filename, "wb") as f:
                for chunk in download_resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"   File saved as {filename}")
            break
            
        elif status == "FAILED":
            print(f"   Job Failed: {status_data.get('error')}")
            break
            
        else:
            print(f"   Status: {status} (Progress: {status_data.get('progress', 0)}%)")
            time.sleep(2)

if __name__ == "__main__":
    main()
```
