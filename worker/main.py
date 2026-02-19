import os
import sys
import time
import json
import base64
import tempfile
import shutil
import subprocess
import re
import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

JOB_ID = os.environ["JOB_ID"]
API_URL = os.environ["API_URL"].rstrip("/")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
INTERNAL_TOKEN = os.environ["INTERNAL_TOKEN"]
PROXY_URL = os.environ.get("VPN_PROXY_URL")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def report(path: str, payload: dict):
    try:
        headers = {"x-internal-token": INTERNAL_TOKEN}
        requests.post(f"{API_URL}{path}", json=payload, headers=headers, timeout=5)
    except Exception as e:
        print(f"Failed to report to {path}: {e}", file=sys.stderr)


def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"pinchana-dlp-cookies",
    )
    return hkdf.derive(shared_secret)


def decrypt_cookies(enc: dict, worker_private: x25519.X25519PrivateKey) -> bytes:
    client_pub = x25519.X25519PublicKey.from_public_bytes(b64d(enc["clientPubKey"]))
    shared = worker_private.exchange(client_pub)
    nonce = b64d(enc["nonce"])
    key = derive_aes_key(shared, salt=nonce)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, b64d(enc["ciphertext"]), None)


def sanitize_error(text: str) -> str:
    text = re.sub(r"\[[a-zA-Z0-9]+\] [a-zA-Z0-9_-]{11}:", "[site] <redacted>:", text)
    text = re.sub(r"https?://\S+", "<url_redacted>", text)
    text = re.sub(
        r"/data/jobs/[a-f0-9-]{36}/", "/data/jobs/<job_id>/", text
    )
    return text


def monitor_process(proc, job_id):
    progress_pattern = re.compile(r"\[download\]\s+(\d+\.\d+)%")
    last_report = 0
    last_lines = []

    for line in iter(proc.stdout.readline, ""):
        if not line:
            break

        line = line.strip()
        print(line)
        last_lines.append(line)
        if len(last_lines) > 5:
            last_lines.pop(0)

        match = progress_pattern.search(line)
        if match:
            percent = float(match.group(1))
            now = time.time()
            if now - last_report > 2.0:
                report(
                    f"/internal/jobs/{job_id}/progress",
                    {"stage": "downloading", "progress": percent, "raw": line},
                )
                last_report = now

    return last_lines


def run():
    print(f"Starting worker for job {JOB_ID}")

    worker_priv = x25519.X25519PrivateKey.generate()
    worker_pub = worker_priv.public_key().public_bytes_raw()
    key_id = f"wk-{JOB_ID}"
    expires_at = int(time.time()) + 300

    report(
        "/internal/workers/register",
        {
            "jobId": JOB_ID,
            "keyId": key_id,
            "workerPubKey": b64e(worker_pub),
            "expiresAt": expires_at,
        },
    )

    payload = None
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            headers = {"x-internal-token": INTERNAL_TOKEN}
            resp = requests.get(
                f"{API_URL}/internal/jobs/{JOB_ID}/payload", headers=headers, timeout=10
            )
            if resp.status_code == 200:
                payload = resp.json()
                break
        except Exception as e:
            print(f"Polling error: {e}", file=sys.stderr)
        time.sleep(1)

    if not payload:
        report(
            f"/internal/jobs/{JOB_ID}/fail",
            {"error": "No payload received within timeout"},
        )
        sys.exit(1)

    cookies_path = None
    tmpdir = None

    try:
        report(
            f"/internal/jobs/{JOB_ID}/progress",
            {"stage": "decrypting", "progress": 0.0},
        )

        try:
            cookies_bytes = decrypt_cookies(payload["cookiesEnc"], worker_priv)
        except Exception as e:
            report(
                f"/internal/jobs/{JOB_ID}/fail",
                {"error": f"Decryption failed: {str(e)}", "stage": "decrypt_failed"},
            )
            sys.exit(1)

        tmpdir = tempfile.mkdtemp(prefix=f"job-{JOB_ID}-")
        cookies_path = os.path.join(tmpdir, "cookies.txt")
        with open(cookies_path, "wb") as f:
            f.write(cookies_bytes)
        os.chmod(cookies_path, 0o600)

        out_dir = os.path.join(DATA_DIR, "jobs", JOB_ID)
        os.makedirs(out_dir, exist_ok=True)
        out_tpl = os.path.join(out_dir, "%(title).200s.%(ext)s")

        report(
            f"/internal/jobs/{JOB_ID}/progress",
            {"stage": "starting_download", "progress": 0.0},
        )

        cmd = [
            sys.executable, "-m", "yt_dlp",
            "--cookies",
            cookies_path,
            "-f",
            payload.get("format", "bv*+ba/b"),
            "-o",
            out_tpl,
            "--no-playlist",
            "--newline",
            "--no-colors",
            "--no-write-thumbnail",
            "--no-write-info-json",
            "--js-runtimes", "deno",
            "--remote-components", "ejs:github",
        ]

        if PROXY_URL:
            cmd.extend(["--proxy", PROXY_URL])

        cmd.append(payload["url"])

        log_cmd = list(cmd)
        try:
            cookie_idx = log_cmd.index("--cookies")
            log_cmd[cookie_idx + 1] = "<redacted>"
        except ValueError:
            pass
        print(f"Running command: {' '.join(log_cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        last_lines = monitor_process(proc, JOB_ID)

        return_code = proc.wait()

        if return_code != 0:
            error_msg = f"yt-dlp exited with code {return_code}"
            if last_lines:
                error_msg += ": " + " | ".join(last_lines)
            report(
                f"/internal/jobs/{JOB_ID}/fail",
                {"error": sanitize_error(error_msg)},
            )
            sys.exit(return_code)

        files = [os.path.join(out_dir, f) for f in os.listdir(out_dir)]
        files = [p for p in files if os.path.isfile(p)]
        if not files:
            report(
                f"/internal/jobs/{JOB_ID}/fail",
                {"error": "Download finished but no file found"},
            )
            return

        path = max(files, key=os.path.getsize)
        size = os.path.getsize(path)

        report(
            f"/internal/jobs/{JOB_ID}/complete",
            {"path": path, "size": size, "mime": "application/octet-stream"},
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        report(f"/internal/jobs/{JOB_ID}/fail", {"error": sanitize_error(str(e))})
        sys.exit(1)
    finally:
        if cookies_path and os.path.exists(cookies_path):
            try:
                os.remove(cookies_path)
            except:
                pass
        if tmpdir and os.path.exists(tmpdir):
            try:
                shutil.rmtree(tmpdir)
            except:
                pass


if __name__ == "__main__":
    run()
