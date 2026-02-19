import os
import time
import uuid
import json
import logging
import threading
import shutil
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import redis
import docker
import yt_dlp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATA_DIR = os.getenv("DATA_DIR", "/data")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "pinchana-worker:latest")
WORKER_NETWORK = os.getenv("WORKER_NETWORK", None)
API_PUBLIC_URL = os.getenv("API_PUBLIC_URL", "http://api:8080")
VPN_PROXY_URL = os.getenv("VPN_PROXY_URL", None)
JOB_KEY_TTL_SECONDS = int(os.getenv("JOB_KEY_TTL_SECONDS", "3600"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "600"))
MAX_JOB_AGE_SECONDS = int(os.getenv("MAX_JOB_AGE_SECONDS", "3600"))
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", str(uuid.uuid4()))
if not os.getenv("INTERNAL_TOKEN"):
    logger.warning(
        "INTERNAL_TOKEN not set! Using random token. Workers will fail if API restarts."
    )
MAX_CONCURRENT_WORKERS = int(os.getenv("MAX_CONCURRENT_WORKERS", "10"))
API_ROOT_PATH = os.getenv("API_ROOT_PATH", "")

try:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    logger.info(f"Connected to Redis at {REDIS_URL}")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {e}")
    raise

try:
    dc = docker.from_env()
    logger.info("Connected to Docker socket")
except Exception as e:
    logger.error(f"Failed to connect to Docker: {e}")
    raise


def job_key(job_id: str, suffix: str) -> str:
    return f"job:{job_id}:{suffix}"


def verify_internal_token(x_internal_token: str = Header(...)):
    if x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid internal token")


def cleanup_old_jobs():
    """Background task to remove old job files."""
    logger.info("Running cleanup task...")
    try:
        if os.path.exists(JOBS_DIR):
            now = time.time()
            for job_id in os.listdir(JOBS_DIR):
                job_path = os.path.join(JOBS_DIR, job_id)
                if os.path.isdir(job_path):
                    try:
                        stat = os.stat(job_path)
                        if now - stat.st_mtime > MAX_JOB_AGE_SECONDS:
                            logger.info(f"Cleaning up expired job: {job_id}")
                            shutil.rmtree(job_path)
                    except Exception as e:
                        logger.error(f"Error cleaning job {job_id}: {e}")
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(JOBS_DIR, exist_ok=True)
    stop_event = threading.Event()

    def loop():
        while not stop_event.is_set():
            cleanup_old_jobs()
            time.sleep(CLEANUP_INTERVAL_SECONDS)

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    yield

    stop_event.set()
    t.join(timeout=2)


app = FastAPI(lifespan=lifespan, title="Pinchana DLP API", root_path=API_ROOT_PATH)


class AllocateResponse(BaseModel):
    jobId: str
    keyId: str
    workerPubKey: str
    expiresAt: int


class WorkerRegisterRequest(BaseModel):
    jobId: str
    keyId: str
    workerPubKey: str
    expiresAt: int


class SubmitRequest(BaseModel):
    url: str
    quality: str = "best"
    format: str = None
    cookiesEnc: dict


@app.get("/health")
def health_check():
    return {"status": "ok", "redis": r.ping(), "docker": dc.ping()}


@app.post("/v1/jobs/allocate", response_model=AllocateResponse)
def allocate_job():
    try:
        containers = dc.containers.list(filters={"name": "worker-"})
        active_workers = len(containers)
    except Exception:
        logger.error("Failed to list containers for concurrency check")
        active_workers = 0

    if active_workers >= MAX_CONCURRENT_WORKERS:
        raise HTTPException(503, "Too many active jobs, please try again later")

    job_id = str(uuid.uuid4())
    logger.info(f"Allocating job {job_id}")

    r.set(
        job_key(job_id, "status"),
        json.dumps({"status": "ALLOCATED"}),
        ex=JOB_KEY_TTL_SECONDS,
    )

    job_dir = os.path.join(JOBS_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)
    os.chmod(job_dir, 0o777)

    env = {
        "JOB_ID": job_id,
        "API_URL": API_PUBLIC_URL,
        "DATA_DIR": "/data",
        "INTERNAL_TOKEN": INTERNAL_TOKEN,
        "VPN_PROXY_URL": VPN_PROXY_URL,
    }

    host_data_dir = os.getenv("HOST_DATA_DIR", os.getcwd() + "/data")

    volumes = {
        host_data_dir: {"bind": "/data", "mode": "rw"},
    }

    kwargs = {
        "auto_remove": True,
        "mem_limit": "512m",
        "cpu_period": 100000,
        "cpu_quota": 50000,
        "name": f"worker-{job_id}",
    }
    if WORKER_NETWORK:
        kwargs["network"] = WORKER_NETWORK

    try:
        container = dc.containers.run(
            WORKER_IMAGE,
            detach=True,
            environment=env,
            volumes=volumes,
            **kwargs,
        )
        r.set(job_key(job_id, "container_id"), container.id, ex=JOB_KEY_TTL_SECONDS)

    except docker.errors.ImageNotFound:
        logger.error(f"Worker image {WORKER_IMAGE} not found")
        raise HTTPException(500, f"Worker image '{WORKER_IMAGE}' not found.")
    except Exception as e:
        logger.error(f"Failed to spawn worker for {job_id}: {e}")
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(500, "Failed to spawn worker")

    deadline = time.time() + 10.0
    while time.time() < deadline:
        reg = r.get(job_key(job_id, "worker_reg"))
        if reg:
            data = json.loads(reg)
            logger.info(f"Job {job_id} allocated successfully")
            return AllocateResponse(
                jobId=job_id,
                keyId=data["keyId"],
                workerPubKey=data["workerPubKey"],
                expiresAt=data["expiresAt"],
            )
        time.sleep(0.1)

    logger.warning(f"Job {job_id} timed out waiting for worker registration")
    try:
        c = dc.containers.get(f"worker-{job_id}")
        c.kill()
    except:
        pass

    shutil.rmtree(job_dir, ignore_errors=True)
    raise HTTPException(504, "Worker did not register in time")


@app.post("/internal/workers/register", dependencies=[Depends(verify_internal_token)])
def worker_register(req: WorkerRegisterRequest):
    logger.info(f"Worker registered for job {req.jobId}")

    if req.expiresAt < time.time():
        raise HTTPException(400, "Key already expired")

    r.set(
        job_key(req.jobId, "worker_reg"), req.model_dump_json(), ex=JOB_KEY_TTL_SECONDS
    )
    r.set(job_key(req.jobId, "keyId"), req.keyId, ex=JOB_KEY_TTL_SECONDS)
    r.set(job_key(req.jobId, "workerPubKey"), req.workerPubKey, ex=JOB_KEY_TTL_SECONDS)
    r.set(job_key(req.jobId, "expiresAt"), req.expiresAt, ex=JOB_KEY_TTL_SECONDS)

    return {"ok": True}


@app.post("/v1/jobs/{job_id}/submit")
def submit_job(job_id: str, req: SubmitRequest):
    key_id = r.get(job_key(job_id, "keyId"))
    if not key_id:
        raise HTTPException(404, "Unknown jobId or expired")
    if req.cookiesEnc.get("keyId") != key_id:
        raise HTTPException(400, "keyId mismatch")

    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "simulate": True,
    }
    if VPN_PROXY_URL:
        ydl_opts["proxy"] = VPN_PROXY_URL

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.extract_info(req.url, download=False)
    except Exception as e:
        logger.warning(f"Initial validation failed for {req.url}: {e} (might need cookies)")
        pass

    logger.info(f"Job {job_id} submitted")

    quality_map = {
        "best": "bv*+ba/b",
        "1080p": "bestvideo[height<=1080]+bestaudio/best[height<=1080]",
        "720p": "bestvideo[height<=720]+bestaudio/best[height<=720]",
        "480p": "bestvideo[height<=480]+bestaudio/best[height<=480]",
        "360p": "bestvideo[height<=360]+bestaudio/best[height<=360]",
        "audio": "bestaudio/best",
    }
    final_format = req.format or quality_map.get(req.quality, "bv*+ba/b")

    payload = {
        "jobId": job_id,
        "url": req.url,
        "format": final_format,
        "cookiesEnc": req.cookiesEnc,
    }
    r.set(job_key(job_id, "payload"), json.dumps(payload), ex=JOB_KEY_TTL_SECONDS)
    r.set(
        job_key(job_id, "status"),
        json.dumps({"status": "QUEUED"}),
        ex=JOB_KEY_TTL_SECONDS,
    )
    return {"jobId": job_id, "status": "QUEUED"}


@app.get(
    "/internal/jobs/{job_id}/payload", dependencies=[Depends(verify_internal_token)]
)
def worker_get_payload(job_id: str):
    key = job_key(job_id, "payload")
    payload = r.get(key)
    if not payload:
        raise HTTPException(404, "No payload yet")

    r.delete(key)
    return json.loads(payload)


@app.post(
    "/internal/jobs/{job_id}/progress", dependencies=[Depends(verify_internal_token)]
)
def worker_progress(job_id: str, body: dict):
    r.set(
        job_key(job_id, "status"),
        json.dumps({"status": "RUNNING", **body}),
        ex=JOB_KEY_TTL_SECONDS,
    )
    return {"ok": True}


@app.post(
    "/internal/jobs/{job_id}/complete", dependencies=[Depends(verify_internal_token)]
)
def worker_complete(job_id: str, body: dict):
    logger.info(f"Job {job_id} completed. Path: {body.get('path')}")
    r.set(
        job_key(job_id, "status"),
        json.dumps({"status": "READY", **body}),
        ex=JOB_KEY_TTL_SECONDS,
    )
    return {"ok": True}


@app.post("/internal/jobs/{job_id}/fail", dependencies=[Depends(verify_internal_token)])
def worker_fail(job_id: str, body: dict):
    logger.error(f"Job {job_id} failed: {body.get('error')}")
    r.set(
        job_key(job_id, "status"),
        json.dumps({"status": "FAILED", **body}),
        ex=JOB_KEY_TTL_SECONDS,
    )
    return {"ok": True}


@app.get("/v1/jobs/{job_id}")
def job_status(job_id: str):
    s = r.get(job_key(job_id, "status"))
    if not s:
        raise HTTPException(404, "Unknown jobId or expired")
    return json.loads(s)


@app.get("/v1/jobs/{job_id}/file")
def job_file(job_id: str):
    s = r.get(job_key(job_id, "status"))
    if not s:
        raise HTTPException(404, "Unknown jobId or expired")
    st = json.loads(s)
    if st.get("status") != "READY":
        raise HTTPException(409, "Not ready")

    path = st.get("path")
    if not path or not os.path.exists(path):
        raise HTTPException(404, "File missing")

    filename = os.path.basename(path)
    return FileResponse(path, filename=filename, media_type="application/octet-stream")
