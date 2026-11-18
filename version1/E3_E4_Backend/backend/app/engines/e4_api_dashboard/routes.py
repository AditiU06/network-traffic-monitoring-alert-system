"""The REST API: every route lives under /api/v1."""
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Blueprint, current_app, g, jsonify, request

from . import security
from .errors import ApiError
from .schemas import LoginRequest, RunRequest, StatusRequest, parse
from .serializer import camelize

bp = Blueprint("api", __name__, url_prefix="/api/v1")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


def svc():
    return current_app.config["E3"]


def ok(data, status=200):
    return jsonify(camelize(data)), status


def auth(permission="view"):
    """Route guard: needs a valid Bearer token, and a role that allows `permission`."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise ApiError(401, "UNAUTHENTICATED", "Please log in.")
            user = svc().get_session_user(security.token_hash(header[7:]))
            if not user:
                raise ApiError(401, "UNAUTHENTICATED", "Your session has ended. Please log in again.")
            if permission not in security.PERMISSIONS.get(user["role_name"], set()):
                raise ApiError(403, "FORBIDDEN", "Your role is not allowed to do this.")
            g.user = user
            return fn(*a, **k)
        return wrapper
    return deco


def page_args():
    return {"page": request.args.get("page", 1), "size": request.args.get("size", 50)}


def _detect_log_type(file_path: Path) -> str:
    """Detects Zeek log type from #path header, fields, or filename."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(25):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line.startswith("#path"):
                    parts = line.split("\t")
                    if len(parts) > 1:
                        return parts[1].strip()
                elif line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    if "name" in fields and "addl" in fields:
                        return "weird"
                    elif "tunnel_type" in fields:
                        return "tunnel"
                    elif "percent_lost" in fields:
                        return "capture_loss"
                    elif "analyzer" in fields:
                        return "dpd"
                    elif "port_proto" in fields or ("host" in fields and "service" in fields):
                        return "known_services"
    except Exception:
        pass
    name = file_path.name.lower()
    for candidate in ("weird", "tunnel", "dpd", "capture_loss", "known_services", "known_hosts"):
        if candidate in name:
            return candidate
    return "conn"


@bp.get("/health")
def health():
    return ok({"status": "ok"})


# ---------- login ----------
@bp.post("/auth/login")
def login():
    body = parse(LoginRequest, request.get_json(silent=True))
    limiter = current_app.config["LIMITER"]
    if limiter.blocked(body.username):
        raise ApiError(429, "TOO_MANY_ATTEMPTS", "Too many wrong passwords. Try again in a few minutes.")
    user = svc().get_user_by_username(body.username)
    if not user or not user["is_active"] or not security.verify_password(body.password, user["password_hash"]):
        limiter.fail(body.username)
        raise ApiError(401, "BAD_CREDENTIALS", "Wrong username or password.")   # same message for both cases
    limiter.clear(body.username)
    token = security.new_token()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=current_app.config["SESSION_HOURS"])
    svc().create_session(svc().new_id(), user["user_id"], security.token_hash(token), now, expires)
    return ok({"token": token, "expires_at": expires.isoformat(),
               "user": {"username": user["username"], "full_name": user["full_name"], "role": user["role_name"],
                        "permissions": sorted(security.PERMISSIONS.get(user["role_name"], []))}})


@bp.post("/auth/logout")
@auth()
def logout():
    svc().revoke_session(g.user["session_id"])
    return ok({"status": "logged_out"})


@bp.get("/auth/me")
@auth()
def me():
    u = g.user
    return ok({"username": u["username"], "full_name": u["full_name"], "role": u["role_name"],
               "permissions": sorted(security.PERMISSIONS.get(u["role_name"], []))})


# ---------- runs & uploads ----------
@bp.get("/logs/files")
@auth()
def list_log_files():
    log_dir = current_app.config["LOG_DIR"]
    files = []
    if log_dir.is_dir():
        for p in sorted(log_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.is_file() and not p.name.startswith("."):
                files.append({
                    "fileName": p.name,
                    "sizeBytes": p.stat().st_size,
                    "modifiedAt": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
                })
    return ok({"files": files})


@bp.post("/logs/upload")
@auth("start_run")
def upload_log():
    if "file" not in request.files:
        raise ApiError(400, "NO_FILE", "Please select a log file to upload.")
    file = request.files["file"]
    if not file or not file.filename:
        raise ApiError(400, "EMPTY_FILE", "No file selected or file name is empty.")

    orig_name = Path(file.filename).name
    clean_name = re.sub(r"[^A-Za-z0-9._-]", "_", orig_name)
    if not clean_name or clean_name.startswith("."):
        clean_name = f"upload_{uuid.uuid4().hex[:8]}.log"

    log_dir = current_app.config["LOG_DIR"]
    log_dir.mkdir(parents=True, exist_ok=True)
    target_path = log_dir / clean_name
    file.save(target_path)

    run_immediately = request.form.get("runImmediately", "true").lower() in ("true", "1", "yes")
    mode = (request.form.get("mode") or "MULTITHREADED").upper()
    if mode not in ("SEQUENTIAL", "MULTITHREADED", "BENCHMARK"):
        mode = "MULTITHREADED"
    try:
        threads = int(request.form.get("threads", 4))
        if not (1 <= threads <= 16):
            threads = 4
    except (ValueError, TypeError):
        threads = 4

    detected_log_type = _detect_log_type(target_path)

    if run_immediately:
        run_id = svc().new_id()
        svc().save_processing_run(dict(
            run_id=run_id,
            initiated_by=g.user["user_id"],
            file_name=clean_name,
            log_type=detected_log_type,
            run_mode=mode,
            started_at=datetime.now(timezone.utc)
        ))
        current_app.config["PROCESSOR"].start(run_id, target_path, mode, threads)
        return ok({
            "runId": run_id,
            "fileName": clean_name,
            "status": "RUNNING",
            "mode": mode,
            "threads": threads
        }, 202)

    return ok({
        "fileName": clean_name,
        "sizeBytes": target_path.stat().st_size,
        "status": "UPLOADED"
    }, 200)


@bp.post("/runs")
@auth("start_run")
def start_run():
    body = parse(RunRequest, request.get_json(silent=True))
    if not SAFE_NAME.match(body.log_file) or body.log_file.startswith("."):
        raise ApiError(400, "BAD_FILE_NAME", "Give just the log file name, not a path.")
    path = (current_app.config["LOG_DIR"] / body.log_file)
    if not path.is_file():
        raise ApiError(404, "FILE_NOT_FOUND", "That log file was not found. Nothing was started.")
    detected_log_type = _detect_log_type(path)
    run_id = svc().new_id()
    svc().save_processing_run(dict(run_id=run_id, initiated_by=g.user["user_id"], file_name=body.log_file,
                                   log_type=detected_log_type, run_mode=body.mode, started_at=datetime.now(timezone.utc)))
    current_app.config["PROCESSOR"].start(run_id, path, body.mode, body.threads)
    return ok({"run_id": run_id, "status": "RUNNING"}, 202)


@bp.get("/runs")
@auth()
def runs():
    return ok(svc().list_runs(**page_args()))


@bp.get("/runs/<run_id>")
@auth()
def run_detail(run_id):
    run = svc().get_run(run_id)
    perf = svc().get_performance_results(run_id)
    return ok({**run, "metrics": perf["metrics"], "comparison": perf["comparison"]})


@bp.get("/benchmarks")
@auth()
def benchmarks():
    return ok(svc().list_benchmarks(**page_args()))


# ---------- logs (events) ----------
@bp.get("/logs")
@auth()
def logs():
    a = request.args
    return ok(svc().search_events(ip=a.get("ip"), source_ip=a.get("sourceIp"), destination_ip=a.get("destinationIp"),
                                  protocol=a.get("protocol"), run_id=a.get("runId"),
                                  from_ts=a.get("from"), to_ts=a.get("to"), **page_args()))


# ---------- alerts ----------
@bp.get("/alerts")
@auth()
def alerts():
    a = request.args
    return ok(svc().search_alerts(severity=a.get("severity"), status=a.get("status"), ip=a.get("ip"),
                                  run_id=a.get("runId"), rule_code=a.get("ruleCode"),
                                  from_ts=a.get("from"), to_ts=a.get("to"), **page_args()))


@bp.get("/alerts/<alert_id>")
@auth()
def alert_detail(alert_id):
    return ok(svc().get_alert(alert_id))


@bp.patch("/alerts/<alert_id>")
@auth("update_alert")
def alert_update(alert_id):
    body = parse(StatusRequest, request.get_json(silent=True))
    return ok(svc().update_alert_status(alert_id, body.status, g.user["user_id"]))


# ---------- dashboard ----------
@bp.get("/dashboard/summary")
@auth()
def summary():
    return ok(svc().get_dashboard_summary(request.args.get("runId")))
