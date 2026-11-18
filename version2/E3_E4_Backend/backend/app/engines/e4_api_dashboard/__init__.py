import logging
from pathlib import Path

from flask import Flask, send_from_directory

from .errors import register_error_handlers
from .processor import DemoProcessor
from .routes import bp
from .security import LoginLimiter

STATIC = Path(__file__).with_name("static")


def create_app(service, log_dir="logs", processor=None, session_hours=8):
    """service = the E3 DataManagementService; processor = E1 PipelineCoordinator (or explicit demo stand-in)."""
    app = Flask(__name__, static_folder=None)
    if processor is None:
        # Require production PipelineCoordinator by default; do NOT silently mask with DemoProcessor
        from Integration.Orchestration import PipelineCoordinator
        processor = PipelineCoordinator(service)
    elif processor == "demo":
        processor = DemoProcessor(service)

    app.config.update(E3=service, LOG_DIR=Path(log_dir), SESSION_HOURS=session_hours,
                      PROCESSOR=processor, LIMITER=LoginLimiter(),
                      MAX_CONTENT_LENGTH=256 * 1024 * 1024)   # Support log uploads up to 256MB
    app.json.sort_keys = False                                 # keep severity order CRITICAL, HIGH, MEDIUM, LOW
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO)
    register_error_handlers(app)
    app.register_blueprint(bp)

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:"
        if resp.mimetype == "application/json":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app
