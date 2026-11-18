"""One error shape for the whole API:  { "error": { "code": "...", "message": "..." } }"""
import logging

from flask import jsonify

from app.engines.e3_data_management import (AlertNotFound, E3Error, InvalidFilterError, InvalidInput,
                                            QueryTimeout, RunNotFound)

log = logging.getLogger("e4")


class ApiError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


def _body(status, code, message):
    return jsonify({"error": {"code": code, "message": message}}), status


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def _api(e): return _body(e.status, e.code, e.message)

    @app.errorhandler(InvalidInput)
    def _bad(e): return _body(400, "BAD_REQUEST", str(e))

    @app.errorhandler(InvalidFilterError)
    def _filter(e): return _body(400, "BAD_FILTER", str(e))

    @app.errorhandler(RunNotFound)
    def _run(e): return _body(404, "RUN_NOT_FOUND", "That run does not exist.")

    @app.errorhandler(AlertNotFound)
    def _alert(e): return _body(404, "ALERT_NOT_FOUND", "That alert does not exist.")

    @app.errorhandler(QueryTimeout)
    def _timeout(e): return _body(504, "TIMEOUT", "The search took too long. Try a narrower filter.")

    @app.errorhandler(E3Error)
    def _e3(e): return _body(500, "DATA_ERROR", "The data layer could not complete the request.")

    @app.errorhandler(404)
    def _404(e): return _body(404, "NOT_FOUND", "No such endpoint.")

    @app.errorhandler(405)
    def _405(e): return _body(405, "METHOD_NOT_ALLOWED", "That method is not allowed here.")

    @app.errorhandler(Exception)
    def _any(e):
        log.exception("unexpected error")          # details go to the server log only
        return _body(500, "INTERNAL_ERROR", "Something went wrong on the server.")
