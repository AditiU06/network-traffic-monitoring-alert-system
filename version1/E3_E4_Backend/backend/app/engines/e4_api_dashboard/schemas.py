"""Checks what comes IN to the API (Pydantic). Anything wrong becomes a 400 with a plain message."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import ApiError


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["SEQUENTIAL", "MULTITHREADED", "BENCHMARK"]
    threads: int = Field(ge=1, le=16)
    log_file: str = Field(alias="logFile", min_length=1, max_length=200)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class StatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


def parse(model, data):
    if not isinstance(data, dict):
        raise ApiError(400, "BAD_REQUEST", "Send a JSON object.")
    if isinstance(data.get("mode"), str):
        data = {**data, "mode": data["mode"].upper()}
    if isinstance(data.get("status"), str):
        data = {**data, "status": data["status"].upper()}
    try:
        return model.model_validate(data)
    except ValidationError as ex:
        first = ex.errors()[0]
        field = ".".join(str(x) for x in first["loc"]) or "request"
        if field == "threads":
            raise ApiError(400, "INVALID_THREADS", "Thread count must be a whole number from 1 to 16.") from None
        raise ApiError(400, "BAD_REQUEST", f"{field}: {first['msg']}") from None
