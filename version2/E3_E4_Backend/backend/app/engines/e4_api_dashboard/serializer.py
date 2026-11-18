"""Turns database-style names (run_id) into the API's names (runId)."""


def camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w.capitalize() for w in rest)


def camelize(value):
    if isinstance(value, dict):
        return {camel(k): camelize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [camelize(v) for v in value]
    return value
