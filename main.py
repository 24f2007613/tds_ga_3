import time
import uuid
from statistics import mean
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from jose import jwt, JWTError


EMAIL = "24f2007613@ds.study.iitm.ac.in"

app = FastAPI()


# ===== Common middleware: all endpoints =====
@app.middleware("http")
async def add_observability_headers(request: Request, call_next):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    response: Response = await call_next(request)

    process_time = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response


# ===== Q1: CORS-Aware Metrics API =====
ALLOWED_ORIGIN_Q1 = "https://dash-t3xuf4.example.com"


def set_origin_q1(response: Response, origin: Optional[str]):
    if origin == ALLOWED_ORIGIN_Q1:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN_Q1


@app.options("/stats")
async def stats_preflight(request: Request):
    origin = request.headers.get("origin")
    response = Response(status_code=200)

    if origin == ALLOWED_ORIGIN_Q1:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN_Q1
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    return response


@app.get("/stats")
async def get_stats(values: str, request: Request):
    origin = request.headers.get("origin")

    try:
        nums: List[int] = [int(x) for x in values.split(",") if x.strip() != ""]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid integer in values")

    if not nums:
        raise HTTPException(status_code=400, detail="No values provided")

    count = len(nums)
    total = sum(nums)
    min_val = min(nums)
    max_val = max(nums)
    avg = mean(nums)

    result = {
        "email": EMAIL,
        "count": count,
        "sum": total,
        "min": min_val,
        "max": max_val,
        "mean": round(avg, 4),
    }

    response = JSONResponse(content=result)
    set_origin_q1(response, origin)
    return response


# ===== Q2: OAuth 2.0 / OIDC Token Verification =====
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-mz0olf8p.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ALGORITHM = "RS256"


def verify_token(token: str):
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except JWTError:
        return None

    exp = payload.get("exp")
    if exp is None:
        return None

    now_ts = datetime.now(timezone.utc).timestamp()
    if exp < now_ts:
        return None

    return payload


@app.post("/verify")
async def verify(body: Dict[str, Any]):
    token = body.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing",
        )

    payload = verify_token(token)
    if payload is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"valid": False},
        )

    email = payload.get("email")
    sub = payload.get("sub")
    aud = payload.get("aud")

    return {
        "valid": True,
        "email": email,
        "sub": sub,
        "aud": aud,
    }


# ===== Q3: Resolve 12-Factor Config Precedence =====
# 1. defaults (hardcoded)
DEFAULT_CONFIG = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}

# 2. config.development.yaml
CONFIG_YAML = {
    "workers": 6,
}

# 3. .env file layer (simulated — your assigned value)
ENV_FILE_VARS = {
    "api_key": "key-7nbh42ur3z",
}

# 4. OS env vars with APP_* prefix (simulated — your assigned value)
OS_ENV_VARS = {
    "workers": 1,
}


def load_config_layers() -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()

    # config.development.yaml layer
    cfg.update(CONFIG_YAML)

    # .env layer (simulated assigned value)
    cfg["api_key"] = ENV_FILE_VARS["api_key"]

    # OS env vars with APP_* prefix (simulated assigned value) — overrides YAML's workers
    cfg.update(OS_ENV_VARS)

    return cfg


def coerce_types(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = cfg.copy()

    # port, workers -> int
    out["port"] = int(out.get("port", 8000))
    out["workers"] = int(out.get("workers", 1))

    # debug -> bool (true/1/yes/on)
    raw_debug = str(out.get("debug", "false")).lower()
    out["debug"] = raw_debug in ("true", "1", "yes", "on")

    # log_level -> string
    out["log_level"] = str(out.get("log_level", "info"))

    # api_key masked always
    out["api_key"] = "****"

    return out


@app.get("/effective-config")
async def effective_config(request: Request):
    cfg = load_config_layers()

    # Read all ?set=key=value overrides from query params (CLI layer — highest precedence)
    set_params = request.query_params.getlist("set")
    for item in set_params:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "port":
            try:
                cfg["port"] = int(value)
            except ValueError:
                pass
        elif key == "workers":
            try:
                cfg["workers"] = int(value)
            except ValueError:
                pass
        elif key == "debug":
            cfg["debug"] = value
        elif key == "log_level":
            cfg["log_level"] = value
        elif key == "api_key":
            cfg["api_key"] = value
        else:
            cfg[key] = value

    final_cfg = coerce_types(cfg)

    # CORS: allow exam page to call this endpoint
    response = JSONResponse(content=final_cfg)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response