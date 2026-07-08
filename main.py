import time
import uuid
from statistics import mean
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

# ===== Question 1: CORS-Aware Metrics API =====

EMAIL = "24f2007613@ds.study.iitm.ac.in"
ALLOWED_ORIGIN = "https://dash-t3xuf4.example.com"

app = FastAPI()


@app.middleware("http")
async def add_observability_headers(request: Request, call_next):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    response: Response = await call_next(request)

    process_time = time.perf_counter() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response


def set_origin_header(response: Response, origin: Optional[str]):
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN


@app.options("/stats")
async def stats_preflight(request: Request):
    origin = request.headers.get("origin")
    response = Response(status_code=200)

    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
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
    set_origin_header(response, origin)
    return response


# ===== Question 2: OAuth 2.0 / OIDC Token Verification Service =====

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
async def verify(body: dict):
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