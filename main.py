import time
import uuid
from statistics import mean
from typing import List, Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse

EMAIL = "24f2007613@ds.study.iitm.ac.in"
ALLOWED_ORIGIN = "https://dash-t3xuf4.example.com"

app = FastAPI()


# Middleware: add X-Request-ID and X-Process-Time on every response
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
    # Only your assigned allowed origin must receive ACAO; no wildcard
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN


@app.options("/stats")
async def stats_preflight(request: Request):
    # CORS preflight handler
    origin = request.headers.get("origin")
    response = Response(status_code=200)

    # Only echo ACAO for the allowed origin
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    # Middleware will still add X-Request-ID and X-Process-Time
    return response


@app.get("/stats")
async def get_stats(values: str, request: Request):
    origin = request.headers.get("origin")

    # Parse comma-separated integers
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
    avg = mean(nums)  # true mean

    result = {
        "email": EMAIL,
        "count": count,
        "sum": total,
        "min": min_val,
        "max": max_val,
        # mean within ±0.01 of true value
        "mean": round(avg, 4),
    }

    response = JSONResponse(content=result)
    set_origin_header(response, origin)
    return response