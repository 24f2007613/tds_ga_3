from fastapi import FastAPI, Request, Response, HTTPException
import time
import uuid
from typing import Optional

ALLOWED_ORIGIN = "https://dash-t3xuf4.example.com"
EMAIL = "24f2007613@ds.study.iitm.ac.in"

app = FastAPI()


@app.middleware("http")
async def add_request_id_and_timing(request: Request, call_next):
    start = time.time()
    request_id = str(uuid.uuid4())

    # Preflight for /stats
    if request.method == "OPTIONS" and request.url.path == "/stats":
        origin = request.headers.get("origin")
        response = Response(status_code=200)
        if origin == ALLOWED_ORIGIN:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{time.time() - start:.6f}"
        return response

    # Normal request
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN

    process_time = time.time() - start
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response


@app.get("/stats")
async def get_stats(values: Optional[str] = None):
    if not values:
        raise HTTPException(status_code=400, detail="values query parameter required")

    try:
        nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(status_code=400, detail="values must be comma-separated integers")

    if not nums:
        raise HTTPException(status_code=400, detail="no numbers provided")

    count = len(nums)
    total = sum(nums)
    min_val = min(nums)
    max_val = max(nums)
    mean_val = total / count

    return {
        "email": EMAIL,
        "count": count,
        "sum": total,
        "min": min_val,
        "max": max_val,
        "mean": round(mean_val, 4)
    }