"""
Main application file

Security features:
- CORS: only specific frontend origins may call the API from a browser,
  and only with the HTTP methods this API actually uses (GET, POST).
- Rate limiting: each IP address may make 10 requests per minute.
  Request 11 within the same minute gets 429 Too Many Requests.
"""

import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import items

app = FastAPI(title="Secure Items API")

# ---------- Rate limiting ----------
RATE_LIMIT = 10        # max requests...
WINDOW_SECONDS = 60    # ...per this many seconds, per IP

# NOTE: This counter lives in memory, so it resets when the server restarts
# and isn't shared across multiple server processes. A production app would
# store counts in something shared like Redis.
# { "127.0.0.1": deque([timestamp, timestamp, ...]) }
request_log: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    timestamps = request_log[client_ip]

    # Drop timestamps older than 60 seconds (sliding window)
    while timestamps and now - timestamps[0] > WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT:
        retry_after = int(WINDOW_SECONDS - (now - timestamps[0])) + 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Too Many Requests. Limit is 10 per minute."},
            headers={"Retry-After": str(retry_after)},
        )

    timestamps.append(now)
    return await call_next(request)

# ---------- CORS ----------
# Only these frontends may call the API from a browser. No "*" wildcard.
ALLOWED_ORIGINS = [
    "http://localhost:3000",   # e.g. a React dev server
    "http://127.0.0.1:5500",   # e.g. VS Code Live Server for an HTML page
]

# Middleware order matters: the middleware added LAST runs FIRST!
# CORS is added after the rate limiter so it wraps the outside, which means
# even 429 responses include CORS headers and browsers can read them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],       # only what this API actually uses
    allow_headers=["Content-Type"],
    allow_credentials=False,
)

# ---------- Routers ----------
app.include_router(items.router)


@app.get("/")
def root():
    return {"message": "Secure Items API is running"}