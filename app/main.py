"""
Main application file

SECURITY MEASURES:

* CORS restricted to localhost:8501 and localhost:3000
* HTTP methods restricted to API-required methods (GET, POST)
* SlowAPI login limit: 5/minute
* POST/create limit: 20/minute
* GET/list limit: 60/minute
* Pydantic string length and numeric bounds
* Parameterized SQL queries
* HTML input sanitization
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.limiter import LIST_LIMIT, limiter
from app.routers import auth, items

app = FastAPI(title="Secure Items API")

# ---------- Rate limiting ----------
# All limits are set per endpoint with @limiter.limit(). See app/limiter.py.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------- CORS ----------
# Only these frontends may call the API from a browser. No "*" wildcard.
ALLOWED_ORIGINS = [
    "http://localhost:8501",   # e.g. a Streamlit app
    "http://localhost:3000",   # e.g. a React dev server
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],       # only what this API actually uses
    allow_headers=["Content-Type"],
    allow_credentials=False,
)

# ---------- Routers ----------
app.include_router(auth.router)
app.include_router(items.router)


@app.get("/")
@limiter.limit(LIST_LIMIT)
def root(request: Request, response: Response):
    return {"message": "Secure Items API is running"}
