# Secure Items API

A FastAPI project that demonstrates core API security practices: CORS restrictions, rate limiting, input validation, HTML sanitization, and parameterized SQL queries. Items are stored in a local SQLite database.

## Security measures

| Measure | Details |
|---|---|
| CORS | Only `localhost:8501` and `localhost:3000` are allowed, using `GET` and `POST` |
| Rate limiting | SlowAPI limits per IP address (see the table below) |
| Input validation | Pydantic length limits on strings and bounds on numbers |
| HTML sanitization | Tags and script contents are removed before saving, which helps prevent stored XSS |
| SQL injection prevention | All queries use `?` placeholders |
| Password handling | Passwords are hashed with PBKDF2 and compared in constant time |

## Endpoints

| Method | Path | Description | Rate limit |
|---|---|---|---|
| `GET` | `/` | Check that the API is running | 60/minute |
| `POST` | `/login` | Log in as the demo user | 5/minute |
| `GET` | `/items` | List items, with optional `search`, `limit`, and `offset` | 60/minute |
| `POST` | `/items` | Create an item | 20/minute |

Requests over a limit return `429 Too Many Requests`.

### Input limits

| Field | Limit |
|---|---|
| `email` | 3-254 characters, valid email format |
| `password` | 8-128 characters |
| `name` | 1-100 characters |
| `description` | Optional, up to 1,000 characters |
| `search` | Optional, 1-100 characters |
| `limit` | 1-100, default 100 |
| `offset` | 0-1,000,000, default 0 |

Input outside these limits returns `422 Unprocessable Entity`.

## Project structure

```
FASTAPI_Security_Basics/
├── app/
│   ├── main.py            # App setup, CORS, security summary
│   ├── limiter.py         # Shared SlowAPI limiter and limits
│   └── routers/
│       ├── auth.py        # POST /login
│       └── items.py       # Items endpoints, validation, sanitization
├── evidence/
│   └── rate_limit_test_output.txt
├── tests/
│   └── test_security.py
└── requirements.txt
```

## Setup

These commands are for Windows PowerShell. Run them from the project folder.

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run the API

```powershell
uvicorn app.main:app --reload
```

Then open the interactive docs at http://127.0.0.1:8000/docs.

To try the login, send this to `POST /login`:

```json
{"email": "demo@example.com", "password": "demo-password"}
```

The first five attempts in a minute return `200`, and the sixth returns `429`.

## Run the tests

```powershell
python -m pytest -v -s
```

The suite covers rate limits, input limits, sanitization, SQL injection, and CORS. Sample output, including six rapid login attempts, is in [`evidence/rate_limit_test_output.txt`](evidence/rate_limit_test_output.txt).

## Limitations

This is a learning project, not a production API:

- `/login` checks a single demo user and does not issue a session or token.
- The demo credentials are for local testing only. Set `DEMO_EMAIL` and `DEMO_PASSWORD` to override them.
- Rate limit counts are stored in memory, so they reset on restart and aren't shared across server processes. A production app would use shared storage such as Redis.
- Sanitization uses regular expressions. A production app would use a dedicated library such as nh3 and also escape output in the frontend.
