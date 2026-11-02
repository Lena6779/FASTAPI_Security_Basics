"""
Security tests:
- Rate limiting: login, create, and list endpoints return 429 past their limits.
- Input limits: oversized strings and out-of-range numbers are rejected (422).
- Sanitization: HTML and script tags are stripped from submitted items.
- Validation: a name made only of HTML is rejected (422).
- SQL injection: a malicious search value is treated as plain text.
- CORS: only the approved frontends get CORS approval.

Run with -s to see the status code of every rate limit attempt:
    pytest -v -s
"""

import pytest
from fastapi.testclient import TestClient

from app.limiter import limiter
from app.main import app
from app.routers import items

client = TestClient(app)

VALID_LOGIN = {"email": "demo@example.com", "password": "demo-password"}
WRONG_LOGIN = {"email": "demo@example.com", "password": "wrong-password"}


# The rate limiter remembers requests between tests, so we clear it around each
# test. Each test also gets its own temporary database, so the many POST
# requests here never add rows to the real items.db.
@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Start every test with a clean request count and an empty database."""
    monkeypatch.setattr(items, "DB_PATH", str(tmp_path / "test_items.db"))
    items.init_db()
    limiter.reset()
    yield
    limiter.reset()


# ---------- Rate limiting ----------
def test_valid_login_succeeds():
    response = client.post("/login", json=VALID_LOGIN)
    assert response.status_code == 200
    assert response.json() == {"message": "Login successful"}


def test_wrong_password_returns_401():
    response = client.post("/login", json=WRONG_LOGIN)
    assert response.status_code == 401


def test_non_ascii_login_returns_401_not_a_server_error():
    response = client.post(
        "/login", json={"email": "josé@example.com", "password": "contraseña-123"}
    )
    assert response.status_code == 401


def test_sixth_rapid_login_returns_429():
    statuses = []
    for attempt in range(1, 7):
        response = client.post("/login", json=WRONG_LOGIN)
        statuses.append(response.status_code)
        print(f"Login attempt {attempt}: {response.status_code}")

    assert statuses == [401, 401, 401, 401, 401, 429]
    assert "Retry-After" in response.headers


def test_21st_rapid_create_returns_429():
    for i in range(20):
        response = client.post("/items", json={"name": f"Item {i}"})
        assert response.status_code == 201, f"Request {i + 1} should succeed"

    response = client.post("/items", json={"name": "One too many"})
    print(f"Create attempt 21: {response.status_code}")
    assert response.status_code == 429


def test_61st_rapid_list_returns_429():
    for i in range(60):
        response = client.get("/items")
        assert response.status_code == 200, f"Request {i + 1} should succeed"

    response = client.get("/items")
    print(f"List attempt 61: {response.status_code}")
    assert response.status_code == 429


# ---------- Input limits ----------
@pytest.mark.parametrize(
    "payload",
    [
        {"email": "a" * 250 + "@example.com", "password": "demo-password"},
        {"email": "not-an-email", "password": "demo-password"},
        {"email": "demo@example.com", "password": "a" * 129},
        {"email": "demo@example.com", "password": "short"},
    ],
)
def test_login_rejects_out_of_bounds_input(payload):
    assert client.post("/login", json=payload).status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"name": ""},
        {"name": "a" * 101},
        {"name": "Laptop", "description": "a" * 1001},
    ],
)
def test_create_item_rejects_out_of_bounds_input(payload):
    assert client.post("/items", json=payload).status_code == 422


def test_create_item_accepts_values_at_the_maximum():
    payload = {"name": "a" * 100, "description": "b" * 1000}
    assert client.post("/items", json=payload).status_code == 201


@pytest.mark.parametrize(
    "query",
    ["limit=0", "limit=101", "offset=-1", "offset=1000001", "search=" + "a" * 101],
)
def test_list_items_rejects_out_of_bounds_query(query):
    assert client.get(f"/items?{query}").status_code == 422


def test_limit_and_offset_page_through_results():
    for name in ["First", "Second", "Third"]:
        client.post("/items", json={"name": name})

    response = client.get("/items?limit=1&offset=1")
    assert [item["name"] for item in response.json()] == ["Second"]


# ---------- Sanitization ----------
def test_script_tags_are_stripped():
    payload = {
        "name": "  <script>alert('xss')</script><b>Laptop</b>  ",
        "description": "<i>Fast</i> and <u>light</u>",
    }
    response = client.post("/items", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Laptop"
    assert data["description"] == "Fast and light"
    assert "<script>" not in data["name"]


def test_name_that_is_only_html_is_rejected():
    response = client.post("/items", json={"name": "<b></b>"})
    assert response.status_code == 422


# ---------- SQL injection ----------
def test_sql_injection_search_is_treated_as_text():
    client.post("/items", json={"name": "Laptop"})

    response = client.get("/items", params={"search": "%' OR 1=1 --"})

    assert response.status_code == 200
    assert response.json() == []


# ---------- CORS ----------
@pytest.mark.parametrize("origin", ["http://localhost:8501", "http://localhost:3000"])
def test_cors_allows_approved_origins(origin):
    response = client.get("/", headers={"Origin": origin})
    assert response.headers["access-control-allow-origin"] == origin


def test_cors_blocks_other_origins():
    response = client.get("/", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers
