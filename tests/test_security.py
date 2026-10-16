"""
Security tests:
- Rate limiting: 10 requests succeed, the 11th returns 429.
- Sanitization: HTML and script tags are stripped from submitted items.
- Validation: a name made only of HTML is rejected (422).
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app, request_log

client = TestClient(app)

# The rate limiter remembers requests between tests, so we clear it before
# and after each test. Otherwise one test's requests could trigger a 429 in the next.
@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Start every test with a clean request count."""
    request_log.clear()
    yield
    request_log.clear()


def test_rate_limit_returns_429_on_11th_request():
    for i in range(10):
        response = client.get("/items")
        assert response.status_code == 200, f"Request {i + 1} should succeed"

    response = client.get("/items")
    assert response.status_code == 429
    assert "Retry-After" in response.headers


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