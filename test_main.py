import pytest
from fastapi.testclient import TestClient

import main as api


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB", str(tmp_path / "test.db"))
    api.init_db()
    with TestClient(api.app) as test_client:
        yield test_client


def register_and_login(client, email="user@example.com"):
    response = client.post(
        "/register",
        json={"name": "Test User", "email": email, "password": "secret123"},
    )
    assert response.status_code == 201
    response = client.post(
        "/login", data={"username": email, "password": "secret123"}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_home_and_registration_login_me(client):
    assert client.get("/").json()["docs"] == "/docs"
    headers = register_and_login(client)

    response = client.get("/me", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "id": 1,
        "name": "Test User",
        "email": "user@example.com",
    }


def test_duplicate_email_and_invalid_login(client):
    register_and_login(client)

    duplicate = client.post(
        "/register",
        json={"name": "Another User", "email": "user@example.com", "password": "secret123"},
    )
    invalid_login = client.post(
        "/login", data={"username": "user@example.com", "password": "wrongpass"}
    )
    oversized_password = client.post(
        "/login",
        data={"username": "user@example.com", "password": "x" * 73},
    )

    assert duplicate.status_code == 400
    assert invalid_login.status_code == 401
    assert oversized_password.status_code == 401


def test_item_crud_is_scoped_to_authenticated_owner(client):
    owner_headers = register_and_login(client)
    other_headers = register_and_login(client, "other@example.com")

    created = client.post(
        "/items",
        json={"title": "First item", "description": "Original"},
        headers=owner_headers,
    )
    item_id = created.json()["id"]
    assert created.status_code == 201

    second_created = client.post(
        "/items",
        json={"title": "Second item", "description": "Newest"},
        headers=owner_headers,
    )
    second_item_id = second_created.json()["id"]

    listed = client.get("/items", headers=owner_headers)
    assert [item["id"] for item in listed.json()] == [second_item_id, item_id]
    assert client.get("/items", headers=other_headers).json() == []
    assert client.get(f"/items/{item_id}", headers=other_headers).status_code == 404
    assert client.put(
        f"/items/{item_id}",
        json={"title": "Not yours", "description": ""},
        headers=other_headers,
    ).status_code == 404
    assert client.delete(f"/items/{item_id}", headers=other_headers).status_code == 404

    updated = client.put(
        f"/items/{item_id}",
        json={"title": "Updated item", "description": "Changed"},
        headers=owner_headers,
    )
    assert updated.status_code == 200
    assert updated.json() == {"message": "Item updated"}
    assert client.get(f"/items/{item_id}", headers=owner_headers).json() == {
        "id": item_id,
        "title": "Updated item",
        "description": "Changed",
    }
    deleted = client.delete(f"/items/{item_id}", headers=owner_headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"message": "Item deleted"}
    assert client.get(f"/items/{item_id}", headers=owner_headers).status_code == 404


def test_protected_routes_reject_missing_or_invalid_token(client):
    assert client.get("/me").status_code == 401
    assert client.get("/items", headers={"Authorization": "Bearer invalid"}).status_code == 401
