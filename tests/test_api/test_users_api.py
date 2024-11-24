from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token
from urllib.parse import urlencode


# Fixtures for authenticated user tokens
@pytest.fixture
async def user_token(async_client, verified_user):
    """Fixture for generating an access token for a regular user."""
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"  # Replace with correct password
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    token = response.json().get("access_token")
    assert token is not None
    return token


@pytest.fixture
async def admin_token(async_client, admin_user):
    """Fixture for generating an access token for an admin user."""
    form_data = {
        "username": admin_user.email,
        "password": "AdminPassword123!"  # Replace with correct admin password
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    token = response.json().get("access_token")
    assert token is not None
    return token


@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token):
    """Regular user should not be able to create new users."""
    headers = {"Authorization": f"Bearer {user_token}"}
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!"
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    """Regular user should not be able to access user details."""
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    """Admin user should be able to access user details."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)


@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    """Regular user should not be able to update user email."""
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    """Admin user should be able to update user email."""
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    """Admin user should be able to delete a user."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404


@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    """Should fail to create a user with a duplicate email."""
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    """Login should succeed with correct credentials."""
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    decoded_token = decode_token(data["access_token"])
    assert decoded_token["role"] == "AUTHENTICATED"


@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    """Login should fail with an incorrect password."""
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "The email or password is incorrect" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    """Deleting a non-existent user should return 404."""
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404


@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    """Admin user should be able to list users."""
    response = await async_client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert "items" in response.json()
