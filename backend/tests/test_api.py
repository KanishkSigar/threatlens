import pytest
from httpx import AsyncClient
from typing import Dict

@pytest.mark.asyncio
async def test_health_check(async_client: AsyncClient):
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "app" in data
    assert "version" in data

@pytest.mark.asyncio
async def test_register_user(async_client: AsyncClient, test_user_data: Dict):
    response = await async_client.post("/api/auth/register", json=test_user_data)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["username"] == test_user_data["username"]

@pytest.mark.asyncio
async def test_register_existing_user(async_client: AsyncClient, test_user_data: Dict):
    await async_client.post("/api/auth/register", json=test_user_data)
    response = await async_client.post("/api/auth/register", json=test_user_data)
    assert response.status_code == 409
    assert response.json()["detail"] == "Email already registered"

@pytest.mark.asyncio
async def test_login_user(async_client: AsyncClient, test_user_data: Dict):
    await async_client.post("/api/auth/register", json=test_user_data)
    
    login_data = {
        "username": test_user_data["username"],
        "password": test_user_data["password"]
    }
    response = await async_client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

@pytest.mark.asyncio
async def test_get_me(async_client: AsyncClient, test_user_data: Dict):
    reg_response = await async_client.post("/api/auth/register", json=test_user_data)
    token = reg_response.json()["access_token"]
    
    response = await async_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user_data["username"]
    assert data["email"] == test_user_data["email"]

@pytest.mark.asyncio
async def test_get_me_unauthorized(async_client: AsyncClient):
    response = await async_client.get("/api/auth/me")
    assert response.status_code == 401 # HTTPBearer returns 401 if missing auth

@pytest.mark.asyncio
async def test_scan_url(async_client: AsyncClient, test_user_data: Dict):
    reg_response = await async_client.post("/api/auth/register", json=test_user_data)
    token = reg_response.json()["access_token"]
    
    response = await async_client.post(
        "/api/scan/url",
        json={"url": "https://www.example.com"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "url"
    assert "risk_score" in data
    assert "verdict" in data

@pytest.mark.asyncio
async def test_scan_email(async_client: AsyncClient, test_user_data: Dict):
    reg_response = await async_client.post("/api/auth/register", json=test_user_data)
    token = reg_response.json()["access_token"]
    
    response = await async_client.post(
        "/api/scan/email",
        json={
            "email_content": "URGENT! Update your account details immediately by clicking this link: http://192.168.1.1/login",
            "subject": "Action Required"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "email"
    assert "risk_score" in data
    assert "verdict" in data

@pytest.mark.asyncio
async def test_scan_history_and_stats(async_client: AsyncClient, test_user_data: Dict):
    reg_response = await async_client.post("/api/auth/register", json=test_user_data)
    token = reg_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Do a scan first
    await async_client.post(
        "/api/scan/url",
        json={"url": "https://www.example.com"},
        headers=headers
    )
    
    # Check history
    history_resp = await async_client.get("/api/scan/history", headers=headers)
    assert history_resp.status_code == 200
    history_data = history_resp.json()
    assert history_data["total"] == 1
    assert len(history_data["scans"]) == 1
    
    # Check stats
    stats_resp = await async_client.get("/api/scan/", headers=headers)
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert stats_data["total_scans"] == 1
    assert stats_data["urls_scanned"] == 1
