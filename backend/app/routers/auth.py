"""
Authentication Router
Handles user registration and login with JWT tokens.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    UserResponse,
)
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(request: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account.
    Returns a JWT token on successful registration.
    """
    # Check if email already exists
    result = await db.execute(select(User).where(User.email == request.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Check if username already exists
    result = await db.execute(select(User).where(User.username == request.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Create new user
    user = User(
        email=request.email,
        username=request.username,
        password_hash=hash_password(request.password),
    )
    db.add(user)
    await db.flush()  # Flush to get the generated ID

    # Generate token
    access_token = create_access_token(data={"sub": user.id})

    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        username=user.username,
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: UserLoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Login with username and password.
    Returns a JWT token on successful authentication.
    """
    # Find user by username
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Generate token
    access_token = create_access_token(data={"sub": user.id})

    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        username=user.username,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get the currently authenticated user's profile."""
    return current_user
