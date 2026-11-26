from datetime import datetime
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    Actor,
    ActorRole,
    create_access_token,
    create_refresh_token,
    get_current_actor,
    hash_password,
    require_roles,
    resolve_settings,
    verify_access_token,
    verify_password,
)
from app.db.base import utcnow
from app.db.models import User
from app.db.session import get_db
from app.evidence.chain import record_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenIssueRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    role: ActorRole = "auditor"
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class TokenIssueResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    actor: Actor


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserRegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: ActorRole = "viewer"
    mfa_enabled: bool = False


class UserLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class AuthSessionResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    actor: Actor
    user: UserOut


@router.get("/me", response_model=Actor)
async def get_me(actor: Actor = Depends(get_current_actor)) -> Actor:
    """Return the resolved actor context for the current request."""
    return actor


@router.post("/token", response_model=TokenIssueResponse)
async def issue_dev_token(
    payload: TokenIssueRequest,
    request: Request,
) -> TokenIssueResponse:
    """Issue a signed dev/test HMAC token (disabled in production)."""
    settings = resolve_settings(request)

    if settings.app_env.strip().lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development token issuance is disabled in production.",
        )

    clean_email = payload.email.strip()
    token = create_access_token(
        email=clean_email,
        role=payload.role,
        secret_key=settings.auth_secret_key,
        ttl_seconds=payload.ttl_seconds,
    )
    return TokenIssueResponse(
        access_token=token,
        actor=Actor(email=clean_email, role=payload.role, auth_method="bearer_token"),
    )


@router.post("/register", response_model=AuthSessionResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthSessionResponse:
    """Register a user (open for initial bootstrap user; admin-only once users exist)."""
    settings = resolve_settings(request)
    clean_email = payload.email.strip().lower()

    any_user = (await db.execute(select(User.id).limit(1))).scalar_one_or_none()
    actor_for_audit: Actor
    if any_user is not None:
        caller = await get_current_actor(request)
        if caller.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required to register additional users.",
            )
        actor_for_audit = caller
    else:
        actor_for_audit = Actor(
            email=clean_email,
            role=payload.role,
            auth_method="bootstrap_register",
        )

    existing = (
        await db.execute(select(User).where(User.email == clean_email))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User '{clean_email}' already exists.",
        )

    user = User(
        email=clean_email,
        full_name=payload.full_name.strip(),
        role=payload.role,
        password_hash=hash_password(payload.password),
        is_active=True,
        mfa_enabled=payload.mfa_enabled,
        last_login_at=utcnow(),
    )
    db.add(user)
    await db.flush()

    await record_audit_event(
        db,
        event_type="auth.user_registered",
        actor=actor_for_audit,
        entity_type="user",
        entity_id=user.id,
        action="register",
        details={"email": user.email, "role": user.role},
    )
    await db.commit()
    await db.refresh(user)

    access = create_access_token(clean_email, payload.role, settings.auth_secret_key)
    refresh = create_refresh_token(clean_email, payload.role, settings.auth_secret_key)
    return AuthSessionResponse(
        access_token=access,
        refresh_token=refresh,
        actor=Actor(email=clean_email, role=payload.role, auth_method="bearer_token"),
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=AuthSessionResponse)
async def login_user(
    payload: UserLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthSessionResponse:
    """Authenticate an active user with password and issue access + refresh JWTs."""
    settings = resolve_settings(request)
    clean_email = payload.email.strip().lower()
    user = (await db.execute(select(User).where(User.email == clean_email))).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(
        payload.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    user.last_login_at = utcnow()
    role = cast(ActorRole, user.role)
    actor = Actor(email=user.email, role=role, auth_method="bearer_token")
    await record_audit_event(
        db,
        event_type="auth.login",
        actor=actor,
        entity_type="user",
        entity_id=user.id,
        action="login",
        details={"email": user.email, "role": user.role},
    )
    await db.commit()
    await db.refresh(user)

    access = create_access_token(user.email, role, settings.auth_secret_key)
    refresh = create_refresh_token(user.email, role, settings.auth_secret_key)
    return AuthSessionResponse(
        access_token=access,
        refresh_token=refresh,
        actor=actor,
        user=UserOut.model_validate(user),
    )


@router.post("/refresh", response_model=AuthSessionResponse)
async def refresh_session(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthSessionResponse:
    """Exchange a valid refresh token for a fresh access + refresh token pair."""
    settings = resolve_settings(request)
    actor = verify_access_token(
        payload.refresh_token.strip(),
        settings.auth_secret_key,
        expected_typ="refresh",
    )
    user = (
        await db.execute(select(User).where(User.email == actor.email.lower()))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
        )

    role = cast(ActorRole, user.role)
    access = create_access_token(user.email, role, settings.auth_secret_key)
    refresh = create_refresh_token(user.email, role, settings.auth_secret_key)
    return AuthSessionResponse(
        access_token=access,
        refresh_token=refresh,
        actor=Actor(email=user.email, role=role, auth_method="bearer_token"),
        user=UserOut.model_validate(user),
    )


@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> list[User]:
    """List registered platform users (officer/admin only)."""
    stmt = select(User).order_by(User.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())
