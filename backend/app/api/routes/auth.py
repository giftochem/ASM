from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.config import settings
from app.core.client_ip import get_client_ip
from app.core.cookies import REFRESH_TOKEN_COOKIE, clear_auth_cookies, set_auth_cookies
from app.core.enums import AuditOutcome, UserRole
from app.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.schemas.user import UserRead
from app.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_csrf_token,
    hash_password,
    verify_password,
)
from app.services import account_lockout, audit_service, refresh_token_service
from app.services.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_session(response: Response, db: Session, user: User) -> None:
    access_token = create_access_token(user.id)
    refresh_token = refresh_token_service.issue(db, user.id)
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, access_token, refresh_token, csrf_token)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_login)
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> User:
    """Bootstraps a new organization plus its first admin user. Every
    subsequent user in that organization must be created by an admin via
    POST /users, not this endpoint. Tokens are delivered exclusively via
    httpOnly cookies — never in this (or any auth) response body. See
    docs/auth-cookie-model.md.
    """
    if db.query(User).filter(User.email == payload.email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    organization = Organization(name=payload.organization_name)
    db.add(organization)
    db.flush()

    user = User(
        organization_id=organization.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=UserRole.admin,
    )
    db.add(user)
    db.flush()

    audit_service.log_action(
        db,
        user_id=user.id,
        organization_id=organization.id,
        action="organization.register",
        resource_type="organization",
        resource_id=organization.id,
        outcome=AuditOutcome.success,
        details={"admin_email": user.email},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(user)

    _issue_session(response, db, user)
    return user


@router.post("/login", response_model=UserRead)
@limiter.limit(settings.rate_limit_login)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> User:
    user = db.query(User).filter(User.email == form_data.username).first()
    ip_address = get_client_ip(request)

    # Account-based brute-force protection (Step 7A, finding H-3),
    # independent of and in addition to the IP-based limiter on this
    # route. Checked before password verification so a locked account
    # doesn't also pay a bcrypt cost on every hammered attempt.
    locked_seconds = account_lockout.seconds_locked(form_data.username)
    if locked_seconds is not None:
        audit_service.log_action(
            db,
            user_id=user.id if user else None,
            organization_id=user.organization_id if user else None,
            action="auth.login",
            resource_type="user",
            resource_id=user.id if user else None,
            outcome=AuditOutcome.failure,
            details={"email": form_data.username, "reason": "account_locked"},
            ip_address=ip_address,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )

    # Always run verify_password -- against a precomputed dummy hash when
    # no such user exists -- so both branches cost the same bcrypt time.
    # Without this, `user is None` would short-circuit the check
    # entirely, and the resulting timing gap would let an attacker
    # distinguish "no such account" from "wrong password" despite both
    # returning the identical response below (Step 7A remediation,
    # finding H-1).
    password_hash = user.hashed_password if user is not None else DUMMY_PASSWORD_HASH
    password_valid = verify_password(form_data.password, password_hash)

    if user is None or not password_valid:
        account_lockout.record_failure(form_data.username)
        audit_service.log_action(
            db,
            user_id=user.id if user else None,
            organization_id=user.organization_id if user else None,
            action="auth.login",
            resource_type="user",
            resource_id=user.id if user else None,
            outcome=AuditOutcome.failure,
            details={"email": form_data.username},
            ip_address=ip_address,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    if not user.is_active:
        audit_service.log_action(
            db,
            user_id=user.id,
            organization_id=user.organization_id,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            outcome=AuditOutcome.failure,
            details={"reason": "user_disabled"},
            ip_address=ip_address,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")

    account_lockout.record_success(form_data.username)
    audit_service.log_action(
        db,
        user_id=user.id,
        organization_id=user.organization_id,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        outcome=AuditOutcome.success,
        ip_address=ip_address,
    )
    db.commit()

    _issue_session(response, db, user)
    return user


@router.post("/refresh", response_model=UserRead)
@limiter.limit(settings.rate_limit_auth_refresh)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> User:
    presented = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not presented:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")

    try:
        new_refresh_token, user_id = refresh_token_service.rotate(db, presented)
    except refresh_token_service.RefreshTokenError as exc:
        clear_auth_cookies(response)
        actor = db.get(User, exc.user_id) if exc.user_id else None
        audit_service.log_action(
            db,
            user_id=exc.user_id,
            organization_id=actor.organization_id if actor else None,
            action="auth.refresh",
            resource_type="refresh_token",
            outcome=AuditOutcome.failure,
            details={"reason": exc.reason},
            ip_address=get_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = create_access_token(user.id)
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, access_token, new_refresh_token, csrf_token)

    audit_service.log_action(
        db,
        user_id=user.id,
        organization_id=user.organization_id,
        action="auth.refresh",
        resource_type="refresh_token",
        outcome=AuditOutcome.success,
        ip_address=get_client_ip(request),
    )
    db.commit()
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> None:
    presented = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if presented:
        refresh_token_service.revoke(db, presented)
        audit_service.log_action(
            db,
            user_id=None,
            organization_id=None,
            action="auth.logout",
            resource_type="refresh_token",
            outcome=AuditOutcome.success,
            ip_address=get_client_ip(request),
        )
        db.commit()
    clear_auth_cookies(response)
