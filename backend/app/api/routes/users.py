import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.client_ip import get_client_ip
from app.core.enums import AuditOutcome, UserRole
from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.security import hash_password
from app.services import audit_service

router = APIRouter(prefix="/users", tags=["users"])


def _get_org_user_or_404(db: Session, user_id: uuid.UUID, organization_id: uuid.UUID) -> User:
    """Same ownership-boundary pattern as every other org-scoped resource
    in this codebase (assets/scans/reports): 404, not 403, on a
    cross-organization ID — an admin must not be able to learn that a
    given user ID exists in another organization at all.
    """
    user = db.get(User, user_id)
    if user is None or user.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("", response_model=list[UserRead])
def list_users(
    current_user: User = Depends(require_role(UserRole.admin)),
    db: Session = Depends(get_db),
) -> list[User]:
    return db.query(User).filter(User.organization_id == current_user.organization_id).all()


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin)),
    db: Session = Depends(get_db),
) -> User:
    if db.query(User).filter(User.email == payload.email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        organization_id=current_user.organization_id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
    )
    db.add(user)
    db.flush()

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        outcome=AuditOutcome.success,
        details={"email": user.email, "role": user.role.value},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    current_user: User = Depends(require_role(UserRole.admin)),
    db: Session = Depends(get_db),
) -> User:
    if payload.role is None and payload.is_active is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Provide at least one of role, is_active"
        )

    target = _get_org_user_or_404(db, user_id, current_user.organization_id)

    if target.id == current_user.id:
        # Prevents an admin locking themselves (and potentially the whole
        # organization, if they're its only admin) out via a single
        # careless request. Self-management still works through other
        # means (e.g. another admin), just not this endpoint on oneself.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own role or active status via this endpoint",
        )

    changes: dict = {}
    if payload.role is not None and payload.role != target.role:
        changes["role"] = {"from": target.role.value, "to": payload.role.value}
        target.role = payload.role
    if payload.is_active is not None and payload.is_active != target.is_active:
        changes["is_active"] = {"from": target.is_active, "to": payload.is_active}
        target.is_active = payload.is_active

    audit_service.log_action(
        db,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        action="user.update",
        resource_type="user",
        resource_id=target.id,
        outcome=AuditOutcome.success,
        details=changes,
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target
