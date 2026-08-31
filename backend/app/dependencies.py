from fastapi import Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.cookies import ACCESS_TOKEN_COOKIE
from app.core.enums import UserRole
from app.database import get_db
from app.models.user import User
from app.security import decode_token


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Reads the access token from the httpOnly cookie — never a header.
    See docs/auth-cookie-model.md for the full cookie/CSRF model.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        raise credentials_exception
    try:
        user_id = decode_token(token, expected_type="access")
    except (JWTError, ValueError) as exc:
        raise credentials_exception from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def require_role(*allowed_roles: UserRole):
    """Dependency factory enforcing RBAC at the route layer, e.g.
    `Depends(require_role(UserRole.admin))`. Every write/list/read
    endpoint that isn't meant for all authenticated roles must use this
    — RBAC is enforced here, server-side, never left to the frontend to
    hide a button.
    """

    def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(r.value for r in allowed_roles)}",
            )
        return current_user

    return _check
