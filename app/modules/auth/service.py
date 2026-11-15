from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import (
    decode_key,
    encrypt_value,
    hmac_value,
    new_data_key,
    wrap_data_key,
)
from app.core.security import (
    create_access_token,
    hash_password,
    new_refresh_token,
    verify_password,
)
from app.db.models.auth import User
from app.modules.auth import repository

logger = structlog.get_logger(__name__)


class DuplicateEmail(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class RefreshTokenReuse(Exception):
    pass


@dataclass(frozen=True)
class AuthTokens:
    user_id: UUID
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._kek = decode_key(settings.master_kek_b64.get_secret_value())
        self._pepper = decode_key(settings.hmac_pepper_b64.get_secret_value())
        self._jwt_key = decode_key(settings.jwt_secret_b64.get_secret_value())

    def _email_hash(self, normalized_email: str) -> str:
        return hmac_value(f"email:{normalized_email}", self._pepper)

    def _refresh_hash(self, token: str) -> str:
        return hmac_value(f"refresh:{token}", self._pepper)

    def _issue_access_token(self, user_id: UUID) -> tuple[str, datetime]:
        return create_access_token(
            user_id,
            self._jwt_key,
            timedelta(minutes=self._settings.access_token_minutes),
        )

    def _refresh_expiration(self, now: datetime) -> datetime:
        return now + timedelta(days=self._settings.refresh_token_days)

    def _make_refresh_token(
        self,
        session: AsyncSession,
        *,
        user_id: UUID,
        family_id: UUID,
        now: datetime,
    ) -> tuple[str, datetime]:
        token = new_refresh_token()
        expires_at = self._refresh_expiration(now)
        repository.add_refresh_token(
            session,
            user_id=user_id,
            token_hash=self._refresh_hash(token),
            family_id=family_id,
            expires_at=expires_at,
        )
        return token, expires_at

    async def register(
        self,
        session: AsyncSession,
        email: str,
        password: str,
    ) -> AuthTokens:
        normalized_email = email.strip().casefold()
        email_hash = self._email_hash(normalized_email)
        user_id = uuid4()
        data_key = new_data_key()
        user_aad = b"user-dek:" + user_id.bytes
        email_aad = b"user-email:" + user_id.bytes
        now = datetime.now(UTC)
        refresh_token = new_refresh_token()
        refresh_expires_at = self._refresh_expiration(now)
        family_id = uuid4()

        user = User(
            id=user_id,
            email_hash=email_hash,
            email_enc=encrypt_value(normalized_email, data_key, email_aad),
            dek_wrapped=wrap_data_key(data_key, self._kek, user_aad),
            password_hash=hash_password(password),
        )

        try:
            async with session.begin():
                if await repository.get_user_by_email_hash(session, email_hash):
                    raise DuplicateEmail
                repository.add_user(session, user)
                repository.add_refresh_token(
                    session,
                    user_id=user_id,
                    token_hash=self._refresh_hash(refresh_token),
                    family_id=family_id,
                    expires_at=refresh_expires_at,
                )
                access_token, access_expires_at = self._issue_access_token(user_id)
        except IntegrityError as exc:
            if await repository.get_user_by_email_hash(session, email_hash):
                raise DuplicateEmail from exc
            raise

        return AuthTokens(
            user_id=user_id,
            access_token=access_token,
            access_expires_at=access_expires_at,
            refresh_token=refresh_token,
            refresh_expires_at=refresh_expires_at,
        )

    async def login(
        self,
        session: AsyncSession,
        email: str,
        password: str,
    ) -> AuthTokens:
        normalized_email = email.strip().casefold()
        email_hash = self._email_hash(normalized_email)
        now = datetime.now(UTC)
        invalid = False
        tokens: AuthTokens | None = None

        async with session.begin():
            user = await repository.get_user_by_email_hash(
                session,
                email_hash,
                for_update=True,
            )
            if user is None or user.deleted_at is not None:
                verify_password(password, None)
                invalid = True
            else:
                password_valid = verify_password(password, user.password_hash)
                locked_until = user.locked_until
                if locked_until is not None and locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=UTC)
                if locked_until is not None and locked_until > now:
                    invalid = True
                elif not password_valid:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= self._settings.login_failure_threshold:
                        exponent = min(
                            user.failed_login_attempts - self._settings.login_failure_threshold,
                            30,
                        )
                        delay = min(
                            self._settings.login_backoff_base_seconds * (2**exponent),
                            self._settings.login_backoff_max_seconds,
                        )
                        user.locked_until = now + timedelta(seconds=delay)
                    invalid = True
                else:
                    user.failed_login_attempts = 0
                    user.locked_until = None
                    family_id = uuid4()
                    refresh_token, refresh_expires_at = self._make_refresh_token(
                        session,
                        user_id=user.id,
                        family_id=family_id,
                        now=now,
                    )
                    access_token, access_expires_at = self._issue_access_token(user.id)
                    tokens = AuthTokens(
                        user_id=user.id,
                        access_token=access_token,
                        access_expires_at=access_expires_at,
                        refresh_token=refresh_token,
                        refresh_expires_at=refresh_expires_at,
                    )

        if invalid or tokens is None:
            raise InvalidCredentials
        return tokens

    async def refresh(self, session: AsyncSession, token: str) -> AuthTokens:
        now = datetime.now(UTC)
        old_hash = self._refresh_hash(token)
        reuse_detected = False
        invalid = False
        tokens: AuthTokens | None = None

        async with session.begin():
            old_token = await repository.get_refresh_token(
                session,
                old_hash,
                for_update=True,
            )
            if old_token is None:
                invalid = True
            elif old_token.revoked_at is not None:
                await repository.revoke_refresh_family(
                    session,
                    old_token.family_id,
                    now,
                )
                reuse_detected = True
            else:
                expires_at = old_token.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)
                user = await repository.get_user_by_id(
                    session,
                    old_token.user_id,
                    for_update=True,
                )
                if expires_at <= now or user is None or user.deleted_at is not None:
                    old_token.revoked_at = now
                    invalid = True
                else:
                    new_token = new_refresh_token()
                    new_token_hash = self._refresh_hash(new_token)
                    refresh_expires_at = self._refresh_expiration(now)
                    old_token.revoked_at = now
                    old_token.replaced_by_hash = new_token_hash
                    repository.add_refresh_token(
                        session,
                        user_id=user.id,
                        token_hash=new_token_hash,
                        family_id=old_token.family_id,
                        expires_at=refresh_expires_at,
                    )
                    access_token, access_expires_at = self._issue_access_token(user.id)
                    tokens = AuthTokens(
                        user_id=user.id,
                        access_token=access_token,
                        access_expires_at=access_expires_at,
                        refresh_token=new_token,
                        refresh_expires_at=refresh_expires_at,
                    )

        if reuse_detected:
            logger.warning("refresh_token_reuse_detected")
            raise RefreshTokenReuse
        if invalid or tokens is None:
            raise InvalidCredentials
        return tokens

    async def logout(self, session: AsyncSession, token: str | None) -> None:
        if token is None:
            return
        async with session.begin():
            refresh_token = await repository.get_refresh_token(
                session,
                self._refresh_hash(token),
                for_update=True,
            )
            if refresh_token is not None and refresh_token.revoked_at is None:
                refresh_token.revoked_at = datetime.now(UTC)
