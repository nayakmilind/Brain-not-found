import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import Settings


class SMTPNotConfigured(Exception):
    pass


class SMTPDeliveryError(Exception):
    pass


class OTPMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send_otp(self, recipient: str, otp: str) -> None:
        settings = self._settings
        if settings.smtp_host is None or settings.smtp_from is None:
            raise SMTPNotConfigured
        try:
            await asyncio.to_thread(self._send_sync, recipient, otp)
        except (OSError, smtplib.SMTPException, TimeoutError) as error:
            raise SMTPDeliveryError from error

    def _send_sync(self, recipient: str, otp: str) -> None:
        settings = self._settings
        if settings.smtp_host is None or settings.smtp_from is None:
            raise SMTPNotConfigured
        message = EmailMessage()
        message["Subject"] = "Privacy Shield AI ownership verification"
        message["From"] = str(settings.smtp_from)
        message["To"] = recipient
        message.set_content(
            f"Your Privacy Shield AI ownership verification code is {otp}. "
            "It expires in 15 minutes. If you did not request it, ignore this message."
        )
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
            client.starttls(context=ssl.create_default_context())
            if settings.smtp_username is not None and settings.smtp_password is not None:
                client.login(
                    settings.smtp_username.get_secret_value(),
                    settings.smtp_password.get_secret_value(),
                )
            client.send_message(message)
