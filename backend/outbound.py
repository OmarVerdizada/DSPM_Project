"""Calls Sentro makes to other systems: webhooks, mail relays, Jira and ServiceNow (D3).

Every outbound connection is made the same way:

- **the address is checked, then pinned.** The name is resolved once; if any address it
  resolves to is loopback, link-local, multicast, reserved or a cloud metadata address,
  nothing is dialed (collectors.net_guard - the rule the scan collectors follow). A
  private address is allowed: the receivers of an on-premises install are on its own
  network. The connection is made to the address that was checked, so a name that
  answers differently a second later (DNS rebinding) is not asked again;
- **TLS is verified**, the chain and the name, against the system's trust store or the
  private CA the administrator uploaded - never switched off;
- **no redirect is followed**, and a response body is read up to 64 KB;
- **what went wrong is written here**, for a person, never an exception's own text
  (which can carry what the peer sent).

Plain HTTP is refused. SMTP may run without TLS only to a relay that asks for no
password, and only when the administrator chose it.
"""

from __future__ import annotations

import http.client
import json
import smtplib
import socket
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit

from collectors.net_guard import ip_disallowed_reason, resolve_addresses

MAX_RESPONSE_BYTES = 64 * 1024
USER_AGENT = "Sentro-DSPM"


class OutboundRefused(Exception):
    """The destination may not be called, or the call failed. `str()` is safe to show."""


def _allow_loopback() -> bool:
    # Tests run their receivers on 127.0.0.1; nothing else may. Patched there, never set.
    return False


def pin(host: str) -> str:
    """Resolve `host` once and return the one address to dial - or refuse."""
    addresses = resolve_addresses(host)
    if not addresses:
        raise OutboundRefused(f"The host name {host} could not be resolved.")
    for address in addresses:
        if address.is_loopback and _allow_loopback():
            continue
        reason = ip_disallowed_reason(address, True)
        if reason:
            raise OutboundRefused(f"{host} resolves to an address Sentro does not call ({reason}).")
    preferred = [item for item in addresses if item.version == 4] or addresses
    return str(preferred[0])


def tls_context(ca_pem: str = "") -> ssl.SSLContext:
    context = ssl.create_default_context(cadata=ca_pem or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def explain(exc: BaseException, host: str, port: int) -> str:
    """What went wrong, for a person - the SIEM's wording, which says what to fix."""
    if isinstance(exc, OutboundRefused):
        return str(exc)
    from backend.siem_settings import safe_message

    return safe_message(exc, {"host": host, "port": port})


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, *, address: str, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def https_request(method: str, url: str, *, body: bytes | None = None, headers: dict | None = None,
                  ca_pem: str = "", timeout: float = 10.0) -> tuple[int, bytes]:
    """One HTTPS request to `url`. Returns (status, body up to 64 KB). Raises
    OutboundRefused with a message fit to show."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise OutboundRefused("Only https:// addresses are called.")
    host = parts.hostname
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    address = pin(host)
    connection = _PinnedHTTPSConnection(host, port, address=address, context=tls_context(ca_pem), timeout=timeout)
    try:
        connection.request(method, path, body=body, headers={"User-Agent": USER_AGENT, **(headers or {})})
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES)
        return response.status, data
    except OutboundRefused:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise OutboundRefused(explain(exc, host, port) if isinstance(exc, OSError)
                              else f"{host}:{port} sent a response that is not HTTP.") from exc
    finally:
        connection.close()


def https_json(method: str, url: str, *, payload: dict | None = None, headers: dict | None = None,
               ca_pem: str = "", timeout: float = 10.0) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    sent = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        sent["Content-Type"] = "application/json"
    status, data = https_request(method, url, body=body, headers=sent, ca_pem=ca_pem, timeout=timeout)
    try:
        parsed = json.loads(data.decode("utf-8")) if data else {}
    except (UnicodeDecodeError, ValueError):
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {"items": parsed}


class _PinnedSMTP(smtplib.SMTP):
    """SMTP to the checked address, with the relay's NAME kept for STARTTLS's check."""

    def __init__(self, *, address: str, **kwargs) -> None:
        self._address = address
        super().__init__(**kwargs)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self._address, port), timeout)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, *, address: str, **kwargs) -> None:
        self._address = address
        super().__init__(**kwargs)

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((self._address, port), timeout)
        return self.context.wrap_socket(sock, server_hostname=self._host)


SMTP_SECURITY = ("starttls", "tls", "none")


def send_mail(*, host: str, port: int, security: str, sender: str, recipients: list[str], subject: str,
              text: str, username: str = "", password: str = "", ca_pem: str = "", timeout: float = 15.0) -> None:
    """Send one plain-text message. STARTTLS and implicit TLS are verified; `none` sends
    in the clear and is refused with a password."""
    if security not in SMTP_SECURITY:
        raise OutboundRefused("Choose STARTTLS, TLS or none.")
    if security == "none" and (username or password):
        raise OutboundRefused("A mail relay password is only sent over TLS.")
    address = pin(host)
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(text)
    context = tls_context(ca_pem)
    try:
        if security == "tls":
            client: smtplib.SMTP = _PinnedSMTPSSL(address=address, host=host, port=port, timeout=timeout, context=context)
        else:
            client = _PinnedSMTP(address=address, host=host, port=port, timeout=timeout)
        try:
            client.ehlo()
            if security == "starttls":
                if not client.has_extn("starttls"):
                    raise OutboundRefused(f"{host}:{port} does not offer STARTTLS.")
                client.starttls(context=context)
                client.ehlo()
            if username:
                client.login(username, password)
            refused = client.send_message(message)
            if refused:
                raise OutboundRefused(f"{host}:{port} refused {len(refused)} of the recipients.")
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                client.close()
    except OutboundRefused:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise OutboundRefused(f"{host}:{port} refused the user name or password.") from exc
    except smtplib.SMTPResponseException as exc:
        raise OutboundRefused(f"{host}:{port} refused the message (SMTP {exc.smtp_code}).") from exc
    except smtplib.SMTPException as exc:
        raise OutboundRefused(f"The conversation with {host}:{port} failed ({type(exc).__name__}).") from exc
    except OSError as exc:
        raise OutboundRefused(explain(exc, host, port)) from exc
