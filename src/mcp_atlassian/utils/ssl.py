"""SSL-related utility functions for MCP Atlassian."""

import logging
import ssl
from typing import Any
from urllib.parse import urlparse

from requests.adapters import HTTPAdapter
from requests.sessions import Session
from urllib3.poolmanager import PoolManager

logger = logging.getLogger("mcp-atlassian")


def _build_ssl_context(
    ssl_verify: bool,
    client_cert: str | None = None,
    client_key: str | None = None,
    client_key_password: str | None = None,
) -> ssl.SSLContext:
    """Create an SSL context for optional mTLS and certificate verification."""
    context = ssl.create_default_context()

    if not ssl_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if isinstance(client_cert, str) and isinstance(client_key, str):
        context.load_cert_chain(
            client_cert,
            client_key,
            password=client_key_password or None,
        )

    return context


class SSLContextAdapter(HTTPAdapter):
    """HTTP adapter that injects a preconfigured SSL context."""

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self._ssl_context = ssl_context
        super().__init__()

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        """Initialize the connection pool manager with the configured SSL context."""
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self._ssl_context,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Ensure proxied HTTPS requests reuse the configured SSL context."""
        proxy_kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class SSLIgnoreAdapter(SSLContextAdapter):
    """HTTP adapter that ignores SSL verification.

    A custom transport adapter that disables SSL certificate verification for specific domains.
    This implementation ensures that both verify_mode is set to CERT_NONE and check_hostname
    is disabled, which is required for properly ignoring SSL certificates.

    Note that this reduces security and should only be used when absolutely necessary.
    """

    def __init__(self) -> None:
        super().__init__(_build_ssl_context(ssl_verify=False))

    def cert_verify(self, conn: Any, url: str, verify: bool, cert: Any | None) -> None:
        """Override cert verification to disable SSL verification.

        This method is still included for backward compatibility, but the main
        SSL disabling happens in init_poolmanager.

        Args:
            conn: The connection
            url: The URL being requested
            verify: The original verify parameter (ignored)
            cert: Client certificate path
        """
        super().cert_verify(conn, url, verify=False, cert=cert)


class MutualTLSAdapter(SSLContextAdapter):
    """HTTP adapter that configures client-certificate authentication."""

    def __init__(
        self,
        client_cert: str,
        client_key: str,
        client_key_password: str | None = None,
        ssl_verify: bool = True,
    ) -> None:
        self._ssl_verify = ssl_verify
        super().__init__(
            _build_ssl_context(
                ssl_verify=ssl_verify,
                client_cert=client_cert,
                client_key=client_key,
                client_key_password=client_key_password,
            )
        )

    def cert_verify(self, conn: Any, url: str, verify: bool, cert: Any | None) -> None:
        """Run requests-level certificate verification with the configured mode."""
        super().cert_verify(conn, url, verify=self._ssl_verify, cert=cert)


def configure_ssl_verification(
    service_name: str,
    url: str,
    session: Session,
    ssl_verify: bool,
    client_cert: str | None = None,
    client_key: str | None = None,
    client_key_password: str | None = None,
) -> None:
    """Configure SSL verification and client certificates for a specific service.

    If SSL verification is disabled, this function will configure the session
    to use a custom SSL adapter that bypasses certificate validation for the
    service's domain.

    If client certificate paths are provided, they will be configured for
    mutual TLS authentication.

    Args:
        service_name: Name of the service for logging (e.g., "Confluence", "Jira")
        url: The base URL of the service
        session: The requests session to configure
        ssl_verify: Whether SSL verification should be enabled
        client_cert: Path to client certificate file (.pem)
        client_key: Path to client private key file (.pem)
        client_key_password: Password for encrypted private key (optional)
    """
    has_client_cert = isinstance(client_cert, str) and isinstance(client_key, str)
    if ssl_verify and not has_client_cert:
        return

    if not isinstance(url, str):
        return

    domain = urlparse(url).netloc
    if not domain:
        return

    mount_prefixes = (f"https://{domain}", f"http://{domain}")

    if has_client_cert:
        adapter = MutualTLSAdapter(
            client_cert=client_cert,
            client_key=client_key,
            client_key_password=client_key_password,
            ssl_verify=ssl_verify,
        )
        for prefix in mount_prefixes:
            session.mount(prefix, adapter)

        logger.info(
            f"{service_name} client certificate authentication configured "
            f"with cert: {client_cert}"
        )

        if not ssl_verify:
            logger.warning(
                f"{service_name} SSL verification disabled. This is insecure and "
                "should only be used in testing environments."
            )
        return

    if not ssl_verify:
        logger.warning(
            f"{service_name} SSL verification disabled. This is insecure and should only be used in testing environments."
        )

        adapter = SSLIgnoreAdapter()
        for prefix in mount_prefixes:
            session.mount(prefix, adapter)
