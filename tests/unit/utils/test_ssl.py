"""Tests for the SSL utilities module."""

import ssl
from unittest.mock import ANY, MagicMock, patch

from requests.adapters import HTTPAdapter
from requests.sessions import Session

import mcp_atlassian.utils.ssl as ssl_utils
from mcp_atlassian.utils.ssl import (
    MutualTLSAdapter,
    SSLIgnoreAdapter,
    configure_ssl_verification,
)


def test_ssl_ignore_adapter_cert_verify():
    """Test that SSLIgnoreAdapter overrides cert verification."""
    # Arrange
    adapter = SSLIgnoreAdapter()
    connection = MagicMock()
    url = "https://example.com"
    cert = None

    # Mock the super class's cert_verify method
    with patch.object(HTTPAdapter, "cert_verify") as mock_super_cert_verify:
        # Act
        adapter.cert_verify(
            connection, url, verify=True, cert=cert
        )  # Pass True, but expect False to be used

        # Assert
        mock_super_cert_verify.assert_called_once_with(
            connection, url, verify=False, cert=cert
        )


def test_ssl_ignore_adapter_init_poolmanager():
    """Test that SSLIgnoreAdapter properly initializes the connection pool with SSL verification disabled."""
    mock_pool_manager = MagicMock()

    with patch(
        "mcp_atlassian.utils.ssl.ssl.create_default_context"
    ) as mock_create_context:
        mock_context = MagicMock()
        mock_create_context.return_value = mock_context

        adapter = SSLIgnoreAdapter()

        with patch(
            "mcp_atlassian.utils.ssl.PoolManager", return_value=mock_pool_manager
        ) as mock_pool_manager_cls:
            adapter.init_poolmanager(5, 10, block=True)

            mock_create_context.assert_called_once()
            assert mock_context.check_hostname is False
            assert mock_context.verify_mode == ssl.CERT_NONE

            mock_pool_manager_cls.assert_called_once()
            _, kwargs = mock_pool_manager_cls.call_args
            assert kwargs["num_pools"] == 5
            assert kwargs["maxsize"] == 10
            assert kwargs["block"] is True
            assert kwargs["ssl_context"] == mock_context


def test_configure_ssl_verification_disabled():
    """Test configure_ssl_verification when SSL verification is disabled."""
    # Arrange
    service_name = "TestService"
    url = "https://test.example.com/path"
    session = MagicMock()  # Use MagicMock instead of actual Session
    ssl_verify = False

    # Mock the logger to avoid issues with real logging
    with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
        with patch("mcp_atlassian.utils.ssl.SSLIgnoreAdapter") as mock_adapter_class:
            mock_adapter = MagicMock()
            mock_adapter_class.return_value = mock_adapter

            # Act
            configure_ssl_verification(service_name, url, session, ssl_verify)

            # Assert
            mock_adapter_class.assert_called_once()
            # Verify the adapter is mounted for both http and https
            assert session.mount.call_count == 2
            session.mount.assert_any_call("https://test.example.com", mock_adapter)
            session.mount.assert_any_call("http://test.example.com", mock_adapter)


def test_configure_ssl_verification_enabled():
    """Test configure_ssl_verification when SSL verification is enabled."""
    # Arrange
    service_name = "TestService"
    url = "https://test.example.com/path"
    session = MagicMock()  # Use MagicMock instead of actual Session
    ssl_verify = True

    with patch("mcp_atlassian.utils.ssl.SSLIgnoreAdapter") as mock_adapter_class:
        # Act
        configure_ssl_verification(service_name, url, session, ssl_verify)

        # Assert
        mock_adapter_class.assert_not_called()
        assert session.mount.call_count == 0


def test_configure_ssl_verification_enabled_with_non_string_url():
    """Test SSL verification skips adapter setup when the URL is not a string."""
    session = MagicMock()

    configure_ssl_verification(
        service_name="TestService",
        url=MagicMock(),
        session=session,
        ssl_verify=True,
    )

    assert session.mount.call_count == 0


def test_configure_ssl_verification_enabled_with_real_session():
    """Test SSL verification configuration when verification is enabled using a real Session."""
    session = Session()
    original_adapters_count = len(session.adapters)

    # Configure with SSL verification enabled
    configure_ssl_verification(
        service_name="Test",
        url="https://example.com",
        session=session,
        ssl_verify=True,
    )

    # No adapters should be added when SSL verification is enabled
    assert len(session.adapters) == original_adapters_count


def test_configure_ssl_verification_disabled_with_real_session():
    """Test SSL verification configuration when verification is disabled using a real Session."""
    session = Session()
    original_adapters_count = len(session.adapters)

    # Mock the logger to avoid issues with real logging
    with patch("mcp_atlassian.utils.ssl.logger") as mock_logger:
        # Configure with SSL verification disabled
        configure_ssl_verification(
            service_name="Test",
            url="https://example.com",
            session=session,
            ssl_verify=False,
        )

        # Should add custom adapters for http and https protocols
        assert len(session.adapters) == original_adapters_count + 2
        assert "https://example.com" in session.adapters
        assert "http://example.com" in session.adapters
        assert isinstance(session.adapters["https://example.com"], SSLIgnoreAdapter)
        assert isinstance(session.adapters["http://example.com"], SSLIgnoreAdapter)


def test_ssl_ignore_adapter():
    """Test the SSLIgnoreAdapter overrides the cert_verify method."""
    # Mock objects
    adapter = SSLIgnoreAdapter()
    conn = MagicMock()
    url = "https://example.com"
    cert = None

    # Test with verify=True - the adapter should still bypass SSL verification
    with patch.object(HTTPAdapter, "cert_verify") as mock_cert_verify:
        adapter.cert_verify(conn, url, verify=True, cert=cert)
        mock_cert_verify.assert_called_once_with(conn, url, verify=False, cert=cert)

    # Test with verify=False - same behavior
    with patch.object(HTTPAdapter, "cert_verify") as mock_cert_verify:
        adapter.cert_verify(conn, url, verify=False, cert=cert)
        mock_cert_verify.assert_called_once_with(conn, url, verify=False, cert=cert)


def test_configure_ssl_with_client_cert():
    """Test configure_ssl_verification with client certificate."""
    session = MagicMock()
    logger_mock = MagicMock()

    with (
        patch("mcp_atlassian.utils.ssl.logger", logger_mock),
        patch("mcp_atlassian.utils.ssl.MutualTLSAdapter") as mock_adapter_class,
    ):
        mock_adapter = MagicMock()
        mock_adapter_class.return_value = mock_adapter

        configure_ssl_verification(
            service_name="TestService",
            url="https://example.com",
            session=session,
            ssl_verify=True,
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
        )

        mock_adapter_class.assert_called_once_with(
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            client_key_password=None,
            ssl_verify=True,
        )
        session.mount.assert_any_call("https://example.com", mock_adapter)
        session.mount.assert_any_call("http://example.com", mock_adapter)
        logger_mock.info.assert_called_once_with(
            "TestService client certificate authentication configured with cert: /path/to/cert.pem"
        )


def test_configure_ssl_with_encrypted_key():
    """Test configure_ssl_verification supports encrypted private keys."""
    session = MagicMock()

    with patch("mcp_atlassian.utils.ssl.MutualTLSAdapter") as mock_adapter_class:
        mock_adapter = MagicMock()
        mock_adapter_class.return_value = mock_adapter

        configure_ssl_verification(
            service_name="TestService",
            url="https://example.com",
            session=session,
            ssl_verify=True,
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            client_key_password="secret",
        )

    mock_adapter_class.assert_called_once_with(
        client_cert="/path/to/cert.pem",
        client_key="/path/to/key.pem",
        client_key_password="secret",
        ssl_verify=True,
    )
    session.mount.assert_any_call("https://example.com", mock_adapter)
    session.mount.assert_any_call("http://example.com", mock_adapter)


def test_configure_ssl_without_client_cert():
    """Test configure_ssl_verification without client certificate."""
    # Arrange
    session = MagicMock()
    logger_mock = MagicMock()

    with patch("mcp_atlassian.utils.ssl.logger", logger_mock):
        # Act
        configure_ssl_verification(
            service_name="TestService",
            url="https://example.com",
            session=session,
            ssl_verify=True,
        )

        # Assert - session.cert should not be set
        assert not hasattr(session, "cert") or session.cert != ("", "")
        logger_mock.info.assert_not_called()


def test_configure_ssl_disabled_with_client_cert():
    """Test configure_ssl_verification with both SSL disabled and client certificate."""
    session = MagicMock()
    logger_mock = MagicMock()

    with (
        patch("mcp_atlassian.utils.ssl.logger", logger_mock),
        patch("mcp_atlassian.utils.ssl.MutualTLSAdapter") as mock_adapter_class,
    ):
        mock_adapter = MagicMock()
        mock_adapter_class.return_value = mock_adapter

        configure_ssl_verification(
            service_name="TestService",
            url="https://example.com",
            session=session,
            ssl_verify=False,
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
        )

        mock_adapter_class.assert_called_once_with(
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            client_key_password=None,
            ssl_verify=False,
        )
        session.mount.assert_any_call("https://example.com", mock_adapter)
        session.mount.assert_any_call("http://example.com", mock_adapter)
        logger_mock.warning.assert_called_once()


def test_build_ssl_context_loads_client_cert_with_password():
    """Test the SSL context helper loads encrypted client keys."""
    with patch("mcp_atlassian.utils.ssl.ssl.create_default_context") as mock_create:
        mock_context = MagicMock()
        mock_create.return_value = mock_context

        context = ssl_utils._build_ssl_context(
            ssl_verify=False,
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            client_key_password="secret",
        )

    assert context is mock_context
    assert mock_context.check_hostname is False
    assert mock_context.verify_mode == ssl.CERT_NONE
    mock_context.load_cert_chain.assert_called_once_with(
        "/path/to/cert.pem",
        "/path/to/key.pem",
        password="secret",
    )


def test_mutual_tls_adapter_cert_verify_respects_ssl_verify():
    """Test MutualTLSAdapter forwards its configured verify mode to requests."""
    with patch("mcp_atlassian.utils.ssl._build_ssl_context") as mock_build_context:
        mock_build_context.return_value = MagicMock()
        adapter = MutualTLSAdapter(
            client_cert="/path/to/cert.pem",
            client_key="/path/to/key.pem",
            ssl_verify=False,
        )

    with patch.object(HTTPAdapter, "cert_verify") as mock_cert_verify:
        adapter.cert_verify(MagicMock(), "https://example.com", verify=True, cert=None)

    mock_cert_verify.assert_called_once_with(
        ANY, "https://example.com", verify=False, cert=None
    )
