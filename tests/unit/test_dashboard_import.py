"""Dashboard packaging regression tests."""


def test_dashboard_client_is_importable() -> None:
    """The Docker dashboard entrypoint must resolve its package imports."""
    from dashboard import client

    assert client.API_URL
