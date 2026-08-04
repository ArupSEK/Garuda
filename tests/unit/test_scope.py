import pytest

from app.core.exceptions import ScopeValidationError
from app.services.scope_validator import enforce_engagement_scope, expand_targets


def test_public_ip_and_deduplication():
    assert expand_targets(["8.8.8.8", "8.8.8.8"]) == ["8.8.8.8"]


@pytest.mark.parametrize(
    "target", ["invalid", "127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1"]
)
def test_rejects_unsafe_targets(target):
    with pytest.raises(ScopeValidationError):
        expand_targets([target])


def test_cidr_expansion_and_limit():
    assert expand_targets(["8.8.8.0/30"]) == ["8.8.8.1", "8.8.8.2"]
    with pytest.raises(ScopeValidationError):
        expand_targets(["8.8.8.0/23"])


def test_engagement_scope_and_exclusion():
    enforce_engagement_scope(["8.8.8.8"], ["8.8.8.0/24"])
    with pytest.raises(ScopeValidationError):
        enforce_engagement_scope(["1.1.1.1"], ["8.8.8.0/24"])
    with pytest.raises(ScopeValidationError):
        enforce_engagement_scope(["8.8.8.8"], ["8.8.8.0/24"], ["8.8.8.8/32"])
