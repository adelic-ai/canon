"""Operation-identity registry — closes the op_name/kernel gap ``derive()`` leaves open.

See ``provenance/registry.py``'s module docstring for why this can't live inside
``derive()``/``Activity.id`` itself (would break ``test_identical_derivations_share_id``).
"""
import pytest

from provenance import OperationIdentityError, derive_registered, source


def _step_plus_one(x):
    return x + 1


def test_same_call_site_repeated_is_fine():
    s = source(10, name="x")
    a = derive_registered("registry_test.step_a", _step_plus_one, [s])
    b = derive_registered("registry_test.step_a", _step_plus_one, [s])
    assert a.id == b.id
    assert a.value() == 11


def test_different_kernel_same_name_raises():
    s = source(10, name="y")
    derive_registered("registry_test.step_b", lambda x: x + 1, [s])
    with pytest.raises(OperationIdentityError):
        derive_registered("registry_test.step_b", lambda x: x + 100, [s])


def test_reviewed_repro_now_raises_instead_of_silently_colliding():
    """The exact repro from the review: two different kernels under one op_name used to
    collide (`a.id == b.id`) and silently return `(11, 11)` instead of `(11, 110)`."""
    s = source(10, name="z")
    derive_registered("registry_test.step_c", lambda x: x + 1, [s])
    with pytest.raises(OperationIdentityError):
        derive_registered("registry_test.step_c", lambda x: x + 100, [s])
