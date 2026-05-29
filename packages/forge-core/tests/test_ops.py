import pytest

from forge_core.signal import Signal
from forge_core import ops


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(ops._REGISTRY)
    ops._REGISTRY.clear()
    yield
    ops._REGISTRY.clear()
    ops._REGISTRY.update(saved)


def test_op_decorator_registers_and_runs():
    @ops.op("mean")
    def _mean(sig, **_):
        return float(sig.samples.mean())

    assert "mean" in ops.registered()
    got = ops.get("mean")
    s = Signal(samples=[1.0, 2.0, 3.0], fs=1.0)
    assert got(s) == pytest.approx(2.0)


def test_duplicate_registration_raises():
    @ops.op("dup")
    def _a(sig, **_):
        return 1

    with pytest.raises(ValueError):
        @ops.op("dup")
        def _b(sig, **_):
            return 2


def test_get_unknown_raises():
    with pytest.raises(KeyError):
        ops.get("nope")


def test_op_satisfies_protocol():
    @ops.op("ident")
    def _ident(sig, **_):
        return sig

    assert isinstance(ops.get("ident"), ops.Op)


def test_params_passed_through():
    @ops.op("scale")
    def _scale(sig, factor=1.0, **_):
        return sig.with_samples(sig.samples * factor)

    s = Signal(samples=[1.0, 2.0], fs=1.0)
    out = ops.get("scale")(s, factor=3.0)
    assert list(out.samples) == [3.0, 6.0]
