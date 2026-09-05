import pytest

import posture
from posture.exceptions import PostureError, SourceUnknown


def test_version() -> None:
    assert posture.__version__ == "1.0.0"


def test_ccm_unknown_source_raises_source_unknown() -> None:
    with pytest.raises(SourceUnknown, match="Unknown source"):
        posture.CCM("not-a-real-source")


def test_source_unknown_is_posture_error_and_value_error() -> None:
    with pytest.raises(SourceUnknown) as exc_info:
        posture.CCM("not-a-real-source")
    assert isinstance(exc_info.value, PostureError)
    assert isinstance(exc_info.value, ValueError)  # backward compatible


def test_schema_returns_a_copy_not_the_live_manifest() -> None:
    ccm = posture.CCM("endoflife")
    schema = ccm.schema("cycles")
    schema["columns"]["bogus"] = ("bogus", "str")

    fresh = ccm.schema("cycles")

    assert "bogus" not in fresh["columns"]
    assert (
        "bogus" not in posture.catalog()["endoflife"]["resources"]["cycles"]["columns"]
    )
