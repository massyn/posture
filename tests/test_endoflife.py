import pytest
import responses

from posture import CCM
from posture.exceptions import PostureError


@responses.activate
def test_no_products_configured_makes_no_network_call() -> None:
    # No responses registered at all — any HTTP call this makes fails the
    # test via responses' "connection refused" behaviour.
    ccm = CCM("endoflife")
    df = ccm.collect("cycles")

    assert len(df) == 0
    assert ccm.report("cycles")["records"] == 0


@responses.activate
def test_products_kwarg_overrides_configured_default() -> None:
    responses.add(
        responses.GET,
        "https://endoflife.date/api/v1/products/ubuntu",
        json={
            "result": {
                "name": "ubuntu",
                "label": "Ubuntu",
                "releases": [
                    {
                        "name": "24.04",
                        "isEol": False,
                        "eolFrom": "2029-04-25",
                        "isMaintained": True,
                    }
                ],
            }
        },
        status=200,
    )

    ccm = CCM("endoflife", {"products": "python"})
    df = ccm.collect("cycles", products=["ubuntu"])

    assert len(df) == 1
    assert df.loc[0, "product"] == "ubuntu"
    assert df.loc[0, "cycle"] == "24.04"
    assert bool(df.loc[0, "is_maintained"]) is True
    assert len(responses.calls) == 1


@responses.activate
def test_unknown_product_raises() -> None:
    responses.add(
        responses.GET,
        "https://endoflife.date/api/v1/products/not-a-real-product",
        status=404,
    )

    ccm = CCM("endoflife")
    with pytest.raises(PostureError):
        ccm.collect("cycles", products=["not-a-real-product"])
