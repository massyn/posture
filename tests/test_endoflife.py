import pytest
import responses

from posture import CCM
from posture.exceptions import PostureError


def _release(name: str) -> dict:
    return {"name": name, "isEol": False, "isMaintained": True}


@responses.activate
def test_no_products_configured_fetches_every_product_in_one_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENDOFLIFE_PRODUCTS", raising=False)
    responses.add(
        responses.GET,
        "https://endoflife.date/api/v1/products/full",
        json={
            "result": [
                {"name": "python", "label": "Python", "releases": [_release("3.13")]},
                {
                    "name": "ubuntu",
                    "label": "Ubuntu",
                    "releases": [_release("24.04"), _release("22.04")],
                },
                {"name": "empty", "label": "Empty", "releases": []},
            ]
        },
        status=200,
    )

    df = CCM("endoflife").collect("cycles")

    assert list(df["product"]) == ["python", "ubuntu", "ubuntu"]
    assert list(df["cycle"]) == ["3.13", "24.04", "22.04"]
    assert df.loc[1, "product_label"] == "Ubuntu"
    assert len(responses.calls) == 1


@responses.activate
def test_products_env_var_accepts_commas_and_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENDOFLIFE_PRODUCTS", " python, ubuntu  debian,")
    for product in ("python", "ubuntu", "debian"):
        responses.add(
            responses.GET,
            f"https://endoflife.date/api/v1/products/{product}",
            json={"result": {"name": product, "releases": [_release("1")]}},
            status=200,
        )

    df = CCM("endoflife").collect("cycles")

    assert list(df["product"]) == ["python", "ubuntu", "debian"]
    assert len(responses.calls) == 3


@responses.activate
def test_products_resource_lists_every_product() -> None:
    responses.add(
        responses.GET,
        "https://endoflife.date/api/v1/products",
        json={
            "result": [
                {"name": "python", "aliases": [], "label": "Python"},
                {"name": "alpine-linux", "aliases": ["alpine"], "label": "Alpine"},
            ]
        },
        status=200,
    )

    df = CCM("endoflife", {"products": "python"}).collect("products")

    assert list(df["product"]) == ["python", "alpine-linux"]
    assert len(responses.calls) == 1


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
