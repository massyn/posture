import json
from pathlib import Path

from posture.collectors.securityscorecard import MANIFEST
from posture.parse import parse

FIXTURES = Path(__file__).parent / "fixtures" / "securityscorecard"


def _load(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text())


def test_portfolio_companies_page() -> None:
    df = parse(
        _load("portfolio_companies_page.json"),
        MANIFEST["portfolio_companies"],
        resource="portfolio_companies",
    )

    assert len(df) == 2
    assert df.loc[0, "domain"] == "example.com"
    assert int(df.loc[0, "score"]) == 88
    assert int(df.loc[0, "last30day_score_change"]) == -2
    assert df.loc[0, "portfolio_id"] == "60c0e4f9a0b1c20010a1b2c3"
    assert df["created_at"].dtype == "datetime64[us, UTC]"


def test_company_factors_page() -> None:
    df = parse(
        _load("company_factors_page.json"),
        MANIFEST["company_factors"],
        resource="company_factors",
    )

    assert len(df) == 2
    assert df.loc[0, "domain"] == "example.com"
    assert df.loc[0, "name"] == "network_security"
    assert int(df.loc[1, "score"]) == 70
    assert isinstance(df.loc[0, "issue_summary"], str)
    assert "open_ports" in df.loc[0, "issue_summary"]
