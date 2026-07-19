from unittest.mock import MagicMock, patch

from posture import CCM


def test_assets_collected_via_pytenable_export() -> None:
    fake_tio = MagicMock()
    fake_tio.exports.assets.return_value = iter(
        [{"id": "asset-1", "hostnames": ["host1.example.com"]}]
    )

    with patch("tenable.io.TenableIO", return_value=fake_tio) as fake_ctor:
        ccm = CCM("tenableio", {"access_key": "ak", "secret_key": "sk"})
        df = ccm.collect("assets")

    fake_ctor.assert_called_once_with(
        access_key="ak", secret_key="sk", retries=5, backoff=1
    )
    assert len(df) == 1
    assert df.loc[0, "asset_id"] == "asset-1"
    assert ccm.report("assets")["pages"] == 1


def test_vulnerabilities_collected_via_pytenable_export() -> None:
    fake_tio = MagicMock()
    fake_tio.exports.vulns.return_value = iter(
        [{"asset": {"uuid": "asset-uuid-1"}, "plugin": {"id": 1}, "severity": "low"}]
    )

    with patch("tenable.io.TenableIO", return_value=fake_tio):
        ccm = CCM("tenableio", {"access_key": "ak", "secret_key": "sk"})
        df = ccm.collect("vulnerabilities")

    assert len(df) == 1
    assert df.loc[0, "asset_uuid"] == "asset-uuid-1"
    assert df.loc[0, "severity"] == "low"
