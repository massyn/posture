from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

from posture.exceptions import StorageConfigError, StorageWriteError
from posture.storage import S3Storage

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})


class _FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_uploads = False

    def put_object(self, *, Bucket: str, Key: str, Body) -> None:
        if self.fail_uploads:
            raise RuntimeError("simulated upload failure")
        self.objects[Key] = Body.read()


@pytest.fixture
def fake_s3(monkeypatch: pytest.MonkeyPatch) -> _FakeS3Client:
    client = _FakeS3Client()
    monkeypatch.setattr("boto3.client", lambda service: client)
    monkeypatch.delenv("TENANT", raising=False)
    return client


def test_s3_truncate_writes_name_tenant_path(fake_s3: _FakeS3Client) -> None:
    store = S3Storage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    assert "hosts/default.parquet" in fake_s3.objects


def test_s3_truncate_overwrites_same_object(fake_s3: _FakeS3Client) -> None:
    store = S3Storage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    store.write(smaller, "hosts", mode="truncate")
    assert len(fake_s3.objects) == 1
    out = pd.read_parquet(
        pd.io.common.BytesIO(fake_s3.objects["hosts/default.parquet"])
    )
    assert out.equals(smaller)


def test_s3_append_is_hive_partitioned(fake_s3: _FakeS3Client) -> None:
    store = S3Storage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="append")
    today = datetime.now(timezone.utc).date()
    expected = (
        f"hosts/default/YEAR={today:%Y}/MONTH={today:%m}/DAY={today:%d}/hosts.parquet"
    )
    assert expected in fake_s3.objects


def test_s3_tenant_env_var_used_in_path(
    fake_s3: _FakeS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANT", "acme")
    store = S3Storage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    assert "hosts/acme.parquet" in fake_s3.objects


def test_s3_write_page_truncate_accumulates_within_run(fake_s3: _FakeS3Client) -> None:
    store = S3Storage({"bucket": "my-bucket"})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    assert sum(1 for key in fake_s3.objects if key.startswith("hosts/default/")) == 2


def test_s3_missing_bucket_raises(fake_s3: _FakeS3Client) -> None:
    with pytest.raises(StorageConfigError, match="Missing required config 'bucket'"):
        S3Storage({})


def test_s3_write_failure_wrapped_as_storage_write_error(
    fake_s3: _FakeS3Client,
) -> None:
    store = S3Storage({"bucket": "my-bucket"})
    fake_s3.fail_uploads = True
    with pytest.raises(StorageWriteError) as exc_info:
        store.write(_DF, "hosts", mode="truncate")
    assert exc_info.value.__cause__ is not None
