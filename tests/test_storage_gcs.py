from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

from posture.exceptions import StorageConfigError, StorageWriteError
from posture.storage import GcsStorage

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})


class _FakeBlob:
    def __init__(self, bucket: _FakeBucket, name: str) -> None:
        self.bucket = bucket
        self.name = name

    def upload_from_file(self, buffer, content_type: str) -> None:
        if self.bucket.fail_uploads:
            raise RuntimeError("simulated upload failure")
        self.bucket.blobs[self.name] = buffer.read()


class _FakeBucket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.blobs: dict[str, bytes] = {}
        self.fail_uploads = False

    def blob(self, name: str) -> _FakeBlob:
        return _FakeBlob(self, name)


class _FakeClient:
    def __init__(self) -> None:
        self.buckets: dict[str, _FakeBucket] = {}

    def bucket(self, name: str) -> _FakeBucket:
        return self.buckets.setdefault(name, _FakeBucket(name))


@pytest.fixture
def fake_gcs(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr("google.cloud.storage.Client", lambda: client)
    monkeypatch.delenv("TENANT", raising=False)
    return client


def test_gcs_truncate_writes_name_tenant_path(fake_gcs: _FakeClient) -> None:
    store = GcsStorage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    assert "hosts/default.parquet" in fake_gcs.buckets["my-bucket"].blobs


def test_gcs_truncate_overwrites_same_blob(fake_gcs: _FakeClient) -> None:
    store = GcsStorage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    smaller = pd.DataFrame({"a": [9], "b": ["z"]})
    store.write(smaller, "hosts", mode="truncate")
    bucket = fake_gcs.buckets["my-bucket"]
    assert len(bucket.blobs) == 1
    out = pd.read_parquet(pd.io.common.BytesIO(bucket.blobs["hosts/default.parquet"]))
    assert out.equals(smaller)


def test_gcs_append_is_dated(fake_gcs: _FakeClient) -> None:
    store = GcsStorage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="append")
    today = datetime.now(timezone.utc).date()
    expected = f"hosts/default/{today:%Y-%m-%d}.parquet"
    assert expected in fake_gcs.buckets["my-bucket"].blobs


def test_gcs_tenant_env_var_used_in_path(
    fake_gcs: _FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANT", "acme")
    store = GcsStorage({"bucket": "my-bucket"})
    store.write(_DF, "hosts", mode="truncate")
    assert "hosts/acme.parquet" in fake_gcs.buckets["my-bucket"].blobs


def test_gcs_write_page_truncate_accumulates_within_run(fake_gcs: _FakeClient) -> None:
    store = GcsStorage({"bucket": "my-bucket"})
    store.write_page(_DF, "hosts", mode="truncate")
    store.write_page(_DF, "hosts", mode="truncate")
    bucket = fake_gcs.buckets["my-bucket"]
    assert sum(1 for name in bucket.blobs if name.startswith("hosts/default/")) == 2


def test_gcs_missing_bucket_raises(fake_gcs: _FakeClient) -> None:
    with pytest.raises(StorageConfigError, match="Missing required config 'bucket'"):
        GcsStorage({})


def test_gcs_write_failure_wrapped_as_storage_write_error(
    fake_gcs: _FakeClient,
) -> None:
    store = GcsStorage({"bucket": "my-bucket"})
    fake_gcs.bucket("my-bucket").fail_uploads = True
    with pytest.raises(StorageWriteError) as exc_info:
        store.write(_DF, "hosts", mode="truncate")
    assert exc_info.value.__cause__ is not None
