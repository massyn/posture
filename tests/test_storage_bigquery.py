from __future__ import annotations

import pandas as pd
import pytest

from posture.exceptions import StorageConfigError, StorageWriteError
from posture.storage import BigQueryStorage

_DF = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})


class _FakeJob:
    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail

    def result(self):
        if self._fail:
            raise RuntimeError("simulated job failure")


class _FakeClient:
    def __init__(self) -> None:
        self.deletes: list[tuple[str, str]] = []  # (table_id, tenant)
        self.loads: list[tuple[pd.DataFrame, str]] = []
        self.fail_loads = False

    def query(self, query: str, job_config) -> _FakeJob:
        tenant = job_config.query_parameters[0].value
        table_id = query.split("`")[1]
        self.deletes.append((table_id, tenant))
        return _FakeJob()

    def load_table_from_dataframe(self, df, table_id, job_config) -> _FakeJob:
        self.loads.append((df.copy(), table_id))
        return _FakeJob(fail=self.fail_loads)


@pytest.fixture
def fake_bq(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr("google.cloud.bigquery.Client", lambda project: client)
    monkeypatch.delenv("TENANT", raising=False)
    return client


def test_bigquery_truncate_deletes_then_loads(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")
    assert fake_bq.deletes == [("proj.ds.hosts", "default")]
    assert len(fake_bq.loads) == 1
    loaded_df, table_id = fake_bq.loads[0]
    assert table_id == "proj.ds.hosts"
    assert list(loaded_df["a"]) == [1, 2]
    assert (loaded_df["tenant"] == "default").all()
    assert "upload_timestamp" in loaded_df.columns


def test_bigquery_append_skips_delete(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="append")
    assert fake_bq.deletes == []
    assert len(fake_bq.loads) == 1


def test_bigquery_tenant_env_var_used(
    fake_bq: _FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANT", "acme")
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")
    assert fake_bq.deletes == [("proj.ds.hosts", "acme")]
    loaded_df, _ = fake_bq.loads[0]
    assert (loaded_df["tenant"] == "acme").all()


def test_bigquery_empty_dataframe_is_noop(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(pd.DataFrame({"a": [], "b": []}), "hosts", mode="truncate")
    assert fake_bq.deletes == []
    assert fake_bq.loads == []


def test_bigquery_missing_config_raises(fake_bq: _FakeClient) -> None:
    with pytest.raises(StorageConfigError, match="Missing required config"):
        BigQueryStorage({"project_id": "proj"})


def test_bigquery_load_failure_wrapped_as_storage_write_error(
    fake_bq: _FakeClient,
) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    fake_bq.fail_loads = True
    with pytest.raises(StorageWriteError) as exc_info:
        store.write(_DF, "hosts", mode="truncate")
    assert exc_info.value.__cause__ is not None
