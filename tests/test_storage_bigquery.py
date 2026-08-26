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


class _FakeField:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeTable:
    def __init__(self, columns: list[str]) -> None:
        self.schema = [_FakeField(col) for col in columns]


class _FakeClient:
    def __init__(self) -> None:
        self.deletes: list[tuple[str, str]] = []  # (table_id, tenancy)
        self.loads: list[tuple[pd.DataFrame, str]] = []
        self.fail_loads = False
        # table_id -> known columns, simulating BigQuery's own schema state
        # (updated after each successful load, same as ALLOW_FIELD_ADDITION
        # actually behaves).
        self.tables: dict[str, list[str]] = {}

    def get_table(self, table_id: str) -> _FakeTable:
        from google.api_core.exceptions import NotFound

        if table_id not in self.tables:
            raise NotFound(table_id)
        return _FakeTable(self.tables[table_id])

    def query(self, query: str, job_config) -> _FakeJob:
        tenancy = job_config.query_parameters[0].value
        table_id = query.split("`")[1]
        self.deletes.append((table_id, tenancy))
        return _FakeJob()

    def load_table_from_dataframe(self, df, table_id, job_config) -> _FakeJob:
        self.loads.append((df.copy(), table_id))
        if not self.fail_loads:
            existing = self.tables.get(table_id, [])
            self.tables[table_id] = existing + [
                col for col in df.columns if col not in existing
            ]
        return _FakeJob(fail=self.fail_loads)


@pytest.fixture
def fake_bq(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr("google.cloud.bigquery.Client", lambda project: client)
    monkeypatch.delenv("TENANCY", raising=False)
    return client


def test_bigquery_truncate_deletes_then_loads(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")
    assert fake_bq.deletes == [("proj.ds.hosts", "default")]
    assert len(fake_bq.loads) == 1
    loaded_df, table_id = fake_bq.loads[0]
    assert table_id == "proj.ds.hosts"
    assert list(loaded_df["a"]) == [1, 2]
    assert (loaded_df["tenancy"] == "default").all()
    assert "upload_timestamp" in loaded_df.columns


def test_bigquery_append_skips_delete(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="append")
    assert fake_bq.deletes == []
    assert len(fake_bq.loads) == 1


def test_bigquery_tenancy_env_var_used(
    fake_bq: _FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TENANCY", "acme")
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")
    assert fake_bq.deletes == [("proj.ds.hosts", "acme")]
    loaded_df, _ = fake_bq.loads[0]
    assert (loaded_df["tenancy"] == "acme").all()


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


def test_bigquery_new_column_is_loaded_without_error(fake_bq: _FakeClient) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")

    wider = _DF.copy()
    wider["c"] = ["p", "q"]
    store.write(wider, "hosts", mode="truncate")

    loaded_df, _ = fake_bq.loads[-1]
    assert "c" in loaded_df.columns


def test_bigquery_warns_on_missing_column(
    fake_bq: _FakeClient, caplog: pytest.LogCaptureFixture
) -> None:
    store = BigQueryStorage({"project_id": "proj", "dataset_id": "ds"})
    store.write(_DF, "hosts", mode="truncate")

    narrower = _DF[["a"]]
    with caplog.at_level("WARNING"):
        store.write(narrower, "hosts", mode="truncate")

    assert any("'b'" in record.getMessage() for record in caplog.records)
