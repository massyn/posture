"""BigQuery storage: one project/dataset, one table per name.

Every row carries a "tenancy" column (see TableStorage) plus an
"upload_timestamp". "truncate" is tenancy-scoped, not table-scoped: it
deletes only that tenancy's existing rows before loading the fresh set,
leaving other tenancies' rows in the same table untouched. "append" skips the
delete and just loads on top of whatever's already there.

No tmp-table/rename dance for atomicity — a load job is one BigQuery
operation; a failed load doesn't touch the table's existing rows.

Schema evolution: a column present in ``df`` but not yet in the table is
added automatically by the load job itself (``ALLOW_FIELD_ADDITION``); a
column present in the table but missing from ``df`` is left untouched
(BigQuery never drops it — a load just leaves that column NULL for the new
rows) — logged as a warning so a disappearing upstream field doesn't go
unnoticed.
"""

from __future__ import annotations

import logging
import time
from datetime import timezone
from typing import Any, ClassVar

import pandas as pd

from posture.exceptions import StorageConfigError
from posture.storage.base import TableStorage

logger = logging.getLogger(__name__)

_MAX_LOAD_ATTEMPTS = 5
_RATE_LIMIT_MARKERS = ("429", "ratelimitexceeded", "too many table update")

# Checked in order — the first matching pandas dtype predicate wins.
# Anything that doesn't match (strings, mixed-type "object" columns, etc.)
# falls through to STRING.
_TYPE_MAP = (
    (pd.api.types.is_bool_dtype, "BOOLEAN"),
    (pd.api.types.is_integer_dtype, "INTEGER"),
    (pd.api.types.is_float_dtype, "FLOAT"),
    (pd.api.types.is_datetime64_any_dtype, "DATETIME"),
)


def _bq_type(series: pd.Series) -> str:
    for is_dtype, bq_type in _TYPE_MAP:
        if is_dtype(series.dtype):
            return bq_type
    return "STRING"


def _coerce_for_load(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce object columns to str so pyarrow can serialise them, preserving
    nulls. Exception: object columns holding only bool/None are promoted to
    nullable boolean so BigQuery always sees BOOLEAN rather than STRING (the
    dtype otherwise flips between runs depending on whether any None values
    are present). Datetime columns are cast to microsecond precision and
    stripped of tz — BigQuery's DATETIME is naive microsecond, pandas
    defaults to tz-aware nanosecond."""
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == object:
            non_null = df[col].dropna()
            if len(non_null) > 0 and all(isinstance(v, bool) for v in non_null):
                df[col] = pd.array(df[col], dtype="boolean")
            else:
                df[col] = df[col].where(df[col].isna(), df[col].astype(str))
        elif pd.api.types.is_datetime64_any_dtype(df[col]):
            if getattr(df[col].dtype, "tz", None) is not None:
                df[col] = df[col].dt.tz_localize(None)
            df[col] = df[col].astype("datetime64[us]")
    return df


class BigQueryStorage(TableStorage):
    env_prefix = "POSTURE_BIGQUERY"
    config_keys: ClassVar[dict[str, bool]] = {"project_id": True, "dataset_id": True}

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._project_id = self._config["project_id"]
        self._dataset_id = self._config["dataset_id"]

        try:
            from google.cloud import bigquery
        except ImportError as exc:
            raise StorageConfigError(
                "google-cloud-bigquery is required for the 'bigquery' backend; "
                "install it with `pip install posture[bigquery]`",
                source=self.env_prefix.lower(),
            ) from exc

        self._bigquery = bigquery
        self._client = bigquery.Client(project=self._project_id)

    def __repr__(self) -> str:
        return f"BigQueryStorage(project_id={self._project_id!s}, dataset_id={self._dataset_id!s})"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        bigquery = self._bigquery
        table_id = f"{self._project_id}.{self._dataset_id}.{name}"

        if df.empty:
            return

        df = self._add_tenancy_column(df)
        df["upload_timestamp"] = pd.Timestamp.now(tz=timezone.utc).tz_localize(None)
        df = _coerce_for_load(df)
        self._warn_on_missing_columns(table_id, df.columns)

        if recreate:
            self._delete_tenancy_rows(table_id, self._tenancy)

        schema = [bigquery.SchemaField(col, _bq_type(df[col])) for col in df.columns]
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            schema=schema,
            schema_update_options=[
                bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION,
                bigquery.SchemaUpdateOption.ALLOW_FIELD_RELAXATION,
            ],
        )
        self._load_with_retry(df, table_id, job_config)

    def _warn_on_missing_columns(self, table_id: str, df_columns: Any) -> None:
        from google.api_core.exceptions import NotFound

        try:
            table = self._client.get_table(table_id)
        except NotFound:
            return  # table doesn't exist yet — the load below creates it

        missing_cols = {field.name for field in table.schema} - set(df_columns)
        if missing_cols:
            logger.warning(
                "BigQuery table '%s' has column(s) %s not present in this write; "
                "leaving them untouched",
                table_id,
                sorted(missing_cols),
            )

    def _delete_tenancy_rows(self, table_id: str, tenancy: str) -> None:
        from google.api_core.exceptions import NotFound

        bigquery = self._bigquery
        delete_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("tenancy", "STRING", tenancy)
            ]
        )
        try:
            self._client.query(
                f"DELETE FROM `{table_id}` WHERE tenancy = @tenancy",
                job_config=delete_config,
            ).result()
        except NotFound:
            # Table doesn't exist yet — the load below creates it.
            logger.debug("BigQuery delete for '%s' skipped: table not found", table_id)

    def _load_with_retry(
        self, df: pd.DataFrame, table_id: str, job_config: Any
    ) -> None:
        for attempt in range(1, _MAX_LOAD_ATTEMPTS + 1):
            try:
                job = self._client.load_table_from_dataframe(
                    df, table_id, job_config=job_config
                )
                job.result()
                return
            except Exception as exc:
                if attempt == _MAX_LOAD_ATTEMPTS:
                    raise
                if any(marker in str(exc).lower() for marker in _RATE_LIMIT_MARKERS):
                    wait = 2**attempt
                    logger.warning(
                        "Rate limit hit loading '%s' (attempt %d/%d), retrying in %ds",
                        table_id,
                        attempt,
                        _MAX_LOAD_ATTEMPTS,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    raise
