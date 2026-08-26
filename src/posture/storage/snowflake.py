"""Snowflake storage: one database/schema, one table per name.

Every credential and connection setting is resolved from config/env vars —
none of it is hardcoded. In particular ``authenticator`` (password,
key-pair, workload identity, OAuth, ...) has no default: a generic library
can't assume a tenancy's auth method, so it must be stated explicitly, either
via config or ``POSTURE_SNOWFLAKE_AUTHENTICATOR``. ``role``/``warehouse``
are optional with no default — if unset, Snowflake falls back to the
connecting user's own account defaults rather than this library guessing a
tenancy-specific name. ``schema`` IS required (unlike role/warehouse) because
this backend's own generated SQL (CREATE TABLE/DELETE) has to fully qualify
`database.schema.table` itself — there's no "session default" to fall back
to for statements this class builds.

Every row carries a "tenancy" column (see TableStorage), so "truncate" means
tenancy-scoped: DELETE rows for the current tenancy, then insert the fresh
set, leaving other tenancies' rows in the same table untouched. "append" just
inserts.

No tmp-table/rename dance for atomicity — write_pandas() is Snowflake's own
bulk-load primitive; a failed load doesn't touch the table's existing rows.

Schema evolution: a column present in ``df`` but not yet in the table is
added (``ALTER TABLE ADD COLUMN``); a column present in the table but
missing from ``df`` is left untouched (never dropped) — just logged as a
warning, since it usually means an upstream field disappeared rather than
something this library should act on unasked.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import pandas as pd

from posture.exceptions import StorageConfigError
from posture.storage.base import TableStorage

logger = logging.getLogger("posture.storage.snowflake")

# Optional connect() kwargs, resolved from config/env if present and passed
# through verbatim — covers password auth (user/password), key-pair auth
# (private_key_file/private_key_file_pwd), and workload identity
# (workload_identity_provider), without this library favouring any one of
# them.
_OPTIONAL_CONNECT_KEYS = (
    "user",
    "password",
    "role",
    "warehouse",
    "workload_identity_provider",
    "private_key_file",
    "private_key_file_pwd",
)

# Checked in order — the first matching pandas dtype predicate wins.
# Anything that doesn't match (strings, mixed-type "object" columns, etc.)
# falls through to VARCHAR.
_TYPE_MAP = (
    (pd.api.types.is_bool_dtype, "BOOLEAN"),
    (pd.api.types.is_integer_dtype, "INTEGER"),
    (pd.api.types.is_float_dtype, "FLOAT"),
    (pd.api.types.is_datetime64_any_dtype, "TIMESTAMP_NTZ"),
)


def _sf_type(series: pd.Series) -> str:
    for is_dtype, sf_type in _TYPE_MAP:
        if is_dtype(series.dtype):
            return sf_type
    return "VARCHAR"


class SnowflakeStorage(TableStorage):
    env_prefix = "POSTURE_SNOWFLAKE"
    config_keys: ClassVar[dict[str, bool]] = {
        "account": True,
        "database": True,
        "schema": True,
        "authenticator": True,
        "user": False,
        "password": False,
        "role": False,
        "warehouse": False,
        "workload_identity_provider": False,
        "private_key_file": False,
        "private_key_file_pwd": False,
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._database = self._config["database"]
        self._schema = self._config["schema"]

        try:
            import snowflake.connector
        except ImportError as exc:
            raise StorageConfigError(
                "snowflake-connector-python is required for the 'snowflake' "
                "backend; install it with `pip install posture[snowflake]`",
                source=self.env_prefix.lower(),
            ) from exc

        connect_kwargs: dict[str, Any] = {
            "account": self._config["account"],
            "authenticator": self._config["authenticator"],
            "database": self._database,
            "schema": self._schema,
        }
        for key in _OPTIONAL_CONNECT_KEYS:
            if key in self._config:
                connect_kwargs[key] = self._config[key]

        self._conn = snowflake.connector.connect(**connect_kwargs)

    def __repr__(self) -> str:
        return f"SnowflakeStorage(account={self._config['account']!s}, database={self._database!s})"

    def _write_table(self, df: pd.DataFrame, name: str, *, recreate: bool) -> None:
        from snowflake.connector.pandas_tools import write_pandas

        df = self._add_tenancy_column(df)
        table_name = name.upper()

        self._create_table_if_missing(table_name, df)
        self._sync_columns(table_name, df)
        if recreate:
            self._delete_tenancy_rows(table_name)
        if df.empty:
            return

        # use_logical_type=True: without it, write_pandas() serialises
        # datetime columns to Parquet using the raw physical INT64 type
        # rather than a timestamp logical type, so COPY INTO tries to parse
        # the raw epoch integer as a date string and every row fails with
        # "Invalid date".
        success, _, _, _ = write_pandas(
            self._conn,
            df,
            table_name,
            database=self._database,
            schema=self._schema,
            quote_identifiers=False,
            use_logical_type=True,
        )
        if not success:
            raise RuntimeError(
                f"write_pandas reported failure for table '{table_name}'"
            )

    def _table_ref(self, table_name: str) -> str:
        return f"{self._database}.{self._schema}.{table_name}"

    def _create_table_if_missing(self, table_name: str, df: pd.DataFrame) -> None:
        columns = ", ".join(f"{col.upper()} {_sf_type(df[col])}" for col in df.columns)
        cur = self._conn.cursor()
        try:
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {self._table_ref(table_name)} ({columns})"
            )
        finally:
            cur.close()

    def _sync_columns(self, table_name: str, df: pd.DataFrame) -> None:
        cur = self._conn.cursor()
        try:
            cur.execute(f"SELECT * FROM {self._table_ref(table_name)} LIMIT 0")
            existing = {desc[0] for desc in cur.description}
        finally:
            cur.close()

        # Snowflake normalises unquoted identifiers to uppercase, so compare
        # (and add) against df's uppercased names, matching what
        # _create_table_if_missing already created them as.
        df_cols_upper = {col.upper(): col for col in df.columns}
        new_cols = [
            orig for upper, orig in df_cols_upper.items() if upper not in existing
        ]
        missing_cols = existing - set(df_cols_upper)

        if new_cols:
            cur = self._conn.cursor()
            try:
                for col in new_cols:
                    cur.execute(
                        f"ALTER TABLE {self._table_ref(table_name)} "
                        f"ADD COLUMN {col.upper()} {_sf_type(df[col])}"
                    )
            finally:
                cur.close()

        if missing_cols:
            logger.warning(
                "snowflake table '%s' has column(s) %s not present in this write; "
                "leaving them untouched",
                table_name,
                sorted(missing_cols),
            )

    def _delete_tenancy_rows(self, table_name: str) -> None:
        cur = self._conn.cursor()
        try:
            cur.execute(
                f"DELETE FROM {self._table_ref(table_name)} WHERE TENANCY = %s",
                (self._tenancy,),
            )
        finally:
            cur.close()
