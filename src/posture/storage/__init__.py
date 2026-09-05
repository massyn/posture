"""Storage backends: DataFrame in, durably written somewhere, out.

    from posture.storage import write_storage

    write_storage(df, "parquet", "crowdstrike_hosts", config={"path": "./data"})

For a paginated collection (Collector.collect_page()), hold a backend
instance and call write_page() once per page instead — open_storage() is a
factory mirroring posture.CCM(), for when the backend is only known at
runtime (a config value, a CLI flag) rather than hardcoded:

    from posture.storage import open_storage

    csv_store = open_storage("csv", {"path": "./data"})
    for page in ccm.collect_page("hosts"):
        csv_store.write_page(page, "crowdstrike_hosts", mode="truncate")

A concrete class also works the same way when the backend IS hardcoded and
an explicit type is more useful than a string:

    from posture.storage import CsvStorage

    csv_store = CsvStorage({"path": "./data"})

``ParquetStorage`` additionally exposes ``write_stream()``, which appends each
page as a row group of one output file instead of writing one file per page
(see its docstring) — parquet-only, not part of the common ``StorageBackend``
interface every other backend satisfies.

No backend module is imported until it's actually used — same lazy-import
convention as ``posture.CCM``/``catalog()`` use for collectors — so
``import posture`` never pays for ``psycopg``/``duckdb``/``pyarrow`` unless
that backend is actually reached. ``from posture.storage import CsvStorage``
imports only ``posture.storage.csv``, via module ``__getattr__`` (PEP 562).
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from posture.exceptions import StorageConfigError
from posture.storage.base import StorageBackend

__all__ = [
    "BigQueryStorage",
    "CsvStorage",
    "DuckdbStorage",
    "GcsStorage",
    "JsonStorage",
    "ParquetStorage",
    "PostgresStorage",
    "S3Storage",
    "SnowflakeStorage",
    "SqliteStorage",
    "StorageBackend",
    "open_storage",
    "storage_catalog",
    "write_storage",
]

# storage key (as passed to write_storage) -> (submodule, class name).
_BACKENDS: dict[str, tuple[str, str]] = {
    "bigquery": ("posture.storage.bigquery", "BigQueryStorage"),
    "csv": ("posture.storage.csv", "CsvStorage"),
    "duckdb": ("posture.storage.duckdb", "DuckdbStorage"),
    "gcs": ("posture.storage.gcs", "GcsStorage"),
    "json": ("posture.storage.json", "JsonStorage"),
    "parquet": ("posture.storage.parquet", "ParquetStorage"),
    "postgres": ("posture.storage.postgres", "PostgresStorage"),
    "s3": ("posture.storage.s3", "S3Storage"),
    "snowflake": ("posture.storage.snowflake", "SnowflakeStorage"),
    "sqlite": ("posture.storage.sqlite", "SqliteStorage"),
}

# Reverse lookup for module-level __getattr__: class name -> storage key.
_CLASS_TO_KEY = {cls_name: key for key, (_, cls_name) in _BACKENDS.items()}

# Populated by _register_backends(), same lazy-until-actually-needed pattern
# as posture._SOURCES/_register_sources() for collectors.
_BACKEND_CLASSES: dict[str, type[StorageBackend]] = {}


def _backend_class(storage: str) -> type[StorageBackend]:
    try:
        module_path, cls_name = _BACKENDS[storage]
    except KeyError:
        raise StorageConfigError(
            f"Unknown storage '{storage}'. Available: {sorted(_BACKENDS)}"
        ) from None
    return getattr(import_module(module_path), cls_name)


def _register_backends() -> None:
    if _BACKEND_CLASSES:
        return
    for key in _BACKENDS:
        _BACKEND_CLASSES[key] = _backend_class(key)


def __getattr__(name: str) -> Any:
    """PEP 562 lazy attribute access, so ``from posture.storage import
    CsvStorage`` only imports ``posture.storage.csv`` — not every backend."""
    key = _CLASS_TO_KEY.get(name)
    if key is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    cls = _backend_class(key)
    globals()[name] = cls  # cache: subsequent access skips __getattr__ entirely
    return cls


def open_storage(storage: str, config: dict[str, Any] | None = None) -> StorageBackend:
    """Construct a storage backend instance for repeated writes — mirrors
    ``posture.CCM()`` for collectors: one instance = one write target.

    Named ``open_storage`` rather than ``Storage`` so it doesn't collide with
    ``posture.storage.base.Storage``, the unrelated ABC file-based backends
    (csv/json/parquet) inherit from — the two aren't interchangeable, and
    sharing a name made that easy to miss.

    Use this instead of importing a concrete backend class by name when the
    backend is only known at runtime; use it for a paginated collection via
    write_page() (see module docstring), or just to hold one instance across
    several write() calls to the same target.

    ``storage`` is one of "csv", "json", "parquet", "sqlite", "duckdb",
    "postgres", "gcs", "s3", "bigquery", "snowflake" — same set
    write_storage() accepts.
    """
    return _backend_class(storage)(config)


def write_storage(
    df: Any,
    storage: str,
    name: str,
    config: dict[str, Any] | None = None,
    *,
    mode: str = "truncate",
) -> None:
    """Write ``df`` as ``name`` to ``storage`` in one shot.

    ``storage`` is one of "csv", "json", "parquet", "sqlite", "duckdb",
    "postgres", "gcs", "s3", "bigquery", "snowflake". ``mode``:
    "truncate" overwrites/replaces, "append" keeps a dated history. For
    per-page writes during a paginated collection, use open_storage() to
    build an instance and call write_page() on it instead (see module
    docstring).
    """
    _backend_class(storage)(config).write(df, name, mode=mode)


def storage_catalog() -> dict[str, Any]:
    """Return what posture's storage layer has to offer, read straight off
    the backend classes — the storage-side equivalent of ``posture.catalog()``.

    No instantiation, no credentials, no writes — just the registered
    backends and the config keys each declares (as constructor keys and the
    env vars they fall back to). Importing this catalog imports every
    backend module (same tradeoff ``catalog()`` makes for collectors) — the
    lazy-import guarantee is about ``import posture`` alone, not about
    calling this.

    A backend's ``config_keys`` only reflects what it can express as plain
    "required"/"optional" per-key flags. PostgresStorage's dsn/host/dbname/
    user/password are all listed as optional here even though one specific
    combination (``dsn`` alone, or all four discrete keys) is actually
    required — that either/or logic lives in its own ``__init__``, not in
    ``config_keys``. Check a backend's own docstring for constraints like
    that beyond simple required/optional.
    """
    _register_backends()
    catalog: dict[str, Any] = {}
    for key, cls in sorted(_BACKEND_CLASSES.items()):
        catalog[key] = {
            "class_name": cls.__name__,
            "required_config": {
                config_key: f"{cls.env_prefix}_{config_key.upper()}"
                for config_key, required in cls.config_keys.items()
                if required
            },
            "optional_config": {
                config_key: f"{cls.env_prefix}_{config_key.upper()}"
                for config_key, required in cls.config_keys.items()
                if not required
            },
        }
    return catalog
