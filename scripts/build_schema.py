"""Generate markdown documentation for every registered collector and
storage backend.

Reads posture's own ``catalog()``/``storage_catalog()`` — never a hardcoded
source/resource/backend list — so the generated docs never drift out of
sync with what the library actually offers. Writes ``docs/index.md`` (one
row per collector plus a storage backend section), ``docs/collectors/
<source>.md`` (env vars, an example query, and the column schema for every
table) for each registered source, and ``docs/storage/<backend>.md`` (env
vars and a write example) for each registered storage backend.

    python scripts/build_schema.py
"""

from pathlib import Path

from jinja2 import Environment

from posture import catalog, storage_catalog

_DOCS_DIR = Path("docs")
_COLLECTORS_DIR = _DOCS_DIR / "collectors"
_STORAGE_DIR = _DOCS_DIR / "storage"

_env = Environment(trim_blocks=True, lstrip_blocks=True)

_INDEX_TEMPLATE = _env.from_string("""\
# Collectors

{% for source in sources %}\
## [{{ source.display_name }}](collectors/{{ source.name }}.md)

{% for resource in source.resources %}\
- [{{ resource.name }}](collectors/{{ source.name }}.md#{{ resource.name }})
{% endfor %}

{% endfor %}\
# Storage backends

{% for backend in backends %}\
- [{{ backend.name }}](storage/{{ backend.name }}.md)
{% endfor %}
""")

_COLLECTOR_TEMPLATE = _env.from_string("""\
# {{ source.display_name }}

[← back to index](../index.md)

## Environment variables

{% if source.required_config %}\
| Config key | Environment variable |
| --- | --- |
{% for key, env_var in source.required_config.items() %}\
| `{{ key }}` | `{{ env_var }}` |
{% endfor %}
{% else %}\
No required configuration.
{% endif %}

{% if source.optional_config %}\
### Optional

| Config key | Environment variable |
| --- | --- |
{% for key, env_var in source.optional_config.items() %}\
| `{{ key }}` | `{{ env_var }}` |
{% endfor %}
{% endif %}

## Example

```python
from posture import CCM

ccm = CCM("{{ source.name }}")  # credentials from {{ source.required_config.values()|join(', ') if source.required_config else 'the environment' }}
{% for resource in source.resources %}
df = ccm.collect("{{ resource.name }}")
{% endfor %}
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("{{ source.name }}")  # credentials from {{ source.required_config.values()|join(', ') if source.required_config else 'the environment' }}

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

{% for resource in source.resources %}\
- [{{ resource.name }}](#{{ resource.name }})
{% endfor %}

{% for resource in source.resources %}\
### {{ resource.name }}

{% if resource.derived_from %}\
Derived from [`{{ resource.derived_from }}`](#{{ resource.derived_from }}) — no separate network call.

{% endif %}\
| Column | Type |
| --- | --- |
{% for column in resource.columns %}\
| `{{ column }}` | `{{ resource.column_types[column] }}` |
{% endfor %}

{% endfor %}\
""")

_STORAGE_TEMPLATE = _env.from_string("""\
# {{ backend.class_name }}

[← back to index](../index.md)

## Environment variables

{% if backend.required_config %}\
| Config key | Environment variable |
| --- | --- |
{% for key, env_var in backend.required_config.items() %}\
| `{{ key }}` | `{{ env_var }}` |
{% endfor %}
{% else %}\
No required configuration — check the class docstring for constraints
required/optional flags can't express (e.g. Postgres requires either "dsn"
or discrete host/dbname/user/password, but each key alone is optional).
{% endif %}

{% if backend.optional_config %}\
### Optional

| Config key | Environment variable |
| --- | --- |
{% for key, env_var in backend.optional_config.items() %}\
| `{{ key }}` | `{{ env_var }}` |
{% endfor %}
{% endif %}

## Example

```python
from posture import write_storage

write_storage(df, "{{ backend.name }}", "table_name", config={ ... })
```

For a paginated collection, use `Storage()` and call `write_page()` once per page instead:

```python
from posture import Storage

store = Storage("{{ backend.name }}", config={ ... })
for page in ccm.collect_page("table_name"):
    store.write_page(page, "table_name", mode="truncate")
```
""")


def build() -> None:
    _COLLECTORS_DIR.mkdir(parents=True, exist_ok=True)
    _STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    sources = []
    for name, info in catalog().items():
        resources = [
            {
                "name": resource,
                "derived_from": data["derived_from"],
                "columns": data["columns"],
                "column_types": data["column_types"],
            }
            for resource, data in sorted(info["resources"].items())
        ]
        sources.append(
            {
                "name": name,
                "display_name": info["display_name"],
                "required_config": info["required_config"],
                "optional_config": info["optional_config"],
                "resources": resources,
            }
        )
    sources.sort(key=lambda s: s["display_name"].lower())

    backends = [
        {
            "name": name,
            "class_name": info["class_name"],
            "required_config": info["required_config"],
            "optional_config": info["optional_config"],
        }
        for name, info in sorted(storage_catalog().items())
    ]

    (_DOCS_DIR / "index.md").write_text(
        _INDEX_TEMPLATE.render(sources=sources, backends=backends), encoding="utf-8"
    )

    for source in sources:
        page = _COLLECTOR_TEMPLATE.render(source=source)
        (_COLLECTORS_DIR / f"{source['name']}.md").write_text(page, encoding="utf-8")

    for backend in backends:
        page = _STORAGE_TEMPLATE.render(backend=backend)
        (_STORAGE_DIR / f"{backend['name']}.md").write_text(page, encoding="utf-8")

    print(
        f"Wrote docs/index.md, {len(sources)} collector page(s) to docs/collectors/, "
        f"and {len(backends)} storage backend page(s) to docs/storage/"
    )


if __name__ == "__main__":
    build()
