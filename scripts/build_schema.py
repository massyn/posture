"""Generate markdown documentation for every registered collector.

Reads posture's own ``catalog()`` — never a hardcoded source/resource list —
so the generated docs never drift out of sync with what the library actually
offers. Writes ``docs/index.md`` (one row per collector, linked to its page)
and ``docs/collectors/<source>.md`` (env vars, an example query, and the
column schema for every table) for each registered source.

    python scripts/build_schema.py
"""

from pathlib import Path

from jinja2 import Environment

from posture import catalog

_DOCS_DIR = Path("docs")
_COLLECTORS_DIR = _DOCS_DIR / "collectors"

_env = Environment(trim_blocks=True, lstrip_blocks=True)

_INDEX_TEMPLATE = _env.from_string(
    """\
# Collectors

{% for source in sources %}\
## [{{ source.display_name }}](collectors/{{ source.name }}.md)

{% for resource in source.resources %}\
- [{{ resource.name }}](collectors/{{ source.name }}.md#{{ resource.name }})
{% endfor %}

{% endfor %}\
"""
)

_COLLECTOR_TEMPLATE = _env.from_string(
    """\
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
No configuration required.
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
"""
)


def build() -> None:
    _COLLECTORS_DIR.mkdir(parents=True, exist_ok=True)

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
                "resources": resources,
            }
        )
    sources.sort(key=lambda s: s["display_name"].lower())

    (_DOCS_DIR / "index.md").write_text(
        _INDEX_TEMPLATE.render(sources=sources), encoding="utf-8"
    )

    for source in sources:
        page = _COLLECTOR_TEMPLATE.render(source=source)
        (_COLLECTORS_DIR / f"{source['name']}.md").write_text(page, encoding="utf-8")

    print(f"Wrote docs/index.md and {len(sources)} collector page(s) to docs/collectors/")


if __name__ == "__main__":
    build()
