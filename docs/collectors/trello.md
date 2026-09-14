# Trello

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `api_key` | `TRELLO_API_KEY` |
| `token` | `TRELLO_TOKEN` |

### Optional

| Config key | Environment variable |
| --- | --- |
| `board` | `TRELLO_BOARD` |

## Example

```python
from posture import CCM

ccm = CCM("trello")  # credentials from TRELLO_API_KEY, TRELLO_TOKEN
df = ccm.collect("boards")
df = ccm.collect("cards")
df = ccm.collect("lists")
df = ccm.collect("members")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("trello")  # credentials from TRELLO_API_KEY, TRELLO_TOKEN

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [boards](#boards)
- [cards](#cards)
- [lists](#lists)
- [members](#members)

### boards

| Column | Type |
| --- | --- |
| `id` | `str` |
| `name` | `str` |
| `url` | `str` |
| `closed` | `bool` |

### cards

| Column | Type |
| --- | --- |
| `id` | `str` |
| `id_board` | `str` |
| `name` | `str` |
| `id_list` | `str` |
| `id_members` | `json` |
| `due` | `datetime` |
| `date_last_activity` | `datetime` |
| `url` | `str` |
| `closed` | `bool` |

### lists

| Column | Type |
| --- | --- |
| `id` | `str` |
| `id_board` | `str` |
| `name` | `str` |
| `closed` | `bool` |

### members

| Column | Type |
| --- | --- |
| `id` | `str` |
| `id_board` | `str` |
| `username` | `str` |
| `full_name` | `str` |

