# Precise

[← back to index](../index.md)

## Environment variables

| Config key | Environment variable |
| --- | --- |
| `token` | `PRECISE_TOKEN` |
| `instance` | `PRECISE_INSTANCE` |


## Example

```python
from posture import CCM

ccm = CCM("precise")  # credentials from PRECISE_TOKEN, PRECISE_INSTANCE
df = ccm.collect("profile_certifications")
df = ccm.collect("profile_conferences")
df = ccm.collect("profile_education")
df = ccm.collect("profile_experience")
df = ccm.collect("profile_network")
df = ccm.collect("profile_skills")
df = ccm.collect("profile_tracks")
df = ccm.collect("profiles")
```

## Example: export every table to CSV

```python
from pathlib import Path

from posture import CCM

ccm = CCM("precise")  # credentials from PRECISE_TOKEN, PRECISE_INSTANCE

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

for table in ccm.tables():
    df = ccm.collect(table)
    df.to_csv(output_dir / f"{table}.csv", index=False)
```

## Tables

- [profile_certifications](#profile_certifications)
- [profile_conferences](#profile_conferences)
- [profile_education](#profile_education)
- [profile_experience](#profile_experience)
- [profile_network](#profile_network)
- [profile_skills](#profile_skills)
- [profile_tracks](#profile_tracks)
- [profiles](#profiles)

### profile_certifications

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `name` | `str` |
| `org_certification_id` | `str` |
| `place` | `str` |
| `period` | `str` |
| `valid_from` | `str` |
| `valid_to` | `str` |

### profile_conferences

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `place` | `str` |
| `title` | `str` |

### profile_education

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `place` | `str` |
| `period` | `str` |
| `description` | `str` |

### profile_experience

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `catalog_id` | `int` |
| `place` | `str` |
| `period` | `str` |
| `role` | `str` |
| `description` | `str` |
| `industry` | `json` |
| `projects` | `json` |

### profile_network

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `type` | `str` |
| `url` | `str` |

### profile_skills

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `name` | `str` |
| `level` | `int` |
| `org_skill_id` | `int` |
| `preference` | `int` |

### profile_tracks

Derived from [`profiles`](#profiles) — no separate network call.

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `category` | `str` |
| `name` | `str` |
| `level` | `int` |
| `desc` | `str` |
| `visible` | `bool` |

### profiles

| Column | Type |
| --- | --- |
| `profile_id` | `str` |
| `owner_email` | `str` |
| `path` | `str` |
| `about_name` | `str` |
| `about_title` | `str` |
| `about_bio` | `str` |
| `about_passion` | `str` |
| `about_photo_url` | `str` |
| `about_pronounce_name_url` | `str` |
| `preference` | `str` |
| `completeness_score` | `int` |
| `membership_id` | `int` |
| `created_at` | `datetime` |
| `updated_at` | `datetime` |

