"""One-off debug helper — not part of the library. Delete once resolved."""

import json

from posture import CCM

ccm = CCM("wiz")
ccm._ensure_authenticated()  # noqa: SLF001 - debug script, not library usage

_QUERY = """
query InputFields {
  __type(name: "VulnerabilityFindingFilters") {
    inputFields {
      name
      type {
        name
        kind
        ofType { name kind }
      }
      defaultValue
    }
  }
}
"""

response = ccm._session.post(  # noqa: SLF001
    ccm._api_endpoint,  # noqa: SLF001
    json={"query": _QUERY},
    timeout=30,
)
print(json.dumps(response.json(), indent=2))
