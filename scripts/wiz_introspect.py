"""One-off debug helper — not part of the library. Delete once resolved."""

import json

from posture import CCM

ccm = CCM("wiz")
ccm._ensure_authenticated()

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

response = ccm._session.post(
    ccm._api_endpoint,
    json={"query": _QUERY},
    timeout=30,
)
print(json.dumps(response.json(), indent=2))
