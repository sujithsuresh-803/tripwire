"""Ship decision logs to a SIEM: Microsoft Sentinel (Logs Ingestion API) or Splunk (HTTP Event Collector).

    python -m tripwire.shipper sentinel logs/decisions.jsonl     # needs TRIPWIRE_DCE, TRIPWIRE_DCR_ID
    python -m tripwire.shipper splunk   logs/decisions.jsonl     # needs SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN

On Azure Container Apps the Sentinel token comes from the gateway's managed identity, which holds
Monitoring Metrics Publisher on the one DCR and nothing else (infra/terraform). Batches stay under the
API's 1 MB request limit. The request format is unit-tested; it has not been run against a live workspace.
"""
from __future__ import annotations

import json
import os
import sys

import httpx

from .audit import read

STREAM = "Custom-TripwireDecisions_CL"
MAX_BYTES = 900_000


def batches(lines: list[dict], max_bytes: int = MAX_BYTES):
    cur, size = [], 2
    for rec in lines:
        n = len(json.dumps(rec, ensure_ascii=False).encode()) + 1
        if cur and size + n > max_bytes:
            yield cur
            cur, size = [], 2
        cur.append(rec)
        size += n
    if cur:
        yield cur


def managed_identity_token(client: httpx.Client, resource: str = "https://monitor.azure.com") -> str:
    r = client.get(os.environ["IDENTITY_ENDPOINT"], headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]},
                   params={"resource": resource, "api-version": "2019-08-01",
                           **({"client_id": os.environ["AZURE_CLIENT_ID"]} if os.environ.get("AZURE_CLIENT_ID") else {})})
    r.raise_for_status()
    return r.json()["access_token"]


def ship_sentinel(lines, endpoint: str, dcr_id: str, token: str, client: httpx.Client) -> int:
    url = f"{endpoint.rstrip('/')}/dataCollectionRules/{dcr_id}/streams/{STREAM}"
    sent = 0
    for b in batches(lines):
        r = client.post(url, params={"api-version": "2023-01-01"}, json=b,
                        headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        sent += len(b)
    return sent


def ship_splunk(lines, hec_url: str, token: str, client: httpx.Client) -> int:
    body = "\n".join(json.dumps({"event": r, "sourcetype": "tripwire:decision", "source": "tripwire"},
                                ensure_ascii=False) for r in lines)
    r = client.post(f"{hec_url.rstrip('/')}/services/collector/event", content=body,
                    headers={"Authorization": f"Splunk {token}"})
    r.raise_for_status()
    return len(lines)


def main():
    target, path = sys.argv[1], sys.argv[2]
    lines = read(path)
    with httpx.Client(timeout=30) as c:
        if target == "sentinel":
            n = ship_sentinel(lines, os.environ["TRIPWIRE_DCE"], os.environ["TRIPWIRE_DCR_ID"], managed_identity_token(c), c)
        else:
            n = ship_splunk(lines, os.environ["SPLUNK_HEC_URL"], os.environ["SPLUNK_HEC_TOKEN"], c)
    print(f"shipped {n} records to {target}")


if __name__ == "__main__":
    main()
