import json

import httpx

from tripwire.shipper import STREAM, batches, ship_sentinel, ship_splunk


def test_batches_stay_under_the_size_limit():
    lines = [{"Input": "x" * 1000, "i": i} for i in range(50)]
    bs = list(batches(lines, max_bytes=10_000))
    assert sum(len(b) for b in bs) == 50
    assert all(len(json.dumps(b).encode()) <= 10_000 for b in bs)


def test_sentinel_and_splunk_request_shapes():
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        return httpx.Response(204)

    c = httpx.Client(transport=httpx.MockTransport(handler))
    recs = [{"EventType": "decision", "AgentId": "a"}]
    assert ship_sentinel(recs, "https://dce.example/", "dcr-123", "tok", c) == 1
    s = seen[0]
    assert s.url.path == f"/dataCollectionRules/dcr-123/streams/{STREAM}"
    assert s.url.params["api-version"] == "2023-01-01" and s.headers["authorization"] == "Bearer tok"
    assert json.loads(s.content) == recs
    ship_splunk(recs, "https://hec.example:8088", "hec", c)
    h = seen[1]
    assert h.url.path == "/services/collector/event" and h.headers["authorization"] == "Splunk hec"
    assert json.loads(h.content)["sourcetype"] == "tripwire:decision"
