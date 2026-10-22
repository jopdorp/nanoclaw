#!/usr/bin/env python3
"""Copy qmem points, vectors included, from one Qdrant to another by point id.

usage: qmem-copy.py SRC_URL DST_URL SUFFIX [TOPIC ...]
Copies mind-active, mind-episodic, mind-medium, jopdorp-memory (only TOPICs when
given) and all of mind-profiles. Missing collections are created with the
source's vector config and keyword indexes. Seeds Orfie from Fable's memory and,
run in both directions, syncs the two.
"""
import json, sys, urllib.request as u

src, dst, suffix, topics = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]

def req(base, method, path, body=None):
    r = u.Request(base + path, json.dumps(body).encode() if body is not None else None,
                  {"content-type": "application/json"}, method=method)
    with u.urlopen(r, timeout=120) as resp:
        return json.load(resp)["result"]

for name in ("mind-active", "mind-episodic", "mind-medium", "jopdorp-memory", "mind-profiles"):
    coll = f"/collections/{name}{suffix}"
    info = req(src, "GET", coll)
    try:
        req(dst, "GET", coll)
    except u.HTTPError:
        req(dst, "PUT", coll, {"vectors": info["config"]["params"]["vectors"]})
        for field in info.get("payload_schema", {}):
            req(dst, "PUT", coll + "/index?wait=true", {"field_name": field, "field_schema": "keyword"})
    body = {"limit": 256, "with_payload": True, "with_vector": True}
    if topics and name != "mind-profiles":
        body["filter"] = {"must": [{"key": "topic", "match": {"any": topics}}]}
    copied = 0
    while True:
        page = req(src, "POST", coll + "/points/scroll", body)
        if page["points"]:
            points = [{k: p[k] for k in ("id", "vector", "payload")} for p in page["points"]]
            req(dst, "PUT", coll + "/points?wait=true", {"points": points})
            copied += len(points)
        if page.get("next_page_offset") is None:
            break
        body["offset"] = page["next_page_offset"]
    print(f"{name}{suffix}: {copied}")
