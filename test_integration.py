"""Integration test: Full pipeline test for The Obsidian Lens"""
import urllib.request
import json
import time

API = "http://localhost:5000"

def api_get(path):
    res = urllib.request.urlopen(f"{API}{path}")
    return json.loads(res.read())

def api_post(path, data=None):
    body = json.dumps(data).encode() if data else b""
    req = urllib.request.Request(f"{API}{path}", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    return json.loads(res.read())

print("=== Step 1: Check model ===")
models = api_get("/api/models")
print(f"  Model exists: {models['model_exists']}")

print("\n=== Step 2: Start live capture ===")
start = api_post("/api/capture/start", {"duration": 5, "packet_count": 50})
print(f"  Status: {start.get('status')}")

print("\n=== Step 3: Wait for capture ===")
time.sleep(7)

print("\n=== Step 4: Stop capture ===")
stop = api_post("/api/capture/stop")
print(f"  Packets: {stop.get('packets_captured')}, File: {stop.get('output_file')}")
aid = stop.get("analysis_id")

if aid:
    print(f"\n=== Step 5: Analyze {aid} ===")
    analysis = api_get(f"/api/analyze/{aid}")
    print(f"  Flows: {analysis.get('total_flows')}, Identities: {analysis.get('identities_created')}")

    print("\n=== Step 6: Check identities ===")
    ids = api_get("/api/identities")
    print(f"  Total: {ids['total']}, White: {len(ids['white_users'])}, Black: {len(ids['black_users'])}")
    for u in ids['white_users'][:3]:
        print(f"    {u['identity_label']} | IPs: {u['associated_ips']} | {u['threat_type']}")
    for u in ids['black_users'][:3]:
        print(f"    {u['identity_label']} | IPs: {u['associated_ips']} | {u['threat_type']} | Blocked: {u['is_blocked']}")

    print("\n=== Step 7: Network health ===")
    health = api_get("/api/network-health")
    print(f"  Score: {health['health_score']}, White: {health['white_count']}, Black: {health['black_count']}")

    # Step 8: Test block/unblock if there are black users
    if ids['black_users']:
        bid = ids['black_users'][0]['id']
        print(f"\n=== Step 8: Block identity {bid} ===")
        block_res = api_post(f"/api/identities/{bid}/block")
        print(f"  Result: {block_res}")

        health2 = api_get("/api/network-health")
        print(f"  Health after block: {health2['health_score']}, Blocked: {health2['blocked_count']}")

        print(f"\n=== Step 9: Unblock identity {bid} ===")
        unblock_res = api_post(f"/api/identities/{bid}/unblock")
        print(f"  Result: {unblock_res}")
    else:
        print("\n=== No black users to test block/unblock ===")

else:
    print("  No analysis_id returned — capture may not have produced a file")

print("\n=== ALL INTEGRATION TESTS COMPLETE ===")
