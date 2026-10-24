#!/usr/bin/env python3
"""Red-team campaign runner. Lives on red_net: it can reach the gateway and nothing else."""
import argparse
import os
import sys

import httpx


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a Bayora red-team campaign")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_URL", "http://gateway:8000"))
    ap.add_argument("--mode", choices=["enforce", "monitor"], default="enforce")
    ap.add_argument("--categories", nargs="*", default=[])
    ap.add_argument("--fail-above", type=float, default=None, help="exit 1 if risk score exceeds this (CI gate)")
    a = ap.parse_args()
    user, pw = os.environ.get("RED_USER", "red_operator"), os.environ.get("RED_PASSWORD", "")
    with httpx.Client(base_url=a.gateway, timeout=60) as c:
        r = c.post("/auth/login", json={"username": user, "password": pw})
        if r.status_code != 200:
            print("login failed", r.status_code, file=sys.stderr)
            return 2
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        res = c.post("/red/campaigns", headers=h, json={"mode": a.mode, "categories": a.categories})
        res.raise_for_status()
        data = res.json()
    print(f"\nCampaign {data['id']}  mode={a.mode}\n{'ID':9}{'CATEGORY':18}{'SEV':9}OUTCOME")
    for x in data["results"]:
        print(f"{x['attack_id']:9}{x['category']:18}{x['severity']:9}{x['outcome']}")
    s = data["summary"]
    print(f"\nattack success rate {s['attack_success_rate']}%  | false positives {s['false_positive_rate']}%"
          f"  | risk score {s['risk_score']}/100  | outcomes {s['outcomes']}")
    if a.fail_above is not None and s["risk_score"] > a.fail_above:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
