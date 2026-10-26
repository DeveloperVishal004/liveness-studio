#!/usr/bin/env python3
"""Prints the ./demo.sh results table from the session-scenarios JSON files in the given directory.

Exit status 2 if any ATTACK scenario was accepted (VERIFIED), else 0. Labels and explanations only; it adds no
evidence of its own. [MOCK] results: simulated inputs, real engine decisions.
"""
import json
import os
import sys

STORY = [  # (scenario id, description, kind)
    ("genuine", "genuine user", "genuine"),
    ("replay-previous-response", "attacker replays an earlier signed capture", "attack"),
    ("txn-mismatch", "response belongs to another request (nonce mismatch)", "attack"),
    ("tamper", "signed capture altered in transit", "attack"),
    ("stream-inject-other-subject", "another person injected on the video stream", "attack"),
    ("capture-swap-other-person", "a different person at the capture moment", "attack"),
    ("whole-stream", "still photo replayed as the live stream", "attack"),
    ("skew+30s", "device clock 30 s off (non-conforming device)", "fault"),
]
EXPLAIN = {
    "OK": "live stream, valid device signature, fresh nonce, same person, capture inside the time window",
    "PAD_UNCERTAIN": "placeholder PAD below the conservative 0.80 capture gate: fail-closed retry, never accepted",
    "REPLAYED_RESPONSE": "this exact signed response was already used: replay detected",
    "TRANSACTION_MISMATCH": "signed transactionId is not this request's fresh nonce",
    "BAD_SIGNATURE": "device signature does not verify: content was altered",
    "SUBJECT_MISMATCH": "face in the signed capture is not the person seen on the stream",
    "SUBJECT_CHANGED": "a different person appeared during the attempt",
    "CAPTURE_OUTSIDE_WINDOW": "signed timestamp outside the capture window: device clock fault, not an attack",
    "STATIC_REPLAY_SUSPECT": "no natural motion across frames: still image suspected, capture never started",
    "INSUFFICIENT_STREAM_EVIDENCE": "too little stream evidence around the capture: fail-closed retry",
    "PASSIVE_UNCERTAIN_NO_CHALLENGE": "stream PAD not confident and no challenge engine yet: fail-closed retry",
}
LABEL = {"VERIFIED": "ACCEPTED", "RETRY_PENDING": "RETRY", "REJECTED_ATTACK": "REJECTED"}


def main(out):
    runs = []
    for name in ("genuine", "attacks", "static"):
        with open(os.path.join(out, name + ".json")) as f:
            runs += json.load(f)["scenarios"]
    rows = []
    for sid, desc, kind in STORY:
        for i, s in enumerate([r for r in runs if r["scenario"] == sid]):
            state, reason, br = s["state"], s["reason"], s.get("binding_reason")
            key = "OK" if state == "VERIFIED" else (br if br and br != "OK" else reason)
            rows.append({
                "kind": kind,
                "desc": desc + (f" (session {i + 1})" if kind == "genuine" else ""),
                "result": LABEL.get(state, "BLOCKED"),
                "verdict": "VERIFIED" if state == "VERIFIED" else reason,
                "why": EXPLAIN.get(key, key),
                "attacks": s.get("attack_events", 0),
                "channel": s.get("channel_events", 0),
            })
    print("\nFace liveness / capture-binding demo")
    print("  INPUTS ARE SIMULATED: mock SBI device, synthetic face motion, scripted attacks, placeholder PAD model.")
    print("  DECISIONS ARE REAL:   the actual engine: face models on every frame, RS256 signature + certificate")
    print("                        verification, nonce/time binding, replay cache, attribution and lockout policy.")
    print("  NOT real-device validation; says NOTHING about PAD accuracy.\n")
    w = max(len(r["desc"]) for r in rows)
    print(f"{'scenario'.ljust(w)}  {'result':8}  {'engine verdict':22}  why")
    print("-" * (w + 120))
    for r in rows:
        print(f"{r['desc'].ljust(w)}  {r['result']:8}  {r['verdict']:22}  {r['why']}")
    print("\nAttribution of each rejection (which counter it increments):")
    for r in rows:
        if r["kind"] == "genuine":
            continue
        if r["attacks"]:
            where = "SUBJECT attack counter (attributable to the person in front of the camera)"
        elif r["channel"]:
            where = "CHANNEL (device) integrity counter - the person is not locked out"
        elif r["verdict"] == "DEVICE_FAULT":
            where = "device-fault diagnostics only (consumes the attempt)"
        else:
            where = "no counter (capture never started; the attempt ends)"
        print(f"  {r['desc'].ljust(w)}  -> {where}")
    attacks = [r for r in rows if r["kind"] == "attack"]
    accepted = [r for r in attacks if r["result"] == "ACCEPTED"]
    genuine = [r for r in rows if r["kind"] == "genuine"]
    print(f"\nattacks accepted: {len(accepted)} of {len(attacks)}    genuine sessions accepted: "
          f"{len([r for r in genuine if r['result'] == 'ACCEPTED'])} of {len(genuine)} "
          f"(RETRY = placeholder PAD uncertain: fail-closed, never an acceptance)")
    print("raw results:", out)
    return 2 if accepted else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
