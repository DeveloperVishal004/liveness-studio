# Demo script (3–5 minutes)

**Before you present (5 minutes earlier):**
- Run `./demo.sh` once. This warms the JVM and caches, and confirms exit status `0`.
- Keep `docs/demo/DEMO_SAMPLE_OUTPUT.txt` open in a second tab as a backup.
- Use a wide terminal (≥ 170 columns), font size up.

---

## 0:00 – 0:45 Problem and architecture

> "MOSIP registration clients see a face through two separate channels: an **unsigned live video stream** used for
> liveness, and a separate **device-signed capture** that is actually enrolled. If you only check liveness on the
> stream, an attacker can show a live face on the stream and a photo, or another person, at the capture."

What we built (`liveness-core`, Java 11, runs offline on the registration PC):

1. **Stream pipeline:** face detection, a PAD model and face embeddings on every frame; static-photo detection; all
   evidence time-stamped at receipt.
2. **Capture binding:**
   - the RCAPTURE response must carry a valid **RS256 device signature** with a **certificate chain**;
   - it must echo a **fresh nonce** (transactionId);
   - it must fall **inside the capture time window**;
   - it must come from the **same device**;
   - it must show the **same person** as the stream.
3. **Session engine:** fail-closed state machine, attempt limits, and **attribution**: attacks by the person count
   against the person; tampering on the device channel counts against the **channel**, so an attacker cannot lock a
   genuine person out.

## 0:45 – 1:15 Run it

```bash
./demo.sh
```

> "Everything you'll see is the real engine making real decisions. The inputs are simulated: a mock SBI device,
> synthetic face motion, scripted attacks. The PAD model is a placeholder. I'll come back to what that means."

Point at the banner: **INPUTS ARE SIMULATED / DECISIONS ARE REAL / not real-device validation**.

## 1:15 – 2:00 Genuine attempt

Point at the `genuine user` rows:
- **ACCEPTED / VERIFIED:** live stream, valid signature, fresh nonce, same person, inside the window.
- **RETRY / CAPTURE_UNCERTAIN:** "The placeholder PAD wasn't confident enough for our conservative 0.80 gate, so
  the engine asks for a retry. It fails **closed**: uncertainty never becomes an acceptance."
- *If no genuine session shows ACCEPTED this run:* "That's the placeholder model being cautious. Here's a previous run"
  (backup file). "The point is that it never accepts by default."

## 2:00 – 3:00 Representative attack rejections

- **Another person injected on the video stream** → `SUBJECT_MISMATCH`: the face in the signed capture is not the
  person on the stream. This is the core stream-vs-capture swap.
- **Still photo replayed as the stream** → `STATIC_REPLAY_SUSPECT`: no natural motion, so the capture is never started.
- **Device clock 30 s off** → `DEVICE_FAULT`: rejected and diagnosed as a misconfigured device, not treated as an attack.

## 3:00 – 3:45 Channel-integrity protection

Point at the three `CHANNEL_INTEGRITY` rows (replay, nonce mismatch, tampered signature) and the attribution block:

> "These were all rejected. But they arrive over the local device channel. We can't prove the person in front of the
> camera caused them, so they increment a **channel** counter, not the person's. After repeated channel failures the
> channel is **locked fail-closed** until an administrator investigates and resets it, with an audit record.
> Earlier, two malformed responses would have locked a genuine person out permanently; this design closes that hole."

## 3:45 – 4:15 Engineering evidence

- **245 automated tests passing.** They include adversarial and concurrency tests, randomized invariant tests (an
  invalid response never reaches VERIFIED), signature/replay/revocation tests and a tamper-evident persistent ledger.
- Fixed and tested during the build: capture-lock latency (frame timestamps no longer stalled during verification),
  per-frame cost (215 ms → 3 ms), and several security defects found by our own review (documented in
  the project's internal review log, not part of this repository).

## 4:15 – 5:00 Limitations (say these plainly)

- **No real device yet.** Everything ran against a mock SBI device. A probe and runbook for one certified device on
  Windows are ready; that run is the next milestone.
- **Placeholder PAD model, accuracy unknown.** These scenarios are **not** a PAD accuracy measurement. That needs a
  consented, representative dataset, which is not yet authorised.
- **The video stream is unsigned in SBI 1.0.** A same-person video injected on the stream can only be stopped by
  capture PAD today. We prototyped a signed stream digest (B1), but it needs an SBI specification change.
- **Not production-ready**; release gates are not ratified.

---

**If something breaks live:**
- **Exit status `1`:** setup issue (missing Java, `curl` or Python packages). The script prints the exact fix.
- **Exit status `2`:** an attack was accepted. Stop and say so; do not present it as passing.
- **In all cases:** show `docs/demo/DEMO_SAMPLE_OUTPUT.txt` (a real earlier transcript, labelled as such).
