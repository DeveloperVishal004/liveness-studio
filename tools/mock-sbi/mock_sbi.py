#!/usr/bin/env python3
"""Mock MOSIP SBI 1.0 face device for Phase-0 experiments, CI and security tests.

Wire format mirrors MOSIP MockMDS (mosip/mosip-mock-services @ 3d2174d):
  * STREAM  -> multipart/x-mixed-replace, boundary "--BoundaryString", per-part Content-Length, JPEG frames
  * RCAPTURE-> {"biometrics":[{"specVersion","data":<JWS RS256 + x5c>,"hash","error"}]}
               data.bioValue = base64url(ISO/IEC 19794-5:2011 record wrapping a JPEG 2000 image)
  * MOSIPDISC / MOSIPDINFO as in the SBI spec (deviceInfo is a signed JWS)

Unlike MockMDS it adds what Phase 0 needs: a shared "camera" ring buffer (so STREAM and RCAPTURE
run concurrently and RCAPTURE picks a frame captured *after* the request), configurable fps /
resolution / JPEG quality / pipeline latency, stream faults, and RCAPTURE attack modes used by
the capture-binding security tests.

Session-security additions ([MOCK] / [SIM] only, see docs/phase1/IMPLEMENTATION_PLAN.md):
  * --motion jitter|animate|static-replay : rigid jitter (legacy), synthetic non-rigid motion (blink/mouth, a
    live-subject STAND-IN, not real human motion), or a re-encoded/transformed still photo (static-image replay).
  * per-RCAPTURE customOpts.phase0StreamDuringCapture = pause|static|inject : while the device captures, the
    UNSIGNED stream pauses, shows a still of the source, or shows --inject-image; the signed capture is unaffected
    (models an attacker on the stream channel only).
  * customOpts.phase0ClockSkewS : device clock offset added to the signed timestamp.
  * capture mode expired-cert : signed with the device key under keys/expired.pem (validity in the past).
  * B1 PROTOTYPE v1 (docs/phase1/B1_STREAM_DIGEST_DESIGN.md; DRAFT, not an SBI format): with --b1-device, every STREAM
    gets a device-chosen streamId and a log of every part the MDS emits (SHA-256 of the genuine JPEG bytes, before
    any attacker-side substitution/suppression); every RCAPTURE response carries the signed statement in
    biometrics[0].additionalInfo.streamDigest (no request field needed). customOpts.phase0B1Mode (mock-only test hook)
    selects faults: omit, top-level, replay-previous, wrong-txn, tamper, rogue-key, device2-key, gap, reorder, stale,
    wrong-capture.
  * --pause-stream-during-rcapture : the device emits NO stream parts while RCAPTURE runs (literal reading of SBI
    "When the Device Registration Capture API is called, frames should not be added to the stream"); not listed.
  * --stream-delay-s D : an attacker delays the whole stream by D seconds (authentic frames, delivered late).
  * --stream-replace-image P : an attacker replaces EVERY stream part with an animated rendering of P (T17); the
    sensor/capture still see the source subject.
  * --camera 0|PATH : REAL camera frames (OpenCV device index, e.g. the MacBook webcam) or a video file instead of
    synthetic images. STREAM sends the real frames; RCAPTURE signs the sharpest real frame of the capture window with
    the TEST-ONLY device key. This is an SBI EMULATOR around a webcam, NOT a certified device.
  * --switch-image P --switch-after-s X : X seconds after each STREAM opens, the person in front of the device
    changes to P (sensor AND stream: a real subject swap, used for the subject-consistency/eviction scenarios).

Stdlib + numpy + opencv-python-headless + cryptography only. Binds to 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import hashlib
import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import cv2
import numpy as np
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

LOG = logging.getLogger("mock-sbi")
BOUNDARY = "--BoundaryString"
CAPTURE_MODES = ("best", "swap", "swap-alt", "replay", "stale", "txn-mismatch", "txn-omit", "tamper",
                 "untrusted-key", "other-device", "error", "expired-cert")
STREAM_DURING_CAPTURE = ("normal", "pause", "static", "inject")


# --------------------------------------------------------------------------- crypto
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Phase0 Mock Device Provider")])


def _cert(subject, issuer, pub, signer, ca: bool, days=3650):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    return b.sign(signer, hashes.SHA256())


@dataclass
class Signer:
    key: rsa.RSAPrivateKey
    chain: list  # leaf first, DER bytes

    def jws(self, payload: dict) -> str:
        header = {"alg": "RS256", "typ": "JWT", "x5c": [base64.b64encode(c).decode() for c in self.chain]}
        h = b64url(json.dumps(header, separators=(",", ":")).encode())
        p = b64url(json.dumps(payload, separators=(",", ":")).encode())
        sig = self.key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{b64url(sig)}"


def load_or_create_keys(d: Path) -> tuple[Signer, Signer]:
    """Returns (trusted device signer chained to the mock CA, untrusted self-signed signer)."""
    d.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    nopw = serialization.NoEncryption()
    pkcs8 = serialization.PrivateFormat.PKCS8

    def key(path: Path):
        if path.exists():
            return serialization.load_pem_private_key(path.read_bytes(), None)
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.write_bytes(k.private_bytes(pem, pkcs8, nopw))
        return k

    ca_key, dev_key, rogue_key = key(d / "ca.key"), key(d / "device.key"), key(d / "rogue.key")
    if not (d / "ca.pem").exists():
        ca = _cert(_name("Phase0 Mock Device CA"), _name("Phase0 Mock Device CA"), ca_key.public_key(), ca_key, True)
        dev = _cert(_name("PHASE0-MOCK-FACE-0001"), ca.subject, dev_key.public_key(), ca_key, False)
        rogue = _cert(_name("PHASE0-MOCK-FACE-0001"), _name("Rogue CA"), rogue_key.public_key(), rogue_key, True)
        (d / "ca.pem").write_bytes(ca.public_bytes(pem))
        (d / "device.pem").write_bytes(dev.public_bytes(pem))
        (d / "rogue.pem").write_bytes(rogue.public_bytes(pem))
        (d / "trust.pem").write_bytes(ca.public_bytes(pem))  # what the client trusts
    load = lambda p: x509.load_pem_x509_certificate((d / p).read_bytes()).public_bytes(serialization.Encoding.DER)
    return Signer(dev_key, [load("device.pem"), load("ca.pem")]), Signer(rogue_key, [load("rogue.pem")])


# --------------------------------------------------------------------------- ISO/IEC 19794-5:2011
def iso19794_5_record(image_bytes: bytes, width: int, height: int, data_type: int, quality: int,
                      when: dt.datetime) -> bytes:
    """Minimal single-representation face record, byte layout as observed in MOSIP MockMDS Face.iso.

    data_type: 0 = JPEG, 1 = JPEG 2000 lossy, 2 = JPEG 2000 lossless.
    """
    rep = bytearray()
    rep += when.year.to_bytes(2, "big") + bytes([when.month, when.day, when.hour, when.minute, when.second])
    rep += (when.microsecond // 1000).to_bytes(2, "big")
    rep += bytes([0x05]) + b"\x00\x00" + b"\x00\x00"           # capture technology, vendor id, type id
    rep += bytes([1, quality & 0xFF]) + b"\x00\x01\x00\x01"     # 1 quality block: score, alg vendor, alg id
    rep += b"\x00\x00"                                          # number of landmark points
    rep += bytes([0xFF, 0x00, 0x00, 0x00]) + b"\x00\x00\x00" + b"\x00\x00" + b"\x00" * 6  # facial info
    rep += bytes([0x01, data_type]) + width.to_bytes(2, "big") + height.to_bytes(2, "big")
    rep += b"\x00\x00\x01\x00\x01"                              # sampling rate, post-proc, cross-ref, colour space
    rep += len(image_bytes).to_bytes(4, "big") + image_bytes
    rep_len = 4 + len(rep)
    total = 17 + rep_len
    hdr = b"FAC\x00" + b"030\x00" + total.to_bytes(4, "big") + (1).to_bytes(2, "big") + b"\x00" + b"\x00\x00"
    return hdr + rep_len.to_bytes(4, "big") + bytes(rep)


# --------------------------------------------------------------------------- camera
@dataclass
class Frame:
    seq: int
    t_capture: float  # time.monotonic() at "sensor"
    wall: dt.datetime
    bgr: np.ndarray
    jpeg: bytes
    sharpness: float
    stream_jpeg: bytes | None = None  # what the UNSIGNED stream sends, if an attacker replaced it (else jpeg)
    paused: bool = False              # attacker withholds this frame (device emitted it)
    device_paused: bool = False       # device does not emit this frame (spec pause during RCAPTURE)


class CameraGrabber(threading.Thread):
    """Reads a real camera (or a video file) continuously and keeps only the LATEST frame, so frames never queue up
    in the driver buffer (no growing latency). Frames are resized to --camera-width keeping the aspect ratio."""

    def __init__(self, spec: str, width: int):
        super().__init__(daemon=True)
        self.spec, self.width, self.is_file = spec, width, not spec.isdigit()
        if self.is_file:
            self.cap = cv2.VideoCapture(spec)
        else:
            import sys
            backend = cv2.CAP_AVFOUNDATION if sys.platform == "darwin" else cv2.CAP_ANY
            self.cap = cv2.VideoCapture(int(spec), backend)
        if not self.cap.isOpened():
            raise SystemExit(f"--camera {spec}: cannot open. On macOS allow camera access for your terminal app "
                             "(System Settings > Privacy & Security > Camera) and close other apps using the camera.")
        self.file_fps = self.cap.get(cv2.CAP_PROP_FPS) or 30.0
        self.latest_frame = None
        self.frames = 0
        self.lock = threading.Condition()
        self.running = True

    def run(self):
        period = 1.0 / max(1.0, self.file_fps) if self.is_file else 0.0
        while self.running:
            ok, frame = self.cap.read()
            if not ok:
                if self.is_file:                      # loop the video file
                    self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                    continue
                time.sleep(0.01)
                continue
            h, w = frame.shape[:2]
            if w > self.width:
                frame = cv2.resize(frame, (self.width, int(round(h * self.width / w))), interpolation=cv2.INTER_AREA)
            with self.lock:
                self.latest_frame = frame
                self.frames += 1
                self.lock.notify_all()
            if period:
                time.sleep(period)

    def latest(self, timeout: float = 5.0) -> np.ndarray:
        with self.lock:
            end = time.monotonic() + timeout
            while self.latest_frame is None:
                left = end - time.monotonic()
                if left <= 0:
                    raise SystemExit(f"--camera {self.spec}: no frame within {timeout:.0f} s")
                self.lock.wait(left)
            return self.latest_frame


class Camera(threading.Thread):
    """Produces frames at a fixed rate into a ring buffer; frames become visible after `latency`."""

    def __init__(self, args):
        super().__init__(daemon=True)
        self.args = args
        self.grabber = None
        self._last_grab = -1
        if args.camera is not None:
            self.grabber = CameraGrabber(args.camera, args.camera_width)
            self.grabber.start()
            first = self.grabber.latest()
            args.size = (first.shape[1], first.shape[0])
        self.sources = load_sources(args.source) if args.source else []
        self.ring: collections.deque[Frame] = collections.deque(maxlen=max(8, int(args.fps * 10)))
        self.cv = threading.Condition()
        self.seq = 0
        self.rng = random.Random(args.seed)
        self.running = True
        self.freeze: Frame | None = None
        self.t0 = time.monotonic()
        self.stream_override = "normal"   # set by Device.capture for the duration of one RCAPTURE
        self.motion = None
        if args.motion != "jitter" or args.inject_image or args.switch_image or args.stream_replace_image:
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))
            import synthetic_motion  # [SIM] generator shared with the temporal fixtures
            self.motion = synthetic_motion
        self.landmarks = [self.motion.landmarks(s) if self.motion else None for s in self.sources]
        if self.grabber is None and not self.sources:
            raise SystemExit("either --source or --camera is required")
        if args.motion == "animate" and any(lm is None for lm in self.landmarks):
            raise SystemExit("--motion animate: no face landmarks in a source image")
        self.inject = cv2.imread(args.inject_image) if args.inject_image else None
        self.replace = cv2.imread(args.stream_replace_image) if args.stream_replace_image else None
        self.replace_lm = self.motion.landmarks(self.replace) if self.replace is not None else None
        self.switch_at = None              # monotonic time after which the subject is args.switch_image
        self.switch = cv2.imread(args.switch_image) if args.switch_image else None
        self.switch_lm = self.motion.landmarks(self.switch) if self.switch is not None else None
        if args.switch_image and (self.switch is None or self.switch_lm is None):
            raise SystemExit("--switch-image: unreadable or no face")
        self.inject_lm = self.motion.landmarks(self.inject) if self.inject is not None else None

    def _source_index(self, i: int) -> int:
        return (i // max(1, int(self.args.fps * self.args.source_hold_s))) % len(self.sources)

    def render_mode(self, i: int, mode: str) -> np.ndarray:
        """Frame i under a motion model: 'jitter' (legacy rigid), 'animate' (non-rigid [SIM]), 'static-replay'.
        With --camera: the latest REAL camera frame, whatever the motion model."""
        if self.grabber is not None:
            return self.grabber.latest()
        if self.switch is not None and self.switch_at is not None and time.monotonic() >= self.switch_at:
            kw = {"w": self.args.size[0], "h": self.args.size[1], "face_scale": self.args.face_scale}
            return self.motion.animate_frame(self.switch, self.switch_lm, i / self.args.fps, self.rng, i, **kw)
        k = self._source_index(i)
        if mode == "jitter" or self.motion is None:
            return self.render(i)
        kw = {"w": self.args.size[0], "h": self.args.size[1], "face_scale": self.args.face_scale}
        if mode == "animate" and self.landmarks[k] is not None:
            return self.motion.animate_frame(self.sources[k], self.landmarks[k], i / self.args.fps, self.rng, i, **kw)
        return self.motion.static_replay_frame(self.sources[k], self.rng, i, **kw)

    def render_inject(self, i: int) -> np.ndarray:
        kw = {"w": self.args.size[0], "h": self.args.size[1], "face_scale": self.args.face_scale}
        if self.inject_lm is not None:
            return self.motion.animate_frame(self.inject, self.inject_lm, i / self.args.fps, self.rng, i, **kw)
        return self.motion.static_replay_frame(self.inject, self.rng, i, **kw)

    def render(self, i: int) -> np.ndarray:
        src = self.sources[self._source_index(i)]
        w, h = self.args.size
        canvas = np.full((h, w, 3), 128, np.uint8)
        sh, sw = src.shape[:2]
        s = min(w / sw, h / sh) * self.args.face_scale
        jx, jy = self.rng.gauss(0, self.args.jitter), self.rng.gauss(0, self.args.jitter)
        m = np.array([[s, 0, (w - sw * s) / 2 + jx], [0, s, (h - sh * s) / 2 + jy]], np.float32)
        cv2.warpAffine(src, m, (w, h), dst=canvas, borderMode=cv2.BORDER_TRANSPARENT)
        if self.args.noise > 0:
            n = np.random.default_rng(i).normal(0, self.args.noise, canvas.shape)
            canvas = np.clip(canvas.astype(np.float32) + n, 0, 255).astype(np.uint8)
        return canvas

    def run(self):
        period = 1.0 / self.args.fps
        next_t = time.monotonic()
        while self.running:
            t = time.monotonic()
            if t < next_t:
                time.sleep(next_t - t)
                continue
            next_t += period
            if self.grabber is not None:
                # real camera: emit each sensor frame at most once, like a real device; if the camera delivered no new
                # frame since the last tick, emit nothing (re-encoding the same frame would look like a frozen sensor)
                if self.grabber.frames == self._last_grab:
                    continue
                self._last_grab = self.grabber.frames
            if self.args.freeze_after_s and t - self.t0 > self.args.freeze_after_s and self.freeze is not None:
                f = Frame(self.seq, t, dt.datetime.now(dt.timezone.utc), self.freeze.bgr, self.freeze.jpeg,
                          self.freeze.sharpness)  # identical bytes = frozen sensor
            else:
                bgr = self.render_mode(self.seq, self.args.motion)
                ok, enc = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, self.args.jpeg_quality])
                gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
                f = Frame(self.seq, t, dt.datetime.now(dt.timezone.utc), bgr, enc.tobytes(),
                          float(cv2.Laplacian(gray, cv2.CV_64F).var()))
                ov = self.stream_override
                if self.replace is not None:                       # T17: attacker video replaces every part
                    kw = {"w": self.args.size[0], "h": self.args.size[1], "face_scale": self.args.face_scale}
                    fake = self.motion.animate_frame(self.replace, self.replace_lm, self.seq / self.args.fps, self.rng, self.seq, **kw)
                    f.stream_jpeg = cv2.imencode(".jpg", fake, [cv2.IMWRITE_JPEG_QUALITY, self.args.jpeg_quality])[1].tobytes()
                if ov == "pause":
                    f.paused = True
                elif ov == "device-pause":
                    f.device_paused = True
                elif ov in ("static", "inject"):
                    fake = self.render_mode(self.seq, "static-replay") if ov == "static" else self.render_inject(self.seq)
                    f.stream_jpeg = cv2.imencode(".jpg", fake, [cv2.IMWRITE_JPEG_QUALITY, self.args.jpeg_quality])[1].tobytes()
                self.freeze = f
            self.seq += 1
            with self.cv:
                self.ring.append(f)
                self.cv.notify_all()

    def visible_after(self, last_seq: int, timeout: float, extra_latency_s: float = 0.0) -> Frame | None:
        """Newest frame with seq > last_seq whose emulated pipeline latency (+ any extra delay) has elapsed."""
        deadline = time.monotonic() + timeout
        with self.cv:
            while True:
                now = time.monotonic()
                ready = [f for f in self.ring if f.seq > last_seq
                         and now - f.t_capture >= self.args.latency_ms / 1000 + extra_latency_s]
                if ready:
                    return ready[-1] if self.args.latest_only else ready[0]
                if now >= deadline:
                    return None
                self.cv.wait(timeout=min(0.005, deadline - now))

    def frames_between(self, t_start: float, t_end: float) -> list[Frame]:
        with self.cv:
            return [f for f in self.ring if t_start <= f.t_capture <= t_end]


def load_sources(spec: list[str]) -> list[np.ndarray]:
    imgs = []
    for s in spec:
        p = Path(s)
        files = sorted(x for x in p.iterdir() if x.suffix.lower() in (".jpg", ".jpeg", ".png")) if p.is_dir() else [p]
        for f in files:
            im = cv2.imread(str(f))
            if im is not None:
                imgs.append(im)
    if not imgs:
        raise SystemExit(f"no images in {spec}")
    return imgs


# --------------------------------------------------------------------------- SBI documents
def sbi_timestamp(when: dt.datetime) -> str:
    """RCAPTURE timestamp in MOSIP MockMDS format: yyyy-MM-dd'T'HH:mm:ss'Z' (no milliseconds).

    Matches CryptoUtility.UTC_DATETIME_PATTERN in mosip-mock-services and the strict pattern of the Registration
    Client's MosipDeviceSpecificationHelper.validateResponseTimestamp. Set PHASE0_TS_MILLIS=1 to emit milliseconds
    instead (to test clients against vendors that do)."""
    if os.environ.get("PHASE0_TS_MILLIS") == "1":
        return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.datetime.now(dt.timezone.utc).microsecond // 1000:03d}Z"


class Device:
    def __init__(self, args, signer: Signer, rogue: Signer, expired: Signer | None = None, device2: Signer | None = None):
        self.args, self.signer, self.rogue, self.expired, self.device2 = args, signer, rogue, expired, device2
        self.current_stream: dict | None = None   # B1: {"id", "frames": [(seq, time_ms, sha256)], "lock"}
        self.last_statement: str | None = None
        self.serial = args.serial
        self.lock = threading.Lock()
        self.last_capture_response: bytes | None = None
        self.swap_img = cv2.imread(args.swap_image) if args.swap_image else None
        self.swap_alt_img = cv2.imread(args.swap_image_alt) if args.swap_image_alt else None
        self.named_swaps = {}
        for spec in args.swap or []:
            name, path = spec.split("=", 1)
            img = cv2.imread(path)
            if img is None:
                raise SystemExit(f"--swap {spec}: cannot read image")
            self.named_swaps[name] = img

    def b1_statement(self, txn: str, capture_data: str, mode: str) -> str | None:
        """B1 PROTOTYPE v1 signed stream digest (draft format phase0-b1-stream-digest/1)."""
        if mode == "omit":
            return None
        state = self.current_stream
        if state is None:
            return None
        with state["lock"]:
            frames = list(state["frames"])
        stream_id = state["id"]
        if mode == "gap" and len(frames) > 12:
            del frames[10]
        if mode == "reorder" and len(frames) > 12:
            frames[10], frames[11] = frames[11], frames[10]
        h = hashlib.sha256(b"phase0-b1/1" + stream_id.encode() + b"\x00" + self.serial.encode()).digest()
        entries = []
        for seq, t, fh in frames:
            h = hashlib.sha256(h + seq.to_bytes(8, "big") + t.to_bytes(8, "big") + fh).digest()
            entries.append([seq, t, b64url(fh)])
        issued = dt.datetime.now(dt.timezone.utc) - (dt.timedelta(seconds=120) if mode == "stale" else dt.timedelta(0))
        payload = {"typ": "phase0-b1-stream-digest/1", "streamId": stream_id,
                   "transactionId": "00000000-previous-txn" if mode == "wrong-txn" else txn,
                   "deviceSerial": self.serial,
                   "captureDataSha256": b64url(hashlib.sha256((capture_data + ("x" if mode == "wrong-capture" else "")).encode()).digest()),
                   "issuedAt": issued.strftime("%Y-%m-%dT%H:%M:%S.") + f"{issued.microsecond // 1000:03d}Z",
                   "frames": entries, "chainHead": b64url(h)}
        signer = self.rogue if mode == "rogue-key" else (self.device2 if mode == "device2-key" and self.device2 else self.signer)
        jws = signer.jws(payload)
        if mode == "tamper":
            h_, p_, s_ = jws.split(".")
            payload["issuedAt"] = payload["issuedAt"][:-2] + "9Z"
            jws = ".".join([h_, b64url(json.dumps(payload, separators=(",", ":")).encode()), s_])
        return jws

    def digital_id(self, serial=None) -> dict:
        return {"serialNo": serial or self.serial, "make": "Phase0", "model": "MOCK-FACE-1", "type": "Face",
                "deviceSubType": "Full face", "deviceProvider": "Phase0 Mock", "deviceProviderId": "PHASE0.MOCK",
                "dateTime": now_iso()}

    def discover(self, port: int) -> list:
        return [{"deviceId": "1", "deviceStatus": "Ready", "certification": self.args.level, "serviceVersion": "0.9.5",
                 "deviceSubId": ["0"], "callbackId": f"http://127.0.0.1:{port}/", "digitalId": b64url(json.dumps(
                     self.digital_id()).encode()), "deviceCode": "PHASE0-MOCK", "specVersion": ["0.9.5"],
                 "purpose": "Registration", "error": {"errorCode": "0", "errorInfo": "Success"}}]

    def info(self, port: int) -> list:
        info = {"deviceStatus": "Ready", "deviceId": "1", "firmware": "phase0", "certification": self.args.level,
                "serviceVersion": "0.9.5", "deviceSubId": ["0"], "callbackId": f"http://127.0.0.1:{port}/",
                "digitalId": self.signer.jws(self.digital_id()), "deviceCode": "PHASE0-MOCK",
                "env": "Developer", "purpose": "Registration", "specVersion": ["0.9.5"],
                # Non-standard, informational only (lets the probe compare declared vs measured fps)
                "x-phase0": {"fps": self.args.fps, "size": self.args.size, "jpegQuality": self.args.jpeg_quality}}
        return [{"deviceInfo": self.signer.jws(info), "error": {"errorCode": "0", "errorInfo": "Success"}}]

    def capture(self, cam: Camera, req: dict) -> bytes:
        # Per-request override through the SBI customOpts field (mock/test use only).
        mode = (req.get("customOpts") or {}).get("phase0CaptureMode", self.args.capture_mode)
        if mode not in CAPTURE_MODES and not (mode.startswith("swap:") and mode[5:] in self.named_swaps):
            mode = "error"
        if mode == "replay" and self.last_capture_response is not None:
            return self.last_capture_response  # byte-identical replay of an earlier, validly signed response
        if mode == "error":
            return json.dumps({"biometrics": [{"specVersion": "0.9.5", "data": "", "hash": "",
                                               "error": {"errorCode": "701", "errorInfo": "mock capture failure"}}]}).encode()
        opts = req.get("customOpts") or {}
        stream_mode = opts.get("phase0StreamDuringCapture", "normal")
        if stream_mode not in STREAM_DURING_CAPTURE:
            stream_mode = "normal"
        skew_s = float(opts.get("phase0ClockSkewS", 0) or 0)
        t_req = time.monotonic()
        # SBI: captureTime is the ISO time of the request; Phase-0 tools used it as a duration in ms (legacy shape)
        ct = str(req.get("captureTime") or "")
        capture_ms = int(ct) if ct.isdigit() else self.args.capture_time_ms
        timeout_ms = int(req.get("timeout") or 10000)
        cam.stream_override = "device-pause" if self.args.pause_stream_during_rcapture else stream_mode
        try:
            time.sleep(min(capture_ms, timeout_ms) / 1000)
        finally:
            cam.stream_override = "normal"
        frames = cam.frames_between(t_req, time.monotonic()) or list(cam.ring)[-1:]
        best = max(frames, key=lambda f: f.sharpness)
        bgr = best.bgr
        if mode == "swap" and self.swap_img is not None:
            bgr = self.swap_img
        elif mode == "swap-alt" and self.swap_alt_img is not None:
            bgr = self.swap_alt_img
        elif mode.startswith("swap:"):
            bgr = self.named_swaps[mode[5:]]
        if self.args.camera is not None:
            img = bgr                                  # real camera: sign the frame at its streamed resolution
        else:
            cw, ch = self.args.capture_size
            h, w = bgr.shape[:2]
            s = min(cw / w, ch / h)
            img = cv2.resize(bgr, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
        ok, jp2 = cv2.imencode(".jp2", img, [cv2.IMWRITE_JPEG2000_COMPRESSION_X1000, self.args.jp2_rate])
        when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=skew_s)
        if mode == "stale":
            when -= dt.timedelta(seconds=self.args.stale_s)
        iso = iso19794_5_record(jp2.tobytes(), img.shape[1], img.shape[0], 1, 80, when)
        txn = req.get("transactionId")
        if mode == "txn-mismatch":
            txn = "00000000-0000-0000-0000-000000000000"
        payload = {"digitalId": self.signer.jws(self.digital_id("PHASE0-OTHER-0002" if mode == "other-device" else None)),
                   "bioType": "Face", "bioSubType": "", "purpose": req.get("purpose", "Registration"),
                   "env": req.get("env", "Developer"), "bioValue": b64url(iso), "bioExtract": None,
                   "transactionId": txn, "timestamp": sbi_timestamp(when),
                   "requestedScore": "40", "qualityScore": "80", "deviceCode": "PHASE0-MOCK",
                   "deviceServiceVersion": "0.9.5"}
        if mode == "txn-omit":
            payload.pop("transactionId")
        signer = self.rogue if mode == "untrusted-key" else self.signer
        if mode == "expired-cert":
            if self.expired is None:
                raise SystemExit("capture mode expired-cert needs keys/expired.pem")
            signer = self.expired
            payload["digitalId"] = self.expired.jws(self.digital_id())
        data = signer.jws(payload)
        if mode == "tamper":
            h_, p_, s_ = data.split(".")
            body = json.loads(base64.urlsafe_b64decode(p_ + "=" * (-len(p_) % 4)))
            body["qualityScore"] = "99"
            data = ".".join([h_, b64url(json.dumps(body, separators=(",", ":")).encode()), s_])
        body_obj = {"biometrics": [{"specVersion": "0.9.5", "data": data,
                                    "hash": hashlib.sha256(iso).hexdigest().upper(),
                                    "error": {"errorCode": "0", "errorInfo": "Success"}}]}
        if self.args.b1_device:
            mode = opts.get("phase0B1Mode", "")
            st = self.b1_statement(req.get("transactionId"), data, mode)
            if mode == "replay-previous":
                # replay a statement signed for an EARLIER capture; if none was issued yet, sign one for a previous
                # transaction now (otherwise the "attack" would silently attach a valid statement: harness defect R34)
                prev = self.last_statement or self.b1_statement("00000000-earlier-txn", data + "-earlier", "")
                st, self.last_statement = prev, st
            elif st is not None:
                self.last_statement = st
            if st is not None and mode == "top-level":
                body_obj["x-phase0-streamDigest"] = st          # prototype v0 carrier: must NOT be read
            elif st is not None:
                body_obj["biometrics"][0]["additionalInfo"] = {"streamDigest": st}
        resp = json.dumps(body_obj).encode()
        with self.lock:
            if mode == "best":
                self.last_capture_response = resp  # what a "replay" request will resend verbatim
        return resp


# --------------------------------------------------------------------------- HTTP
def make_handler(dev: Device, cam: Camera, args):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):
            LOG.debug("%s " + fmt, self.command, *a)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                raise ValueError("request too large")
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw) if raw.strip() else {}

        def _json(self, obj, code=200):
            b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_MOSIPDISC(self):
            self._body()
            self._json(dev.discover(args.port))

        def do_MOSIPDINFO(self):
            self._body()
            self._json(dev.info(args.port))

        def do_RCAPTURE(self):
            req = self._body()
            self._json(dev.capture(cam, req))

        def do_CAPTURE(self):
            self.do_RCAPTURE()

        def do_STREAM(self):
            req = self._body()
            timeout_s = int(req.get("timeout") or 300000) / 1000
            self.send_response(200)
            self.send_header("Content-Type", f"multipart/x-mixed-replace; boundary={BOUNDARY}")
            self.send_header("Connection", "close")
            self.end_headers()
            start = time.monotonic()
            last = cam.seq - 1  # a new stream starts at "now"; never replays the camera's backlog
            b1 = None
            if args.b1_device:
                b1 = {"id": base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("="), "frames": [], "lock": threading.Lock()}
                dev.current_stream = b1
            if args.switch_image:
                cam.switch_at = time.monotonic() + args.switch_after_s
            rng = random.Random(args.seed + 1)
            try:
                while time.monotonic() - start < timeout_s:
                    if args.disconnect_after_s and time.monotonic() - start > args.disconnect_after_s:
                        LOG.info("emulating disconnect")
                        return
                    f = cam.visible_after(last, timeout=1.0, extra_latency_s=args.stream_delay_s)
                    if f is None:
                        continue
                    last = f.seq
                    if rng.random() < args.drop_rate or f.device_paused:
                        continue                       # device-side drop / spec pause: never emitted, not listed
                    if b1 is not None:                 # MDS-side log of what it emits (genuine bytes)
                        with b1["lock"]:
                            b1["frames"].append((len(b1["frames"]), int(f.wall.timestamp() * 1000),
                                                 hashlib.sha256(f.jpeg).digest()))
                    if f.paused:
                        continue                       # attacker-side suppression: listed but never delivered
                    jpeg = f.stream_jpeg or f.jpeg
                    if rng.random() < args.corrupt_rate:
                        cut = rng.randint(10, max(11, len(jpeg) - 1))
                        jpeg = jpeg[:cut] + bytes(rng.getrandbits(8) for _ in range(min(64, len(jpeg) - cut)))
                    hdr = (f"{BOUNDARY}\r\nAccess-Control-Allow-Origin:*\r\nContent-Type:image/jpeg\r\n"
                           f"Content-Length:{len(jpeg)}\r\n\r\n").encode()
                    self.wfile.write(hdr + jpeg + b"\r\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=4501)
    ap.add_argument("--source", nargs="+", help="image files or directories (synthetic scene); or use --camera")
    ap.add_argument("--camera", help="REAL camera index (e.g. 0 = MacBook webcam) or a video file path")
    ap.add_argument("--camera-width", type=int, default=960, help="resize camera frames to this width (aspect kept)")
    ap.add_argument("--source-hold-s", type=float, default=1e9, help="seconds per source image when cycling")
    ap.add_argument("--fps", type=float, default=15)
    ap.add_argument("--size", type=lambda s: tuple(map(int, s.split("x"))), default=(640, 480))
    ap.add_argument("--face-scale", type=float, default=0.9)
    ap.add_argument("--jpeg-quality", type=int, default=80)
    ap.add_argument("--latency-ms", type=float, default=60, help="emulated sensor->wire pipeline latency")
    ap.add_argument("--latest-only", action="store_true", help="device skips to newest frame when behind")
    ap.add_argument("--jitter", type=float, default=1.5, help="px std-dev of per-frame head motion")
    ap.add_argument("--noise", type=float, default=2.0, help="sensor noise std-dev (0..255)")
    ap.add_argument("--drop-rate", type=float, default=0.0)
    ap.add_argument("--corrupt-rate", type=float, default=0.0)
    ap.add_argument("--freeze-after-s", type=float, default=0.0)
    ap.add_argument("--disconnect-after-s", type=float, default=0.0)
    ap.add_argument("--capture-mode", choices=CAPTURE_MODES, default="best")
    ap.add_argument("--capture-time-ms", type=int, default=1500)
    ap.add_argument("--capture-size", type=lambda s: tuple(map(int, s.split("x"))), default=(480, 640))
    ap.add_argument("--jp2-rate", type=int, default=100, help="OpenCV JPEG2000 compression x1000 (1000=lossless-ish)")
    ap.add_argument("--swap-image", help="image returned by capture mode 'swap'")
    ap.add_argument("--swap-image-alt", help="image returned by capture mode 'swap-alt'")
    ap.add_argument("--swap", action="append", metavar="NAME=PATH", help="named swap image for capture mode 'swap:NAME'")
    ap.add_argument("--stale-s", type=float, default=900)
    ap.add_argument("--serial", default="PHASE0-MOCK-FACE-0001")
    ap.add_argument("--level", choices=("L0", "L1"), default="L0")
    ap.add_argument("--keys-dir", default=str(Path(__file__).with_name("keys")))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--motion", choices=("jitter", "animate", "static-replay"), default="jitter",
                    help="stream motion model: legacy rigid jitter, synthetic non-rigid [SIM], or still-photo replay")
    ap.add_argument("--inject-image", help="subject shown on the stream for phase0StreamDuringCapture=inject")
    ap.add_argument("--b1-device", action="store_true", help="B1 prototype v1: attach a signed stream digest to RCAPTURE")
    ap.add_argument("--pause-stream-during-rcapture", action="store_true", help="device emits no stream parts during RCAPTURE")
    ap.add_argument("--stream-delay-s", type=float, default=0.0, help="attacker delays every stream part by this many seconds")
    ap.add_argument("--stream-replace-image", help="T17: attacker replaces every stream part with this subject (animated)")
    ap.add_argument("--switch-image", help="person who replaces the source subject --switch-after-s after STREAM opens")
    ap.add_argument("--switch-after-s", type=float, default=4.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    signer, rogue = load_or_create_keys(Path(args.keys_dir))
    expired = None
    exp_pem = Path(args.keys_dir) / "expired.pem"
    if exp_pem.exists():
        der = lambda p: x509.load_pem_x509_certificate(p.read_bytes()).public_bytes(serialization.Encoding.DER)
        expired = Signer(signer.key, [der(exp_pem), der(Path(args.keys_dir) / "ca.pem")])
    device2 = None
    if (Path(args.keys_dir) / "device2.key").exists():
        der = lambda p: x509.load_pem_x509_certificate(p.read_bytes()).public_bytes(serialization.Encoding.DER)
        device2 = Signer(serialization.load_pem_private_key((Path(args.keys_dir) / "device2.key").read_bytes(), None),
                         [der(Path(args.keys_dir) / "device2.pem"), der(Path(args.keys_dir) / "ca.pem")])
    cam = Camera(args)
    cam.start()
    dev = Device(args, signer, rogue, expired, device2)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(dev, cam, args))
    srv.daemon_threads = True
    LOG.info("mock SBI on 127.0.0.1:%d fps=%s size=%s q=%d latency=%sms capture-mode=%s trust=%s",
             args.port, args.fps, args.size, args.jpeg_quality, args.latency_ms, args.capture_mode,
             Path(args.keys_dir) / "trust.pem")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
