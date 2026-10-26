"""Camera-source tests for the mock SBI device, using a VIDEO FILE (no webcam needed).

Run:  .tools/.venv/bin/python -m unittest tools/mock-sbi/test_camera_source.py -v
"""
import glob
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

import cv2

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MOCK = os.path.join(ROOT, "tools", "mock-sbi", "mock_sbi.py")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port, verb, path, body, timeout=15):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/{path}", data=json.dumps(body).encode(), method=verb)
    return urllib.request.urlopen(req, timeout=timeout).read()


class CameraSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.video = os.path.join(cls.tmp, "fixture.avi")
        frames = sorted(glob.glob(os.path.join(ROOT, "research/fixtures/temporal/animate/T1/*.jpg")))
        img = cv2.imread(frames[0])
        vw = cv2.VideoWriter(cls.video, cv2.VideoWriter_fourcc(*"MJPG"), 30, (img.shape[1], img.shape[0]))
        for _ in range(4):
            for f in frames:
                vw.write(cv2.imread(f))
        vw.release()
        cls.port = free_port()
        cls.proc = subprocess.Popen([sys.executable, "-u", MOCK, "--port", str(cls.port), "--fps", "15", "--camera", cls.video],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(80):
            try:
                request(cls.port, "MOSIPDISC", "device", {}, timeout=1)
                break
            except Exception:
                time.sleep(0.25)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(10)

    def test_stream_serves_real_frames_without_duplicates(self):
        raw = request(self.port, "STREAM", "stream", {"serialNo": "x", "deviceSubId": "0", "timeout": "3000"}, timeout=10)
        parts = []
        for chunk in raw.split(b"--BoundaryString")[1:]:
            head, _, rest = chunk.partition(b"\r\n\r\n")
            n = int([l for l in head.decode(errors="ignore").split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
            parts.append(rest[:n])
        self.assertGreaterEqual(len(parts), 20, "about 15 fps for ~3 s")
        img = cv2.imdecode(__import__("numpy").frombuffer(parts[0], dtype="uint8"), cv2.IMREAD_COLOR)
        self.assertEqual(img.shape[:2], (480, 640))
        dup = sum(1 for a, b in zip(parts, parts[1:]) if a == b)
        self.assertEqual(dup, 0, "a camera frame must never be emitted twice (would read as a frozen sensor)")

    def test_rcapture_returns_a_signed_capture_of_a_camera_frame(self):
        body = {"env": "Developer", "purpose": "Registration", "specVersion": "1.0", "timeout": "10000",
                "captureTime": "2026-10-24T10:00:00", "transactionId": "txn-cam-1",
                "bio": [{"type": "Face", "count": "1", "deviceSubId": "0", "requestedScore": "40"}]}
        resp = json.loads(request(self.port, "RCAPTURE", "capture", body))
        b = resp["biometrics"][0]
        self.assertEqual(b["error"]["errorCode"], "0")
        self.assertEqual(len(b["data"].split(".")), 3)

    def test_unopenable_camera_fails_clearly(self):
        p = subprocess.run([sys.executable, MOCK, "--port", str(free_port()), "--camera", os.path.join(self.tmp, "missing.avi")],
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot open", p.stderr + p.stdout)


if __name__ == "__main__":
    unittest.main()
