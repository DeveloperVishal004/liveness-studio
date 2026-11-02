// Plain-language copy for every machine-readable code the engine can emit. Unknown codes fall back honestly.

export interface ReasonCopy {
  title: string
  why: string
  next: string
}

const R: Record<string, ReasonCopy> = {
  OK: { title: 'All checks passed', why: 'The passive checks passed, the signed capture was bound to this attempt, and the same face appeared throughout.', next: 'Continue with registration.' },
  NONE: { title: 'No result yet', why: 'The engine has not reached a decision.', next: 'Wait for the session to finish.' },
  PASSIVE_PASSED: { title: 'Passive checks passed', why: 'In this browser, the face was found, the quality gates passed, the attack score stayed above the accept line, and natural facial movement was seen. A browser has no certified capture device, so there is no signed capture and this is NOT a verification.', next: 'For a full verification with a signed capture, run the engine locally with ./webcam.sh --ui.' },
  STREAM_PAD_ATTACK: { title: 'Presentation attack suspected', why: 'Several frames scored below the attack line on the passive presentation-attack check.', next: 'The attempt is rejected. A person should not retry with the same material.' },
  CAPTURE_PAD_ATTACK: { title: 'Signed capture looks like an attack', why: 'The signed image scored below the attack line on the presentation-attack check.', next: 'The attempt is rejected.' },
  WINDOW_PAD_ATTACK: { title: 'Attack-level frame around the capture', why: 'A frame near the moment of capture scored below the attack line.', next: 'The attempt is rejected.' },
  STATIC_REPLAY_SUSPECT: { title: 'No facial movement seen', why: 'The face did not move enough in the last few seconds, which is also what a still image looks like. Blinking alone is often too small for this camera to register.', next: 'Retry and smile or speak naturally while looking at the camera.' },
  PASSIVE_UNCERTAIN_NO_CHALLENGE: { title: 'Assessment not confident enough', why: 'The presentation-attack score stayed below the accept line and there is no challenge step to resolve it.', next: 'Retry with the face centred, in even light, closer to the camera.' },
  INSUFFICIENT_EVIDENCE: { title: 'Not enough usable frames', why: 'Too few frames passed the face-size, light and sharpness checks in time.', next: 'Retry with one face centred, well lit and in focus.' },
  MULTIPLE_FACES: { title: 'More than one face in view', why: 'The engine only assesses one person at a time.', next: 'Make sure only one person is in front of the camera, then retry.' },
  CAPTURE_UNCERTAIN: { title: 'Signed capture not confident enough', why: 'The signed image scored between the attack line and the accept gate, so the engine asks for a retry rather than accepting.', next: 'Retry with the face centred and still for the capture.' },
  CAPTURE_NOT_STARTED: { title: 'Capture was not started in time', why: 'The session was ready but no signed capture began before the time limit.', next: 'Retry.' },
  CAPTURE_TIMEOUT: { title: 'Device did not answer in time', why: 'The signed capture did not arrive before the time limit.', next: 'Check the device connection and retry.' },
  BINDING_REJECTED: { title: 'Capture could not be bound', why: 'The signed capture failed a check, so it cannot be tied to this attempt.', next: 'See the integrity checks for the first failing check, then retry.' },
  BINDING_INTEGRITY: { title: 'Capture does not match the stream', why: 'The face in the signed capture is not the person seen on the video stream.', next: 'The attempt is rejected.' },
  SUBJECT_CHANGED: { title: 'The face changed during the attempt', why: 'A face earlier in the attempt did not match the signed capture closely enough. This rule is strict, and natural head movement can occasionally trip it.', next: 'Retry facing the camera steadily.' },
  CHANNEL_INTEGRITY: { title: 'Capture channel integrity failure', why: 'The device response failed a channel check (signature, replay, device or nonce). It is counted against the device channel, not the person.', next: 'Check the device; repeated failures lock the channel for an administrator.' },
  CHANNEL_INTEGRITY_LOCKED: { title: 'Capture channel locked', why: 'The channel exceeded its integrity-failure limit and is locked until an administrator resets it.', next: 'Contact an administrator.' },
  DEVICE_FAULT: { title: 'Device fault', why: 'The device answered in a non-conforming way (for example a clock outside the window). This is diagnosed as a fault, not an attack.', next: 'Check the device configuration and retry.' },
  DEVICE_DISCONNECTED: { title: 'Device disconnected', why: 'The capture device stopped responding.', next: 'Reconnect the device and retry.' },
  DEVICE_LEVEL_INSUFFICIENT: { title: 'Device certification level too low', why: 'The workflow requires a higher device certification level.', next: 'Use a device with the required level.' },
  WINDOW_NOT_COVERED: { title: 'Stream did not cover the capture', why: 'Too few usable frames surrounded the moment of capture.', next: 'Retry.' },
  STREAM_GAP_IN_WINDOW: { title: 'Gap in the video stream', why: 'The stream paused around the capture, so the capture cannot be tied to what was seen.', next: 'Retry.' },
  INTEGRITY_IN_WINDOW: { title: 'Unusual frames around the capture', why: 'A frozen frame or a second face appeared around the capture.', next: 'Retry with one face and a steady camera.' },
  STATIC_IN_WINDOW: { title: 'Stream looked still at capture', why: 'The stream around the capture showed no facial movement.', next: 'Retry and smile or speak naturally.' },
  STATIC_IN_CAPTURE_WINDOW: { title: 'Stream looked still during capture', why: 'The stream did not move while the capture was taken.', next: 'Retry.' },
  WINDOW_PAD_INSUFFICIENT: { title: 'Presentation-attack score too low at capture', why: 'The median score around the capture was below the accept line.', next: 'Retry in even light.' },
  MISSING_EMBEDDINGS: { title: 'Not enough face samples', why: 'Too few face samples were available to compare the stream with the capture.', next: 'Retry.' },
  ATTEMPT_EVIDENCE_OVERFLOW: { title: 'Attempt grew too large', why: 'The attempt exceeded its evidence limit and failed closed.', next: 'Start a fresh attempt.' },
  INVALID_EVIDENCE: { title: 'Invalid evidence discarded', why: 'A model output was not usable and was discarded.', next: 'Retry.' },
  CLOCK_DISCONTINUITY: { title: 'Clock jump detected', why: 'The computer clock jumped during the attempt (for example after sleep), so timing cannot be trusted.', next: 'Retry.' },
  ENGINE_ERROR: { title: 'Engine error', why: 'The engine hit an internal error and failed closed. Nothing was accepted.', next: 'Retry; if it persists, check diagnostics.' },
  SESSION_EXPIRED: { title: 'Session expired', why: 'The session reached its time limit.', next: 'Start a new session.' },
  MAX_RETRIES: { title: 'Attempt limit reached', why: 'The maximum number of attempts for this person was used.', next: 'Contact an administrator.' },
  ATTACK_LIMIT: { title: 'Attack limit reached', why: 'The maximum number of suspected attacks for this person was reached.', next: 'Contact an administrator.' },
  DEVICE_RECOVERY_LIMIT: { title: 'Device recovery limit reached', why: 'The device disconnected too many times.', next: 'Check the device.' },
  LEDGER_UNTRUSTED: { title: 'Attempt record could not be trusted', why: 'The stored attempt record failed authentication, so no session may start.', next: 'Contact an administrator.' },
  CANCELLED: { title: 'Cancelled', why: 'The trial was cancelled before the engine reached a decision. It is not a pass or a fail.', next: 'Start a new verification when ready.' },
  SHUTDOWN: { title: 'Engine shut down', why: 'The engine was stopped.', next: 'Restart the application.' },
  STREAM_AUTH_PROTOCOL_FAILURE: { title: 'Signed-stream protocol failure', why: 'The signed-stream prototype reported a protocol problem.', next: 'Retry.' },
  STREAM_AUTH_INTEGRITY_FAILURE: { title: 'Signed-stream integrity failure', why: 'The signed-stream prototype reported tampering.', next: 'The attempt is rejected.' },
  // binder (capture) reasons
  PAD_ATTACK: { title: 'Capture scored as an attack', why: 'The signed image scored below the attack line.', next: 'The attempt is rejected.' },
  PAD_UNCERTAIN: { title: 'Capture score between the lines', why: 'The signed image scored above the attack line but below the accept gate.', next: 'Retry.' },
  SUBJECT_MISMATCH: { title: 'Stream and capture faces differ', why: 'The median face similarity between the stream and the signed capture was below the line.', next: 'The attempt is rejected.' },
  INSUFFICIENT_STREAM_EVIDENCE: { title: 'Too few stream face samples', why: 'Fewer than three face samples from the stream were available near the capture.', next: 'Retry; keep the face visible for the whole attempt.' },
  NO_FACE: { title: 'No face found', why: 'No face was found in the image.', next: 'Face the camera.' },
  MALFORMED_RESPONSE: { title: 'Malformed device response', why: 'The device response was not in the expected format.', next: 'Check the device.' },
  DEVICE_ERROR: { title: 'Device reported an error', why: 'The device returned an error code instead of a capture.', next: 'Check the device and retry.' },
  BAD_SIGNATURE: { title: 'Signature does not verify', why: 'The device signature did not match the content, so the capture may have been altered.', next: 'The capture is refused.' },
  UNTRUSTED_DEVICE: { title: 'Device certificate not trusted', why: 'The signer does not chain to a trusted authority, or its certificate is expired or revoked.', next: 'The capture is refused.' },
  DIGITAL_ID_INVALID: { title: 'Device identity invalid', why: 'The device identity could not be validated.', next: 'The capture is refused.' },
  DEVICE_MISMATCH: { title: 'Different device answered', why: 'The response came from a different device than the one in use.', next: 'The capture is refused.' },
  TRANSACTION_MISMATCH: { title: 'Response for another request', why: 'The signed transaction ID is not this request’s fresh nonce.', next: 'The capture is refused.' },
  TRANSACTION_ABSENT: { title: 'No transaction ID in the response', why: 'The device response carried no nonce.', next: 'Check the device.' },
  MALFORMED_CONTENT: { title: 'Capture content incomplete', why: 'The authenticated capture has malformed content such as a missing timestamp.', next: 'Check the device.' },
  CAPTURE_STALE: { title: 'Capture too old', why: 'The capture timestamp is older than this session.', next: 'The capture is refused.' },
  CAPTURE_FROM_FUTURE: { title: 'Capture dated in the future', why: 'The capture timestamp is later than now by more than the allowed skew.', next: 'Check the device clock.' },
  CAPTURE_OUTSIDE_WINDOW: { title: 'Capture outside the time window', why: 'The capture timestamp is outside the allowed window for this request.', next: 'Check the device clock and retry.' },
  REPLAYED_RESPONSE: { title: 'Response already used', why: 'This exact signed response was seen before: replay detected.', next: 'The capture is refused.' },
  BAD_BIO_FORMAT: { title: 'Biometric record invalid', why: 'The biometric record did not match the expected format or size.', next: 'Check the device.' },
  CAPTURE_UNAVAILABLE: { title: 'Capture could not run', why: 'The signed capture request failed before a response arrived.', next: 'Check the device and retry.' },
  // frame-quality codes
  FACE_TOO_SMALL: { title: 'Face too small', why: 'The face is smaller than the minimum size.', next: 'Move closer to the camera.' },
  TOO_DARK: { title: 'Too dark', why: 'The face is too dark to assess.', next: 'Add light on your face.' },
  TOO_BRIGHT: { title: 'Too bright', why: 'The face is overexposed.', next: 'Reduce glare or backlight.' },
  BLUR: { title: 'Image blurred', why: 'The face is not sharp enough.', next: 'Hold still and check the lens.' },
}

export function explainReason(code: string | null | undefined): ReasonCopy {
  if (!code) return R['NONE']!
  return R[code] ?? { title: 'Unrecognised reason code', why: `The engine reported "${code}", which this interface has no description for. The code is shown unchanged.`, next: 'See diagnostics for details.' }
}

// Frame-quality guidance shown on the camera stage (engine signals only).
export function frameGuidance(faceCount: number, ineligible: string | null, eligible: boolean): { text: string; tone: 'ok' | 'warn' | 'idle' } {
  if (faceCount < 0) return { text: 'Waiting for the first frame.', tone: 'idle' }
  if (faceCount === 0 || ineligible === 'NO_FACE') return { text: 'No face in view. Centre your face in the guide.', tone: 'warn' }
  if (faceCount > 1 || ineligible === 'MULTIPLE_FACES') return { text: 'More than one face in view. Only one person should be visible.', tone: 'warn' }
  if (eligible) return { text: 'One face, usable for assessment.', tone: 'ok' }
  switch (ineligible) {
    case 'FACE_TOO_SMALL':
      return { text: 'Too far away. Move closer to the camera.', tone: 'warn' }
    case 'TOO_DARK':
      return { text: 'Too dark. Add light on your face.', tone: 'warn' }
    case 'TOO_BRIGHT':
      return { text: 'Too bright. Reduce glare or backlight.', tone: 'warn' }
    case 'BLUR':
      return { text: 'Image is blurred. Hold still.', tone: 'warn' }
    default:
      return { text: 'Frame not usable yet.', tone: 'warn' }
  }
}

export const CHECK_MEANING: Record<string, string> = {
  response: 'The device answered with a well-formed response and no error code.',
  signature: 'The content was signed with the device key and has not been altered.',
  chain: 'The signing certificate chains to a trusted authority and is neither expired nor revoked.',
  replay: 'This exact response has not been used before.',
  device: 'The response comes from the same device identity that is in use.',
  nonce: 'The signed transaction ID equals the fresh random value requested for this capture.',
  timestamp: 'The capture time falls inside the allowed window for this request.',
  biometric: 'The biometric record has the expected format and its image size matches its header.',
  faceCount: 'Exactly one face is present in the signed image.',
  subject: 'The face in the signed image is the same person seen on the video stream.',
  streamAuth: 'Whether the video stream itself carries a device signature.',
}

export const STAGE_GLOSSARY: Record<string, string> = {
  YuNet: 'A small face-detection model that finds faces and five landmarks.',
  MiniFASNet: 'A public presentation-attack model. Its score is not calibrated for this setup and is not a probability of identity.',
  SFace: 'A face-recognition model used only to compare the stream face with the capture face within one attempt. No face is looked up or stored.',
  PAD: 'Presentation-attack detection: telling a live face from a photo, screen or mask.',
}
