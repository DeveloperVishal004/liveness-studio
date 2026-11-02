import { useCallback, useEffect, useRef, useState } from 'react'

export type CameraState =
  | { kind: 'off' }
  | { kind: 'requesting' }
  | { kind: 'live'; stream: MediaStream; label: string }
  | { kind: 'denied' }
  | { kind: 'unavailable' }
  | { kind: 'busy' }
  | { kind: 'disconnected' }
  | { kind: 'error'; message: string }

export interface CameraDevice {
  id: string
  label: string
}

/**
 * Browser camera for POSITIONING PREVIEW ONLY (demo mode). Nothing from it is analysed, stored or transmitted, and it
 * has none of the trust properties of an authenticated SBI capture device. The camera is requested only on an explicit
 * user action, and every track is stopped when the preview is turned off or the component unmounts.
 */
export function useBrowserCamera() {
  const [state, setState] = useState<CameraState>({ kind: 'off' })
  const [devices, setDevices] = useState<CameraDevice[]>([])
  const [deviceId, setDeviceId] = useState<string>('')
  const streamRef = useRef<MediaStream | null>(null)
  const generation = useRef(0)

  const release = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop())
    streamRef.current = null
  }, [])

  const refreshDevices = useCallback(async () => {
    try {
      const all = await navigator.mediaDevices.enumerateDevices()
      setDevices(all.filter((d) => d.kind === 'videoinput').map((d, i) => ({ id: d.deviceId, label: d.label || `Camera ${i + 1}` })))
    } catch {
      setDevices([])
    }
  }, [])

  const stop = useCallback(() => {
    generation.current++
    release()
    setState({ kind: 'off' })
  }, [release])

  const start = useCallback(
    async (id?: string): Promise<MediaStream | null> => {
      if (!navigator.mediaDevices?.getUserMedia) {
        setState({ kind: 'unavailable' })
        return null
      }
      const gen = ++generation.current
      release()
      setState({ kind: 'requesting' })
      try {
        const want = id ?? deviceId
        const stream = await navigator.mediaDevices.getUserMedia({
          video: want ? { deviceId: { exact: want } } : { width: { ideal: 1280 }, height: { ideal: 720 } },
          audio: false,
        })
        if (gen !== generation.current) {
          stream.getTracks().forEach((t) => t.stop()) // stopped or restarted while the prompt was open
          return null
        }
        streamRef.current = stream
        const track = stream.getVideoTracks()[0]
        track?.addEventListener('ended', () => {
          if (gen === generation.current) {
            release()
            setState({ kind: 'disconnected' })
          }
        })
        setState({ kind: 'live', stream, label: track?.label || 'Camera' })
        void refreshDevices()
        return stream
      } catch (e) {
        if (gen !== generation.current) return null
        const name = e instanceof DOMException ? e.name : ''
        if (name === 'NotAllowedError' || name === 'SecurityError' || name === 'PermissionDeniedError') setState({ kind: 'denied' })
        else if (name === 'NotFoundError' || name === 'OverconstrainedError' || name === 'DevicesNotFoundError') setState({ kind: 'unavailable' })
        else if (name === 'NotReadableError' || name === 'TrackStartError') setState({ kind: 'busy' })
        else setState({ kind: 'error', message: e instanceof Error ? e.message : 'The camera could not be started.' })
        return null
      }
    },
    [deviceId, release, refreshDevices],
  )

  useEffect(() => {
    const onChange = () => void refreshDevices()
    navigator.mediaDevices?.addEventListener?.('devicechange', onChange)
    return () => navigator.mediaDevices?.removeEventListener?.('devicechange', onChange)
  }, [refreshDevices])

  useEffect(
    () => () => {
      generation.current++
      streamRef.current?.getTracks().forEach((t) => t.stop())
      streamRef.current = null
    },
    [],
  )

  /** Reuses a live stream; otherwise asks for the camera (call from a user action). */
  const ensure = useCallback(async (): Promise<MediaStream | null> => {
    const s = streamRef.current
    if (s && s.getVideoTracks().some((t) => t.readyState === 'live')) return s
    return start()
  }, [start])

  return { state, devices, deviceId, setDeviceId, start, stop, ensure }
}
