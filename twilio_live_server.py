"""Alert-only Twilio Media Streams bridge for ScamShield AI."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import wave
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit
from xml.etree import ElementTree

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from twilio.request_validator import RequestValidator

from guardian_agent import analyze_message
from safety import detect_sensitive_credentials, validate_input_text


LOGGER = logging.getLogger("scamshield.twilio")
TWILIO_VOICE_PATH = "/twilio/voice"
TWILIO_MEDIA_PATH = "/twilio/media"
LIVE_SAMPLE_RATE = 8000
LIVE_CHUNK_SECONDS = 6
MIN_FINAL_CHUNK_SECONDS = 1.5
MAX_MULAW_FRAME_BYTES = 64 * 1024
MAX_TRANSCRIPT_CHARS = 5000
REDACTION_CONTEXT_CHARS = 64
ALERT_RETENTION_SECONDS = 30 * 60
MAX_WEBHOOK_BODY_BYTES = 65536
CALL_SID_PATTERN = re.compile(r"^CA[0-9a-fA-F]{32}$")
E164_PATTERN = re.compile(r"^\+[1-9][0-9]{6,14}$")
TRANSCRIBER_LOCK = threading.Lock()
_TRANSCRIBER = None


@dataclass(frozen=True)
class ServerSettings:
    public_base_url: str
    twilio_auth_token: str
    alert_token: str
    forward_to: str
    enabled: bool
    language: str


def load_settings(environ: Optional[Dict[str, str]] = None) -> ServerSettings:
    values = os.environ if environ is None else environ
    public_base_url = values.get("SCAMSHIELD_PUBLIC_BASE_URL", "").rstrip("/")
    auth_token = values.get("TWILIO_AUTH_TOKEN", "")
    alert_token = values.get("SCAMSHIELD_ALERT_TOKEN", "")
    forward_to = values.get("SCAMSHIELD_FORWARD_TO", "")
    language = values.get("SCAMSHIELD_WHISPER_LANGUAGE", "auto").lower()

    parsed_base_url = urlsplit(public_base_url)
    if (
        parsed_base_url.scheme != "https"
        or not parsed_base_url.netloc
        or not parsed_base_url.hostname
        or parsed_base_url.username
        or parsed_base_url.password
        or parsed_base_url.path
        or parsed_base_url.query
        or parsed_base_url.fragment
    ):
        raise ValueError(
            "SCAMSHIELD_PUBLIC_BASE_URL must be an HTTPS origin, such as https://calls.example.com."
        )
    if not auth_token:
        raise ValueError("TWILIO_AUTH_TOKEN must be configured.")
    if len(alert_token) < 32:
        raise ValueError("SCAMSHIELD_ALERT_TOKEN must contain at least 32 characters.")
    if not E164_PATTERN.fullmatch(forward_to):
        raise ValueError("SCAMSHIELD_FORWARD_TO must be an E.164 phone number, such as +14155550123.")
    if language not in {"auto", "en", "hi"}:
        raise ValueError("SCAMSHIELD_WHISPER_LANGUAGE must be one of: auto, en, hi.")

    return ServerSettings(
        public_base_url=public_base_url,
        twilio_auth_token=auth_token,
        alert_token=alert_token,
        forward_to=forward_to,
        enabled=values.get("SCAMSHIELD_ENABLE_CALL_MONITOR", "").lower() == "true",
        language=language,
    )


def make_stream_token(call_sid: str, auth_token: str) -> str:
    """Create a per-call MAC so only a signed Twilio webhook can authorize a stream."""
    if not isinstance(call_sid, str) or not CALL_SID_PATTERN.fullmatch(call_sid):
        raise ValueError("Invalid Twilio CallSid.")
    message = f"scamshield-media-stream:{call_sid}".encode("utf-8")
    return hmac.new(auth_token.encode("utf-8"), message, hashlib.sha256).hexdigest()


def validate_stream_token(call_sid: str, token: str, auth_token: str) -> bool:
    if (
        not isinstance(call_sid, str)
        or not CALL_SID_PATTERN.fullmatch(call_sid)
        or not isinstance(token, str)
    ):
        return False
    expected = make_stream_token(call_sid, auth_token)
    return hmac.compare_digest(expected, token)


def build_voice_twiml(call_sid: str, settings: ServerSettings) -> str:
    if not CALL_SID_PATTERN.fullmatch(call_sid):
        raise ValueError("Twilio provided an invalid CallSid.")

    response = ElementTree.Element("Response")
    start = ElementTree.SubElement(response, "Start")
    stream = ElementTree.SubElement(
        start,
        "Stream",
        {
            "name": "ScamShieldAlertOnly",
            "url": f"wss://{urlsplit(settings.public_base_url).netloc}{TWILIO_MEDIA_PATH}",
            "track": "inbound_track",
        },
    )
    ElementTree.SubElement(
        stream,
        "Parameter",
        {
            "name": "streamToken",
            "value": make_stream_token(call_sid, settings.twilio_auth_token),
        },
    )
    dial = ElementTree.SubElement(response, "Dial", {"timeout": "30"})
    ElementTree.SubElement(dial, "Number").text = settings.forward_to
    return ElementTree.tostring(response, encoding="unicode", xml_declaration=True)


def decode_mulaw_base64(payload: str) -> bytes:
    if (
        not isinstance(payload, str)
        or not payload
        or len(payload) > MAX_MULAW_FRAME_BYTES * 4 // 3 + 8
    ):
        raise ValueError("Twilio media frame is empty or too large.")
    try:
        encoded = base64.b64decode(payload, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Twilio media frame is not valid base64.") from exc
    if not encoded or len(encoded) > MAX_MULAW_FRAME_BYTES:
        raise ValueError("Twilio media frame is empty or too large.")

    pcm = bytearray(len(encoded) * 2)
    for index, value in enumerate(encoded):
        decoded = (~value) & 0xFF
        sample = ((decoded & 0x0F) << 3) + 0x84
        sample <<= (decoded & 0x70) >> 4
        sample = 0x84 - sample if decoded & 0x80 else sample - 0x84
        pcm[index * 2] = sample & 0xFF
        pcm[index * 2 + 1] = (sample >> 8) & 0xFF
    return bytes(pcm)


@dataclass
class CallSnapshot:
    call_sid: str
    active: bool
    transcript: str
    risk_level: str
    risk_score: int
    suspicious_indicators: List[str]
    updated_at: float
    raw_transcript: str = ""
    error: Optional[str] = None


class AlertRegistry:
    """Keep recent redacted call alerts in memory."""

    def __init__(self):
        self._lock = threading.Lock()
        self._calls: Dict[str, CallSnapshot] = {}
        self._latest_call_sid: Optional[str] = None

    def start_call(self, call_sid: str) -> None:
        with self._lock:
            self._purge_expired()
            self._calls[call_sid] = CallSnapshot(
                call_sid=call_sid,
                active=True,
                transcript="",
                risk_level="LOW",
                risk_score=0,
                suspicious_indicators=[],
                updated_at=time.time(),
            )
            self._latest_call_sid = call_sid

    def add_transcript(self, call_sid: str, new_text: str) -> None:
        with self._lock:
            snapshot = self._get_call(call_sid)
            combined = f"{snapshot.raw_transcript} {new_text}".strip()
            commit_size = max(0, len(combined) - REDACTION_CONTEXT_CHARS)
            if commit_size:
                safe_prefix = detect_sensitive_credentials(
                    combined[:commit_size]
                )["redacted_text"]
                snapshot.transcript = (
                    f"{snapshot.transcript} {safe_prefix}".strip()
                )[-MAX_TRANSCRIPT_CHARS:]
            snapshot.raw_transcript = combined[commit_size:]
            safe_preview = detect_sensitive_credentials(
                snapshot.raw_transcript
            )["redacted_text"]
            analysis_text = f"{snapshot.transcript} {safe_preview}".strip()
            result = analyze_message(analysis_text[-MAX_TRANSCRIPT_CHARS:])
            snapshot.risk_level = result["risk_level"]
            snapshot.risk_score = result["risk_score"]
            snapshot.suspicious_indicators = result["suspicious_indicators"]
            snapshot.error = None
            snapshot.updated_at = time.time()

    def set_error(self, call_sid: str, message: str) -> None:
        with self._lock:
            snapshot = self._get_call(call_sid)
            snapshot.error = message[:500]
            snapshot.updated_at = time.time()

    def end_call(self, call_sid: str) -> None:
        with self._lock:
            snapshot = self._calls.get(call_sid)
            if snapshot:
                if snapshot.raw_transcript:
                    safe_tail = detect_sensitive_credentials(
                        snapshot.raw_transcript
                    )["redacted_text"]
                    snapshot.transcript = (
                        f"{snapshot.transcript} {safe_tail}".strip()
                    )[-MAX_TRANSCRIPT_CHARS:]
                    result = analyze_message(snapshot.transcript)
                    snapshot.risk_level = result["risk_level"]
                    snapshot.risk_score = result["risk_score"]
                    snapshot.suspicious_indicators = result["suspicious_indicators"]
                snapshot.active = False
                snapshot.raw_transcript = ""
                snapshot.updated_at = time.time()

    def latest(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._purge_expired()
            if self._latest_call_sid is None:
                return None
            snapshot = self._calls.get(self._latest_call_sid)
            if snapshot is None:
                self._latest_call_sid = None
                return None
            return self._serialize(snapshot)

    def _serialize(self, snapshot: CallSnapshot) -> Dict[str, Any]:
        return {
            "call_sid": snapshot.call_sid,
            "active": snapshot.active,
            "transcript": snapshot.transcript,
            "risk_level": snapshot.risk_level,
            "risk_score": snapshot.risk_score,
            "suspicious_indicators": list(snapshot.suspicious_indicators),
            "updated_at": snapshot.updated_at,
            "error": snapshot.error,
        }

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [
            call_sid
            for call_sid, snapshot in self._calls.items()
            if not snapshot.active and now - snapshot.updated_at > ALERT_RETENTION_SECONDS
        ]
        for call_sid in expired:
            del self._calls[call_sid]
            if call_sid == self._latest_call_sid:
                self._latest_call_sid = None

    def get(self, call_sid: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._purge_expired()
            snapshot = self._calls.get(call_sid)
            return self._serialize(snapshot) if snapshot else None

    def _get_call(self, call_sid: str) -> CallSnapshot:
        snapshot = self._calls.get(call_sid)
        if snapshot is None:
            raise KeyError("Call is no longer available.")
        return snapshot


registry = AlertRegistry()
app = FastAPI(title="ScamShield AI Twilio Alert Monitor", version="1.0.0")


def _validate_twilio_signature(
    request_url: str,
    signature: Optional[str],
    parameters: Dict[str, str],
    auth_token: str,
) -> bool:
    if not signature:
        return False
    return RequestValidator(auth_token).validate(request_url, parameters, signature)


def _get_transcriber():
    global _TRANSCRIBER
    if _TRANSCRIBER is None:
        from audio_transcription import AudioTranscriber

        _TRANSCRIBER = AudioTranscriber()
    if _TRANSCRIBER.backend.name == "FallbackManualBackend":
        raise RuntimeError("The local faster-whisper transcription engine is not installed.")
    return _TRANSCRIBER


def _transcribe_pcm_chunk(pcm_bytes: bytes, language: str) -> Dict[str, Any]:
    wav_buffer = BytesIO()
    with wave.open(wav_buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(LIVE_SAMPLE_RATE)
        wav_file.writeframes(pcm_bytes)
    return _get_transcriber().transcribe(
        wav_buffer.getvalue(),
        "twilio_live_chunk.wav",
        language=language,
    )


def _transcribe_pcm_chunk_serialized(pcm_bytes: bytes, language: str) -> Dict[str, Any]:
    with TRANSCRIBER_LOCK:
        return _transcribe_pcm_chunk(pcm_bytes, language)


def _append_transcription(
    call_sid: str,
    result: Dict[str, Any],
    alert_registry: Optional[AlertRegistry] = None,
) -> None:
    target_registry = alert_registry or registry
    if not result.get("success"):
        target_registry.set_error(
            call_sid,
            result.get("error") or result.get("notice") or "Local live transcription failed.",
        )
        return

    raw_text = (result.get("transcript") or "").strip()
    if not raw_text:
        return
    validated = validate_input_text(raw_text)
    if not validated["is_valid"]:
        target_registry.set_error(call_sid, validated["error"])
        return
    target_registry.add_transcript(call_sid, validated["sanitized_text"])


def _require_alert_token(authorization: Optional[str], expected_token: str) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="A bearer alert token is required.")
    provided = authorization[7:]
    if not hmac.compare_digest(provided, expected_token):
        raise HTTPException(status_code=403, detail="Invalid alert token.")


@app.get("/health")
async def health():
    try:
        load_settings()
    except ValueError:
        return {"status": "needs_configuration"}
    return {"status": "enabled" if os.getenv("SCAMSHIELD_ENABLE_CALL_MONITOR", "").lower() == "true" else "disabled"}


@app.post(TWILIO_VOICE_PATH)
async def handle_incoming_call(request: Request):
    try:
        settings = load_settings()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not settings.enabled:
        raise HTTPException(status_code=503, detail="Call monitoring is disabled by configuration.")
    if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        raise HTTPException(status_code=415, detail="Expected a URL-encoded Twilio webhook.")

    try:
        body_bytes = bytearray()
        async for part in request.stream():
            if len(body_bytes) + len(part) > MAX_WEBHOOK_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Twilio webhook body is too large.")
            body_bytes.extend(part)
        body = body_bytes.decode("utf-8")
        parameters = dict(parse_qsl(body, keep_blank_values=True, max_num_fields=100))
    except HTTPException:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid Twilio webhook form body.") from exc
    external_url = settings.public_base_url + TWILIO_VOICE_PATH
    if request.url.query:
        external_url += f"?{request.url.query}"
    if not _validate_twilio_signature(
        external_url,
        request.headers.get("x-twilio-signature"),
        parameters,
        settings.twilio_auth_token,
    ):
        raise HTTPException(status_code=403, detail="Twilio webhook signature validation failed.")

    call_sid = parameters.get("CallSid", "")
    try:
        twiml = build_voice_twiml(call_sid, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content=twiml,
        media_type="application/xml",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/alerts/latest")
async def latest_alert(request: Request):
    try:
        settings = load_settings()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    _require_alert_token(request.headers.get("authorization"), settings.alert_token)
    return {"call": registry.latest()}


@app.websocket(TWILIO_MEDIA_PATH)
async def receive_call_audio(websocket: WebSocket):
    try:
        settings = load_settings()
    except ValueError:
        await websocket.close(code=1011, reason="Call monitor is not configured.")
        return
    if not settings.enabled:
        await websocket.close(code=1008, reason="Call monitoring is disabled.")
        return

    await websocket.accept()
    try:
        start_message = None
        for _ in range(3):
            raw_message = await asyncio.wait_for(websocket.receive_text(), timeout=15)
            message = json.loads(raw_message)
            if not isinstance(message, dict):
                raise ValueError("Twilio sent an invalid media event.")
            if message.get("event") == "start":
                start_message = message
                break
            if message.get("event") not in {"connected", "start"}:
                raise ValueError("Expected a Twilio connected or start message.")
        if start_message is None:
            raise ValueError("Twilio did not start a media stream.")

        start = start_message.get("start", {})
        if not isinstance(start, dict):
            raise ValueError("Twilio sent an invalid media stream start event.")
        call_sid = start.get("callSid", "")
        custom_parameters = start.get("customParameters", {})
        media_format = start.get("mediaFormat", {})
        if not isinstance(custom_parameters, dict) or not isinstance(media_format, dict):
            raise ValueError("Twilio sent invalid media stream metadata.")
        if not validate_stream_token(
            call_sid,
            custom_parameters.get("streamToken", ""),
            settings.twilio_auth_token,
        ):
            raise ValueError("Twilio media stream authorization failed.")
        if (
            media_format.get("encoding") != "audio/x-mulaw"
            or media_format.get("sampleRate") != LIVE_SAMPLE_RATE
            or media_format.get("channels") != 1
        ):
            raise ValueError("Twilio sent an unsupported audio format.")

        registry.start_call(call_sid)
        chunk_size = LIVE_SAMPLE_RATE * LIVE_CHUNK_SECONDS * 2
        min_final_size = int(LIVE_SAMPLE_RATE * MIN_FINAL_CHUNK_SECONDS * 2)
        pending_pcm = bytearray()
        work_queue: asyncio.Queue = asyncio.Queue(maxsize=3)

        async def transcribe_worker():
            while True:
                pcm_chunk = await work_queue.get()
                if pcm_chunk is None:
                    return
                try:
                    result = await asyncio.to_thread(
                        _transcribe_pcm_chunk_serialized,
                        pcm_chunk,
                        settings.language,
                    )
                    _append_transcription(call_sid, result)
                except Exception as exc:
                    LOGGER.exception("Live transcription failed for call %s.", call_sid)
                    registry.set_error(call_sid, f"Live transcription failed: {exc}")

        worker_task = asyncio.create_task(transcribe_worker())
        try:
            while True:
                raw_message = await websocket.receive_text()
                try:
                    message = json.loads(raw_message)
                except json.JSONDecodeError as exc:
                    raise ValueError("Twilio sent an invalid JSON media message.") from exc
                if not isinstance(message, dict):
                    raise ValueError("Twilio sent an invalid media event.")
                event = message.get("event")
                if event == "stop":
                    break
                if event != "media":
                    continue
                media = message.get("media", {})
                if not isinstance(media, dict):
                    raise ValueError("Twilio sent an invalid media payload.")
                if media.get("track") != "inbound":
                    continue
                pending_pcm.extend(decode_mulaw_base64(media.get("payload", "")))
                while len(pending_pcm) >= chunk_size:
                    if work_queue.full():
                        registry.set_error(
                            call_sid,
                            "Transcription is falling behind the live call. Audio processing was stopped.",
                        )
                        await websocket.close(code=1013, reason="Transcription queue is full.")
                        return
                    chunk = bytes(pending_pcm[:chunk_size])
                    del pending_pcm[:chunk_size]
                    work_queue.put_nowait(chunk)
        except WebSocketDisconnect:
            pass
        finally:
            if len(pending_pcm) >= min_final_size and not work_queue.full():
                work_queue.put_nowait(bytes(pending_pcm))
            elif pending_pcm and len(pending_pcm) < min_final_size:
                registry.set_error(
                    call_sid,
                    "The final call audio was too short to transcribe and was discarded.",
                )
            pending_pcm.clear()
            await work_queue.put(None)
            await worker_task
            registry.end_call(call_sid)
    except (asyncio.TimeoutError, json.JSONDecodeError, ValueError, KeyError) as exc:
        LOGGER.warning("Rejected Twilio media stream: %s", exc)
        try:
            await websocket.close(code=1008, reason=str(exc)[:120])
        except RuntimeError:
            pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "twilio_live_server:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )
