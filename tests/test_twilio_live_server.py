"""Tests for the alert-only Twilio live-call bridge."""

import unittest
import os
import sys
import base64
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ElementTree
import wave

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from twilio.request_validator import RequestValidator

from twilio_live_server import (
    AlertRegistry,
    _append_transcription,
    _validate_twilio_signature,
    build_voice_twiml,
    decode_mulaw_base64,
    load_settings,
    make_stream_token,
    app,
    registry,
    validate_stream_token,
)


class TestTwilioLiveServer(unittest.TestCase):
    def setUp(self):
        self.auth_token = "test-twilio-auth-token"
        self.settings = load_settings(
            {
                "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                "TWILIO_AUTH_TOKEN": self.auth_token,
                "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                "SCAMSHIELD_FORWARD_TO": "+14155550123",
                "SCAMSHIELD_ENABLE_CALL_MONITOR": "true",
                "SCAMSHIELD_WHISPER_LANGUAGE": "en",
            }
        )
        self.call_sid = "CA" + "a" * 32

    def test_settings_require_safe_server_configuration(self):
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            load_settings(
                {
                    "SCAMSHIELD_PUBLIC_BASE_URL": "http://calls.example.com",
                    "TWILIO_AUTH_TOKEN": self.auth_token,
                    "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                    "SCAMSHIELD_FORWARD_TO": "+14155550123",
                }
            )
        with self.assertRaisesRegex(ValueError, "at least 32 characters"):
            load_settings(
                {
                    "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                    "TWILIO_AUTH_TOKEN": self.auth_token,
                    "SCAMSHIELD_ALERT_TOKEN": "short",
                    "SCAMSHIELD_FORWARD_TO": "+14155550123",
                }
            )

    def test_stream_authorization_is_bound_to_call_sid(self):
        token = make_stream_token(self.call_sid, self.auth_token)
        self.assertTrue(validate_stream_token(self.call_sid, token, self.auth_token))
        self.assertFalse(validate_stream_token(self.call_sid, token, "different-secret"))
        self.assertFalse(validate_stream_token("invalid-call-id", token, self.auth_token))

    def test_voice_twiml_starts_one_way_stream_then_forwards_call(self):
        response = ElementTree.fromstring(build_voice_twiml(self.call_sid, self.settings))
        stream = response.find("./Start/Stream")
        self.assertIsNotNone(stream)
        self.assertEqual(stream.attrib["track"], "inbound_track")
        self.assertEqual(stream.attrib["url"], "wss://calls.example.com/twilio/media")
        self.assertIsNotNone(stream.find("./Parameter[@name='streamToken']"))
        self.assertEqual(response.findtext("./Dial/Number"), "+14155550123")
        self.assertIsNone(response.find(".//Connect"))
        with self.assertRaisesRegex(ValueError, "invalid CallSid"):
            build_voice_twiml("invalid-call-id", self.settings)

    def test_twilio_webhook_signature_validation(self):
        url = "https://calls.example.com/twilio/voice"
        params = {"CallSid": self.call_sid, "To": "+14155550000"}
        signature = RequestValidator(self.auth_token).compute_signature(url, params)
        self.assertTrue(
            _validate_twilio_signature(url, signature, params, self.auth_token)
        )
        self.assertFalse(
            _validate_twilio_signature(url, "invalid-signature", params, self.auth_token)
        )
        self.assertFalse(_validate_twilio_signature(url, None, params, self.auth_token))

    def test_mulaw_payload_decodes_to_pcm16(self):
        decoded = decode_mulaw_base64("/w==")
        self.assertEqual(decoded, b"\x00\x00")
        with self.assertRaisesRegex(ValueError, "base64"):
            decode_mulaw_base64("not base64!")

    def test_registry_retains_only_redacted_transcript(self):
        call_registry = AlertRegistry()
        call_registry.start_call(self.call_sid)
        _append_transcription(
            self.call_sid,
            {"success": True, "transcript": "My OTP is"},
            alert_registry=call_registry,
        )
        _append_transcription(
            self.call_sid,
            {"success": True, "transcript": "123456. Card number is 411122223333"},
            alert_registry=call_registry,
        )
        _append_transcription(
            self.call_sid,
            {"success": True, "transcript": "4444. Send money now."},
            alert_registry=call_registry,
        )
        _append_transcription(
            self.call_sid,
            {
                "success": True,
                "transcript": "Here is some additional harmless conversation to finish the sentence.",
            },
            alert_registry=call_registry,
        )
        latest = call_registry.latest()
        self.assertIsNotNone(latest)
        self.assertNotIn("123456", latest["transcript"])
        self.assertNotIn("4111222233334444", latest["transcript"])
        self.assertIn("[REDACTED_OTP]", latest["transcript"])
        self.assertIn("[REDACTED_CARD_NUMBER]", latest["transcript"])
        self.assertEqual(latest["call_sid"], self.call_sid)
        self.assertTrue(latest["active"])
        call_registry.end_call(self.call_sid)
        self.assertFalse(call_registry.latest()["active"])
        self.assertEqual(call_registry._calls[self.call_sid].raw_transcript, "")

    def test_signed_incoming_webhook_returns_forwarding_twiml(self):
        parameters = {
            "CallSid": self.call_sid,
            "From": "+14155550111",
            "To": "+14155550112",
        }
        url = "https://calls.example.com/twilio/voice"
        signature = RequestValidator(self.auth_token).compute_signature(url, parameters)
        with patch.dict(
            os.environ,
            {
                "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                "TWILIO_AUTH_TOKEN": self.auth_token,
                "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                "SCAMSHIELD_FORWARD_TO": "+14155550123",
                "SCAMSHIELD_ENABLE_CALL_MONITOR": "true",
            },
        ):
            with TestClient(app) as client:
                response = client.post(
                    "/twilio/voice",
                    data=parameters,
                    headers={"X-Twilio-Signature": signature},
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn("wss://calls.example.com/twilio/media", response.text)
                self.assertIn("+14155550123", response.text)
                denied = client.post("/twilio/voice", data=parameters)
                self.assertEqual(denied.status_code, 403)

    def test_alert_api_requires_bearer_token(self):
        with patch.dict(
            os.environ,
            {
                "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                "TWILIO_AUTH_TOKEN": self.auth_token,
                "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                "SCAMSHIELD_FORWARD_TO": "+14155550123",
            },
        ):
            with TestClient(app) as client:
                denied = client.get("/alerts/latest")
                self.assertEqual(denied.status_code, 401)
                allowed = client.get(
                    "/alerts/latest",
                    headers={"Authorization": f"Bearer {'a' * 40}"},
                )
                self.assertEqual(allowed.status_code, 200)
                self.assertIn("call", allowed.json())

    def test_media_socket_rejects_invalid_stream_token(self):
        with patch.dict(
            os.environ,
            {
                "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                "TWILIO_AUTH_TOKEN": self.auth_token,
                "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                "SCAMSHIELD_FORWARD_TO": "+14155550123",
                "SCAMSHIELD_ENABLE_CALL_MONITOR": "true",
            },
        ):
            with TestClient(app) as client:
                with client.websocket_connect("/twilio/media") as socket:
                    with self.assertRaises(WebSocketDisconnect) as error:
                        socket.send_json(
                            {
                                "event": "start",
                                "start": {
                                    "callSid": self.call_sid,
                                    "customParameters": {"streamToken": "invalid"},
                                    "mediaFormat": {
                                        "encoding": "audio/x-mulaw",
                                        "sampleRate": 8000,
                                        "channels": 1,
                                    },
                                },
                            }
                        )
                        socket.receive_json()
                    self.assertEqual(error.exception.code, 1008)

    def test_media_socket_transcribes_authenticated_inbound_audio(self):
        transcription = {
            "success": True,
            "transcript": "This caller is threatening arrest and demanding an urgent money transfer.",
        }
        with patch.dict(
            os.environ,
            {
                "SCAMSHIELD_PUBLIC_BASE_URL": "https://calls.example.com",
                "TWILIO_AUTH_TOKEN": self.auth_token,
                "SCAMSHIELD_ALERT_TOKEN": "a" * 40,
                "SCAMSHIELD_FORWARD_TO": "+14155550123",
                "SCAMSHIELD_ENABLE_CALL_MONITOR": "true",
            },
        ):
            fake_transcriber = Mock()
            fake_transcriber.transcribe.return_value = transcription
            with patch(
                "twilio_live_server._get_transcriber",
                return_value=fake_transcriber,
            ):
                with TestClient(app) as client:
                    with client.websocket_connect("/twilio/media") as socket:
                        socket.send_json({"event": "connected"})
                        socket.send_json(
                            {
                                "event": "start",
                                "start": {
                                    "callSid": self.call_sid,
                                    "customParameters": {
                                        "streamToken": make_stream_token(
                                            self.call_sid, self.auth_token
                                        )
                                    },
                                    "mediaFormat": {
                                        "encoding": "audio/x-mulaw",
                                        "sampleRate": 8000,
                                        "channels": 1,
                                    },
                                },
                            }
                        )
                        socket.send_json(
                            {
                                "event": "media",
                                "media": {
                                    "track": "inbound",
                                    "payload": base64.b64encode(
                                        b"\xff" * (8000 * 6)
                                    ).decode("ascii"),
                                },
                            }
                        )
                        socket.send_json({"event": "stop"})
                alert = registry.latest()
                self.assertEqual(alert["call_sid"], self.call_sid)
                self.assertFalse(alert["active"])
                self.assertIn("threatening arrest", alert["transcript"])
                fake_transcriber.transcribe.assert_called_once()
                audio_bytes = fake_transcriber.transcribe.call_args.args[0]
                with wave.open(BytesIO(audio_bytes), "rb") as audio_file:
                    self.assertEqual(audio_file.getframerate(), 8000)
                    self.assertAlmostEqual(audio_file.getnframes() / 8000, 6)


if __name__ == "__main__":
    unittest.main()
