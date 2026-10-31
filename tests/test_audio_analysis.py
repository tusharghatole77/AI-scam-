"""
ScamShield AI - Recorded Call Analysis & Audio Transcription Test Suite
=======================================================================
Comprehensive deterministic unit and integration tests verifying:
- WAV and MP3 file validation and security limits (25 MB cap, binary header checks).
- Audio metadata extraction (duration, sample rate, channels, bit depth).
- Pluggable transcription backends (Mock, Fallback, Local hook).
- Error handling (empty files, corrupted streams, oversized files, transcription failures).
- End-to-end integration: Audio -> Transcription -> Safety Redaction -> Guardian Risk Scoring -> Intelligence Reporting.

Uses mocked audio backends so zero internet access, paid APIs, or heavy neural weights are required.
"""

import os
import sys
import json
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from audio_transcription import (
    validate_audio_file,
    extract_audio_metadata,
    create_synthetic_wav,
    AudioTranscriber,
    MockTranscriptionBackend,
    FallbackManualBackend,
    FasterWhisperTranscriptionBackend,
    get_sample_call_presets,
    MAX_AUDIO_SIZE_BYTES,
    normalize_language_code,
    build_domain_initial_prompt,
    inspect_audio_signal,
    evaluate_transcript_quality,
    resolve_optimal_device,
    DEFAULT_WHISPER_MODEL,
)
from guardian_agent import analyze_message
from intelligence_agent import extract_intelligence, format_text_report
from safety import validate_input_text, detect_sensitive_credentials, validate_intelligence_report
from live_audio import LiveAudioBuffer, pcm16_mono_to_wav


class TestAudioAnalysis(unittest.TestCase):
    """Test suite for audio validation, transcription, and downstream agent integration."""

    @classmethod
    def setUpClass(cls):
        # Generate standard synthetic 16-bit mono 16kHz WAV audio bytes (2 seconds)
        cls.valid_wav_bytes = create_synthetic_wav(duration_seconds=2.0, sample_rate=16000, frequency_hz=440.0)

    # -----------------------------------------------------------------------
    # 1. Audio File Validation Tests
    # -----------------------------------------------------------------------

    def test_01_valid_wav_validation(self):
        """Verifies that a valid WAV file passes validation with correct properties."""
        res = validate_audio_file(self.valid_wav_bytes, "call_recording.wav")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["audio_format"], "WAV")
        self.assertIsNone(res["error"])
        self.assertGreater(res["file_size_bytes"], 1000)

    def test_live_audio_buffer_yields_fixed_chunks(self):
        buffer = LiveAudioBuffer(
            chunk_seconds=1,
            max_buffer_seconds=3,
            sample_rate=2,
            resampler=object(),
        )
        buffer.append_pcm_bytes(b"\x01\x00")
        self.assertAlmostEqual(buffer.buffered_seconds, 0.5)
        self.assertIsNone(buffer.take_chunk())

        buffer.append_pcm_bytes(b"\x02\x00")
        chunk = buffer.take_chunk()
        self.assertEqual(chunk, b"\x01\x00" + b"\x02\x00")
        self.assertEqual(buffer.buffered_seconds, 0)
        buffer.append_pcm_bytes(b"\x03\x00")
        buffer.discard_pending_audio()
        self.assertEqual(buffer.buffered_seconds, 0)

    def test_live_audio_buffer_flushes_final_speech_chunk(self):
        buffer = LiveAudioBuffer(
            chunk_seconds=2,
            max_buffer_seconds=3,
            sample_rate=2,
            resampler=object(),
        )
        final_audio = b"\x01\x00" * 3
        buffer.append_pcm_bytes(final_audio)
        self.assertIsNone(buffer.take_chunk())
        self.assertEqual(buffer.take_chunk(final=True), final_audio)

    def test_live_audio_wav_conversion_and_buffer_limit(self):
        wav_bytes = pcm16_mono_to_wav(b"\x00\x00" * 4, sample_rate=8000)
        metadata = extract_audio_metadata(wav_bytes, "live_chunk.wav")
        self.assertTrue(metadata["is_valid_audio"])
        self.assertEqual(metadata["sample_rate_hz"], 8000)

        buffer = LiveAudioBuffer(
            chunk_seconds=1,
            max_buffer_seconds=1,
            sample_rate=2,
            resampler=object(),
        )
        buffer.append_pcm_bytes(b"\x00\x00" * 3)
        self.assertIn("buffer is full", buffer.error)
        with self.assertRaises(ValueError):
            pcm16_mono_to_wav(b"\x00")

    def test_02_wav_metadata_extraction(self):
        """Verifies extraction of duration, sample rate, bit depth, and channels."""
        meta = extract_audio_metadata(self.valid_wav_bytes, "test_call.wav")
        self.assertTrue(meta["is_valid_audio"])
        self.assertEqual(meta["format"], "WAV")
        self.assertEqual(meta["channels"], 1)
        self.assertEqual(meta["sample_rate_hz"], 16000)
        self.assertEqual(meta["bit_depth"], 16)
        self.assertAlmostEqual(meta["duration_seconds"], 2.0, delta=0.1)
        self.assertEqual(meta["duration_formatted"], "00:02")

    def test_03_oversized_audio_rejection(self):
        """Verifies that an audio file exceeding the 25 MB limit is rejected with explicit error."""
        # Test with custom max_size_mb = 0.05 MB (~50 KB)
        res = validate_audio_file(self.valid_wav_bytes, "huge_recording.wav", max_size_mb=0.01)
        self.assertFalse(res["is_valid"])
        self.assertIn("exceeds the maximum limit", res["error"])

    def test_04_empty_audio_rejection(self):
        """Verifies that empty bytes or None input are rejected gracefully."""
        res_empty = validate_audio_file(b"", "empty.wav")
        self.assertFalse(res_empty["is_valid"])
        self.assertIn("empty", res_empty["error"].lower())

        res_none = validate_audio_file(None, "none.wav")
        self.assertFalse(res_none["is_valid"])
        self.assertIn("no audio", res_none["error"].lower())

    def test_05_unsupported_format_rejection(self):
        """Verifies that non-audio extensions (.pdf, .exe, .sh) are rejected immediately."""
        fake_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        res_exe = validate_audio_file(fake_payload, "malicious_script.exe")
        self.assertFalse(res_exe["is_valid"])
        self.assertIn("unsupported audio extension", res_exe["error"].lower())

    def test_06_corrupted_wav_header_rejection(self):
        """Verifies that arbitrary binary data disguised with a .wav extension is rejected."""
        fake_wav = b"RIFF\x00\x00\x00\x00CORRUPT_NOT_WAVE_HEADER"
        res = validate_audio_file(fake_wav, "spoofed.wav")
        self.assertFalse(res["is_valid"])
        self.assertIn("corrupted or invalid wav file", res["error"].lower())

    def test_07_valid_mp3_validation(self):
        """Verifies that valid ID3 or frame sync headers are accepted for MP3."""
        # Simulated MP3 with ID3 header
        id3_mp3 = b"ID3\x03\x00\x00\x00\x00\x00#" + b"\xff\xfb\x90\x64" * 100
        res = validate_audio_file(id3_mp3, "call_recording.mp3")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["audio_format"], "MP3")

        # Non-MP3 with .mp3 extension rejected
        corrupt_mp3 = b"NOT_REAL_MP3_DATA_AT_ALL"
        res_corrupt = validate_audio_file(corrupt_mp3, "corrupted.mp3")
        self.assertFalse(res_corrupt["is_valid"])
        self.assertIn("corrupted or invalid mp3", res_corrupt["error"].lower())

    # -----------------------------------------------------------------------
    # 2. Transcription Backend Interface Tests
    # -----------------------------------------------------------------------

    def test_08_mock_transcription_success(self):
        """Verifies that MockTranscriptionBackend produces deterministic transcript output."""
        expected_text = "This is Officer Vikram. Transfer Rs 50,000 immediately."
        mock_backend = MockTranscriptionBackend(default_transcript=expected_text)
        transcriber = AudioTranscriber(backend=mock_backend)

        res = transcriber.transcribe(self.valid_wav_bytes, "police_call.wav")
        self.assertTrue(res["success"])
        self.assertEqual(res["transcript"], expected_text)
        self.assertGreaterEqual(res["confidence"], 0.9)
        self.assertEqual(res["engine_used"], "MockTranscriptionBackend")
        self.assertTrue(res["metadata"]["is_valid_audio"])

    def test_09_mock_transcription_failure_handling(self):
        """Verifies that simulated transcription engine errors are handled gracefully."""
        mock_backend = MockTranscriptionBackend()
        mock_backend.trigger_failure("Acoustic model out of memory error.")
        transcriber = AudioTranscriber(backend=mock_backend)

        res = transcriber.transcribe(self.valid_wav_bytes, "failed_call.wav")
        self.assertFalse(res["success"])
        self.assertEqual(res["transcript"], "")
        self.assertIn("Acoustic model out of memory error", res["error"])

    def test_10_fallback_manual_backend_notice(self):
        """Verifies that FallbackManualBackend explicitly communicates model unavailability."""
        fallback = FallbackManualBackend()
        transcriber = AudioTranscriber(backend=fallback)

        res = transcriber.transcribe(self.valid_wav_bytes, "uploaded_call.wav")
        self.assertFalse(res["success"])
        self.assertFalse(res["is_real_stt"])
        self.assertIn("neural speech-to-text model weights", res["notice"])
        self.assertIn("type or paste the transcript into the text area", res["notice"])

    def test_11_demo_presets_generation(self):
        """Verifies that all 6 demo presets generate valid audio bytes and non-empty transcripts."""
        presets = get_sample_call_presets()
        self.assertEqual(len(presets), 6)

        for p in presets:
            self.assertIn("filename", p)
            self.assertIn("transcript", p)
            self.assertGreater(len(p["transcript"]), 30)
            self.assertIn("audio_bytes", p)
            self.assertGreater(len(p["audio_bytes"]), 1000)
            # Verify synthesized WAV container is structurally valid
            val = validate_audio_file(p["audio_bytes"], p["filename"])
            self.assertTrue(val["is_valid"])

    # -----------------------------------------------------------------------
    # 3. Downstream Agent Integration Tests (Audio -> Safety -> Guardian -> Intel)
    # -----------------------------------------------------------------------

    def test_12_audio_transcript_guardian_integration(self):
        """Verifies that a transcribed extortion call flows into Guardian Agent and produces HIGH risk."""
        call_transcript = (
            "This is Officer Vikram Sharma from Delhi Police Crime Branch. "
            "A digital arrest warrant has been issued against you for illegal narcotics trafficking. "
            "Transfer Rs 50,000 immediately to the clearance account to avoid police raid. "
            "Do not disconnect the video call."
        )
        mock_backend = MockTranscriptionBackend(default_transcript=call_transcript)
        transcriber = AudioTranscriber(backend=mock_backend)

        trans_res = transcriber.transcribe(self.valid_wav_bytes, "delhi_police_call.wav")
        self.assertTrue(trans_res["success"])

        # Feed transcript into Guardian Agent
        guardian_res = analyze_message(trans_res["transcript"])
        self.assertEqual(guardian_res["risk_level"], "HIGH")
        self.assertGreaterEqual(guardian_res["risk_score"], 70)
        self.assertTrue(any("Authority" in ind for ind in guardian_res["suspicious_indicators"]))
        self.assertTrue(any("Arrest" in ind for ind in guardian_res["suspicious_indicators"]))

    def test_13_audio_transcript_safety_redaction(self):
        """Verifies that an audio transcript with sensitive credentials is sanitized by Safety module."""
        call_with_otp = (
            "Bank automated alert: Your account is suspended. "
            "Please speak your 6-digit OTP 849201 and ATM PIN 1234 to verify identity."
        )
        mock_backend = MockTranscriptionBackend(default_transcript=call_with_otp)
        transcriber = AudioTranscriber(backend=mock_backend)

        trans_res = transcriber.transcribe(self.valid_wav_bytes, "bank_phishing_call.wav")
        raw_text = trans_res["transcript"]

        # Safety redaction
        cred_res = detect_sensitive_credentials(raw_text)
        self.assertTrue(cred_res["credentials_detected"])
        self.assertIn("[REDACTED_OTP]", cred_res["redacted_text"])
        self.assertIn("[REDACTED_PIN]", cred_res["redacted_text"])
        self.assertNotIn("849201", cred_res["redacted_text"])
        self.assertNotIn("1234", cred_res["redacted_text"])

    def test_14_audio_transcript_intelligence_integration(self):
        """Verifies that a transcribed call flows into Intelligence Agent and extracts entities."""
        call_transcript = (
            "This is Officer Vikram Sharma from Delhi Police Cyber Crime Branch, Badge DL-9482. "
            "Transfer Rs 35,000 immediately to UPI ID police.clearance@sbi to freeze your arrest warrant."
        )
        mock_backend = MockTranscriptionBackend(default_transcript=call_transcript)
        transcriber = AudioTranscriber(backend=mock_backend)
        trans_res = transcriber.transcribe(self.valid_wav_bytes, "customs_call.wav")

        transcript_history = [
            {"turn": 1, "role": "caller", "message": trans_res["transcript"]}
        ]
        raw_rep = extract_intelligence(transcript_history)
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]

        # Validate extraction of entities
        names = [n["value"] for n in san_rep["unverified_caller_claims"]["claimed_names"] if isinstance(n, dict)]
        depts = [d["value"] for d in san_rep["unverified_caller_claims"]["claimed_departments"] if isinstance(d, dict)]
        amounts = [a["value"] for a in san_rep["unverified_caller_claims"]["claimed_payment_amounts"] if isinstance(a, dict)]
        upis = [u["value"] for u in san_rep["extracted_indicators"]["upi_ids"] if isinstance(u, dict)]

        self.assertIn("Vikram Sharma", names)
        self.assertTrue(any("delhi police" in d.lower() for d in depts))
        self.assertIn("35,000", amounts)
        self.assertIn("police.clearance@sbi", upis)

        # Verify export formatting
        text_export = san_rep.get("formatted_text_report", "")
        self.assertIn("DEFENSIVE CYBER THREAT INTELLIGENCE REPORT", text_export)
        self.assertIn("police.clearance@sbi", text_export)

    def test_15_empty_transcript_handling(self):
        """Verifies that an empty transcript string does not crash Guardian or Intelligence engines."""
        mock_backend = MockTranscriptionBackend(default_transcript="")
        transcriber = AudioTranscriber(backend=mock_backend)
        res = transcriber.transcribe(self.valid_wav_bytes, "silent.wav")

        guardian_res = analyze_message(res["transcript"])
        self.assertEqual(guardian_res["risk_level"], "LOW")
        self.assertEqual(guardian_res["risk_score"], 0)

        intel_res = extract_intelligence([{"turn": 1, "role": "caller", "message": res["transcript"]}])
        self.assertEqual(len(intel_res["detected_tactics"]), 0)

    def test_16_streamlit_dashboard_audio_tab_rendering(self):
        """Verifies that app.py initializes with all 5 navigation tabs including Recorded Call Analysis."""
        try:
            from streamlit.testing.v1 import AppTest
            at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=25)
            at.run()
            self.assertFalse(at.exception)
            self.assertEqual(len(at.tabs), 5)
            tab_labels = [tab.label for tab in at.tabs]
            self.assertTrue(any("Recorded Call" in lbl for lbl in tab_labels))
            self.assertTrue(any("Guardian Agent" in lbl for lbl in tab_labels))
            self.assertTrue(any("Decoy Agent" in lbl for lbl in tab_labels))
            self.assertTrue(any("Intelligence Agent" in lbl for lbl in tab_labels))
            self.assertTrue(any("Safety" in lbl for lbl in tab_labels))
        except ImportError:
            self.skipTest("streamlit.testing.v1 not available in this environment")

    def test_17_faster_whisper_backend_initialization(self):
        """Verifies that FasterWhisperTranscriptionBackend initializes with expected defaults."""
        backend = FasterWhisperTranscriptionBackend(
            model_size="tiny",
            device="cpu",
            compute_type="int8",
        )
        self.assertEqual(backend.name, "FasterWhisperBackend(tiny)")
        self.assertEqual(backend.model_size, "tiny")
        self.assertEqual(backend.device, "cpu")
        self.assertEqual(backend.compute_type, "int8")

    def test_18_faster_whisper_backend_availability(self):
        """Verifies that FasterWhisperTranscriptionBackend is_available returns a valid boolean."""
        backend = FasterWhisperTranscriptionBackend()
        # In .venv, faster-whisper is installed and should be available
        self.assertTrue(backend.is_available())

    def test_19_faster_whisper_invalid_audio_error_handling(self):
        """Verifies that corrupted bytes return failure without crashing."""
        backend = FasterWhisperTranscriptionBackend()
        res = backend.transcribe(b"CORRUPTED_BINARY_NOT_AUDIO", "corrupted.wav")
        self.assertFalse(res["success"])
        self.assertEqual(res["transcript"], "")
        self.assertFalse(res["is_real_stt"])
        self.assertIn("error", res)

    def test_20_audio_transcriber_defaults_to_faster_whisper(self):
        """Verifies that AudioTranscriber automatically activates FasterWhisperBackend when installed."""
        transcriber = AudioTranscriber()
        self.assertIsInstance(transcriber.backend, FasterWhisperTranscriptionBackend)
        self.assertTrue(transcriber.backend.is_available())

    def test_21_streamlit_dashboard_tab4_preset_and_analysis_flow(self):
        """Verifies that Tab 4 in app.py loads audio presets, analyzes the call, and exposes report exports."""
        try:
            from streamlit.testing.v1 import AppTest
            at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=25)
            at.run()
            # Click Tab 4 preset button (Call 1: Police Digital Arrest)
            preset_btn = [b for b in at.button if "Call 1" in (b.help or "")][0]
            preset_btn.click().run()
            self.assertFalse(at.exception)
            self.assertIsNotNone(at.session_state.recorded_call_bytes)
            self.assertGreater(len(at.session_state.recorded_call_transcript), 30)

            # Click Analyze Recorded Call button
            analyze_btn = [b for b in at.button if "Analyze Recorded Call" in b.label][0]
            analyze_btn.click().run()
            self.assertFalse(at.exception)
            self.assertIsNotNone(at.session_state.recorded_call_analysis)
            self.assertEqual(at.session_state.recorded_call_analysis["risk_level"], "HIGH")
            self.assertIsNotNone(at.session_state.recorded_call_intel_report)
            self.assertEqual(len(at.download_button), 2)
        except ImportError:
            self.skipTest("streamlit.testing.v1 not available in this environment")

    def test_22_normalize_language_code(self):
        """Verifies language code normalization for Whisper."""
        self.assertIsNone(normalize_language_code("auto"))
        self.assertIsNone(normalize_language_code(None))
        self.assertIsNone(normalize_language_code(""))
        self.assertIsNone(normalize_language_code("unknown"))
        self.assertEqual(normalize_language_code("hi"), "hi")
        self.assertEqual(normalize_language_code("HINDI"), "hi")
        self.assertEqual(normalize_language_code("en"), "en")
        self.assertEqual(normalize_language_code("English"), "en")
        self.assertEqual(normalize_language_code("fr"), "fr")

    def test_23_build_domain_initial_prompt(self):
        """Verifies domain vocabulary prompt generation for Hindi and English cybercrime contexts."""
        prompt_hi = build_domain_initial_prompt("hi")
        self.assertIn("सीबीआई", prompt_hi)
        self.assertIn("डिजिटल अरेस्ट", prompt_hi)
        self.assertIn("वारंट", prompt_hi)

        prompt_en = build_domain_initial_prompt("en")
        self.assertIn("Delhi Police", prompt_en)
        self.assertIn("digital arrest", prompt_en)
        self.assertIn("clearance", prompt_en)

        prompt_auto = build_domain_initial_prompt(None)
        self.assertIn("Delhi Police", prompt_auto)

    def test_24_inspect_audio_signal(self):
        """Verifies audio signal inspection for silence, short duration, and normal waveforms."""
        # 1. Normal sine tone WAV
        sig_norm = inspect_audio_signal(self.valid_wav_bytes, "normal.wav")
        self.assertTrue(sig_norm["is_valid"])
        self.assertFalse(sig_norm["is_near_silent"])
        self.assertFalse(sig_norm["is_extremely_short"])
        self.assertAlmostEqual(sig_norm["duration_seconds"], 2.0, delta=0.2)
        self.assertGreater(sig_norm["rms_amplitude"], 0.05)

        # 2. Pure silence WAV
        import io, wave
        silent_buf = io.BytesIO()
        with wave.open(silent_buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b"\x00\x00" * 16000)
        sig_silent = inspect_audio_signal(silent_buf.getvalue(), "silent.wav")
        self.assertTrue(sig_silent["is_near_silent"])
        self.assertLess(sig_silent["peak_amplitude"], 0.01)

        # 3. Extremely short audio (<0.5s)
        short_wav = create_synthetic_wav(duration_seconds=0.3, sample_rate=16000, frequency_hz=440.0)
        sig_short = inspect_audio_signal(short_wav, "short.wav")
        self.assertTrue(sig_short["is_extremely_short"])

    def test_25_evaluate_transcript_quality(self):
        """Verifies transcript quality evaluation including code-switching and repetition loops."""
        # Empty transcript
        q_empty = evaluate_transcript_quality(
            transcript="",
            overall_confidence=0.0,
            lang_prob=0.0,
            detected_language="unknown",
            requested_language=None,
            duration_sec=2.0,
            is_silent=True,
        )
        self.assertEqual(q_empty["rating"], "EMPTY")
        self.assertEqual(q_empty["score"], 0.0)
        self.assertFalse(q_empty["is_reliable"])

        # High-confidence speech
        q_good = evaluate_transcript_quality(
            transcript="This is Officer Vikram Sharma calling from Delhi Police Cyber Cell regarding a warrant.",
            overall_confidence=0.92,
            lang_prob=0.98,
            detected_language="en",
            requested_language="en",
            duration_sec=5.0,
        )
        self.assertIn(q_good["rating"], ["HIGH", "MODERATE"])
        self.assertTrue(q_good["is_reliable"])
        self.assertFalse(q_good["code_switching_detected"])

        # Code-switching detection (Hindi Devanagari + English Latin)
        q_mixed = evaluate_transcript_quality(
            transcript="सीबीआई Cyber Cell से कॉल है। Aapka digital arrest warrant issue हुआ है।",
            overall_confidence=0.75,
            lang_prob=0.80,
            detected_language="hi",
            requested_language="hi",
            duration_sec=6.0,
        )
        self.assertTrue(q_mixed["code_switching_detected"])
        self.assertTrue(any("code-switching" in w.lower() for w in q_mixed["warnings"]))

        # Hallucination / repetition loop detection via segments
        segments = [
            {"id": 0, "text": "police officer", "start": 0.0, "end": 1.0},
            {"id": 1, "text": "police officer", "start": 1.0, "end": 2.0},
            {"id": 2, "text": "police officer", "start": 2.0, "end": 3.0},
        ]
        q_loop = evaluate_transcript_quality(
            transcript="police officer police officer police officer",
            overall_confidence=0.60,
            lang_prob=0.90,
            detected_language="en",
            requested_language="en",
            duration_sec=3.0,
            segments=segments,
        )
        self.assertTrue(any("repetitive" in w.lower() or "hallucination" in w.lower() for w in q_loop["warnings"]))

    def test_26_configurable_model_and_env_override(self):
        """Verifies Whisper model configuration parameter and environment variable override."""
        # Custom model_size argument
        backend_small = FasterWhisperTranscriptionBackend(model_size="small")
        self.assertEqual(backend_small.model_size, "small")
        self.assertEqual(backend_small.name, "FasterWhisperBackend(small)")

        # Environment variable override
        old_env = os.environ.get("SCAMSHIELD_WHISPER_MODEL")
        try:
            os.environ["SCAMSHIELD_WHISPER_MODEL"] = "tiny"
            backend_env = FasterWhisperTranscriptionBackend()
            self.assertEqual(backend_env.model_size, "tiny")
        finally:
            if old_env is not None:
                os.environ["SCAMSHIELD_WHISPER_MODEL"] = old_env
            else:
                os.environ.pop("SCAMSHIELD_WHISPER_MODEL", None)

    def test_27_resolve_optimal_device(self):
        """Verifies safe device resolution with CPU int8 fallback."""
        dev, comp, desc = resolve_optimal_device("cpu")
        self.assertEqual(dev, "cpu")
        self.assertEqual(comp, "int8")
        self.assertIn("CPU", desc)

        # Auto device should return valid 3-tuple
        auto_dev, auto_comp, auto_desc = resolve_optimal_device("auto")
        self.assertIn(auto_dev, ["cpu", "cuda"])
        self.assertIn(auto_comp, ["int8", "float16"])
        self.assertIsInstance(auto_desc, str)

    def test_28_demo_preset_hindi_digital_arrest(self):
        """Verifies that Preset 6 (Hindi Digital Arrest) loads and processes through Guardian and Intel Agents."""
        presets = get_sample_call_presets()
        self.assertGreaterEqual(len(presets), 6)
        preset_hindi = presets[5]
        self.assertEqual(preset_hindi["id"], "demo_call_06")
        self.assertIn("सीबीआई", preset_hindi["transcript"])
        self.assertEqual(preset_hindi["expected_risk"], "HIGH")

        # Guardian Agent risk assessment on Hindi preset
        guardian_res = analyze_message(preset_hindi["transcript"])
        self.assertEqual(guardian_res["risk_level"], "HIGH")
        self.assertGreaterEqual(guardian_res["risk_score"], 60)

        # Intelligence Agent report extraction on Hindi preset
        call_history = [{"turn": 1, "role": "caller", "message": preset_hindi["transcript"]}]
        raw_rep = extract_intelligence(call_history)
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]
        self.assertIsNotNone(san_rep)
        self.assertTrue(len(san_rep["missing_information"]) > 0)

    def test_29_transcription_language_parameter_handling(self):
        """Verifies that AudioTranscriber passes language parameters through to backends."""
        mock_backend = MockTranscriptionBackend(default_transcript="नमस्ते अधिकारी")
        transcriber = AudioTranscriber(backend=mock_backend)

        res = transcriber.transcribe(self.valid_wav_bytes, "hindi_test.wav", language="hi")
        self.assertTrue(res["success"])
        self.assertEqual(res["language_requested"], "hi")
        self.assertEqual(res["transcript"], "नमस्ते अधिकारी")
        self.assertIn("quality_assessment", res)
        self.assertIn("segments", res)



def run_audio_tests():
    """Runs all audio analysis tests with a structured console summary."""
    print("=" * 80)
    print("SCAMSHIELD AI - RECORDED CALL ANALYSIS TEST SUITE")
    print("Verification of Audio Validation, Transcription Interface & Agent Pipelines")
    print("=" * 80)

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAudioAnalysis)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    print(f"AUDIO TEST SUMMARY: {result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors")
    if result.wasSuccessful():
        print("ALL AUDIO ANALYSIS TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_audio_tests()
    sys.exit(0 if success else 1)
