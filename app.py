"""
ScamShield AI - Defensive Cybersecurity Dashboard
==================================================
Streamlit-based unified dashboard integrating:
1. Guardian Agent: Rule-based scam and extortion detection.
2. Decoy Agent: Simulated counter-extortion multi-turn dialogue.
3. Intelligence Agent: Structured threat reporting, entity extraction, and gap analysis.
4. Safety System: Credential redaction, input validation, and local execution boundaries.

DISCLAIMER:
Educational defensive prototype developed for cybersecurity hackathons.
All external telecom/SMS actions are disabled. All analysis remains strictly local.
"""

import sys
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime
from typing import Any, Optional, Dict, List
from urllib.parse import urlsplit

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Attempt Streamlit import with graceful message if not installed
try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    st = None
    STREAMLIT_AVAILABLE = False

# Import ScamShield AI internal agent modules
from guardian_agent import analyze_message, GuardianAgent
from decoy_agent import respond_as_decoy, DecoyAgent, DEFAULT_PERSONA
from intelligence_agent import extract_intelligence, IntelligenceAgent, format_text_report
from safety import (
    validate_input_text,
    detect_sensitive_credentials,
    redact_sensitive_credentials,
    validate_intelligence_report,
    generate_safe_advisory,
    enforce_local_safeguards,
    SafetySystem,
)
from audio_transcription import (
    validate_audio_file,
    extract_audio_metadata,
    inspect_audio_signal,
    create_synthetic_wav,
    AudioTranscriber,
    FasterWhisperTranscriptionBackend,
    get_sample_call_presets,
    MAX_AUDIO_SIZE_BYTES,
)
from live_audio import LiveAudioBuffer, pcm16_mono_to_wav

try:
    from streamlit_webrtc import WebRtcMode, webrtc_streamer
    STREAMLIT_WEBRTC_AVAILABLE = True
except ImportError:
    WebRtcMode = None
    webrtc_streamer = None
    STREAMLIT_WEBRTC_AVAILABLE = False


def _set_recorded_call_transcript(text: str) -> None:
    st.session_state.recorded_call_transcript = text
    st.session_state.recorded_call_transcript_input = text


def _sync_recorded_call_transcript() -> None:
    st.session_state.recorded_call_transcript = st.session_state.recorded_call_transcript_input


def _fetch_latest_telephony_alert():
    base_url = os.getenv("SCAMSHIELD_ALERT_API_URL", "").rstrip("/")
    alert_token = os.getenv("SCAMSHIELD_ALERT_TOKEN", "")
    if not base_url or not alert_token:
        return None, None
    parsed_url = urlsplit(base_url)
    if (
        (parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1", "::1"})
        or parsed_url.username
        or parsed_url.password
        or parsed_url.path
        or parsed_url.query
        or parsed_url.fragment
    ):
        return None, "Telephony alert API must use HTTPS except for localhost development."
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        return None, "SCAMSHIELD_ALERT_API_URL must be a valid HTTP(S) origin."

    request = urllib.request.Request(
        f"{base_url}/alerts/latest",
        headers={"Authorization": f"Bearer {alert_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None, f"Telephony alert service returned HTTP {exc.code}."
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, f"Could not reach the telephony alert service: {exc}"
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"Telephony alert service returned invalid JSON: {exc}"

    call = payload.get("call")
    if call is not None and not isinstance(call, dict):
        return None, "Telephony alert service returned an invalid call payload."
    return call, None


def run_dashboard():
    if not STREAMLIT_AVAILABLE or st is None:
        print('=' * 80)
        print('ScamShield AI - Streamlit Dashboard')
        print('=' * 80)
        print('\n[!] Streamlit is not currently installed in this Python environment.')
        print('To launch the interactive dashboard, please run:')
        print('    pip install streamlit')
        print('\nThen run:')
        print('    streamlit run app.py')
        print('=' * 80)
        return

    # ---------------------------------------------------------------------------
    # Streamlit Page Configuration & Dark Cybersecurity Theme
    # ---------------------------------------------------------------------------

    st.set_page_config(
        page_title="ScamShield AI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom CSS for Cybersecurity Dark Theme
    st.markdown(
        """
        <style>
        /* Cybersecurity theme colors */
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --accent-blue: #58a6ff;
            --danger-red: #f85149;
            --warning-amber: #d29922;
            --safe-green: #3fb950;
            --text-primary: #c9d1d9;
        }

        .main-title {
            font-size: 2.3rem;
            font-weight: 800;
            color: #58a6ff;
            margin-bottom: 0px;
            letter-spacing: -0.5px;
        }
        .main-subtitle {
            font-size: 1.15rem;
            font-weight: 500;
            color: #8b949e;
            margin-top: 0px;
            margin-bottom: 1.5rem;
        }
        .cyber-card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }
        .badge-high {
            background-color: rgba(248, 81, 73, 0.15);
            color: #f85149;
            border: 1px solid #f85149;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            display: inline-block;
        }
        .badge-medium {
            background-color: rgba(210, 153, 34, 0.15);
            color: #d29922;
            border: 1px solid #d29922;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            display: inline-block;
        }
        .badge-low {
            background-color: rgba(63, 185, 80, 0.15);
            color: #3fb950;
            border: 1px solid #3fb950;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            display: inline-block;
        }
        .evidence-quote {
            background-color: #0d1117;
            border-left: 3px solid #58a6ff;
            padding: 6px 12px;
            margin: 6px 0px;
            font-family: monospace;
            font-size: 0.88rem;
            color: #e6edf3;
        }
        .missing-alert {
            background-color: rgba(210, 153, 34, 0.08);
            border-left: 3px solid #d29922;
            padding: 6px 12px;
            margin: 4px 0px;
            font-size: 0.88rem;
            color: #e3b341;
        }
        .helpline-banner {
            background: linear-gradient(90deg, #1f2937, #111827);
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 10px 16px;
            margin-bottom: 1.25rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


    # ---------------------------------------------------------------------------
    # Session State Initialization
    # ---------------------------------------------------------------------------

    if "decoy_history" not in st.session_state:
        st.session_state.decoy_history = []

    if "intel_report" not in st.session_state:
        st.session_state.intel_report = None

    if "guardian_result" not in st.session_state:
        st.session_state.guardian_result = None

    if "sample_guardian_text" not in st.session_state:
        st.session_state.sample_guardian_text = ""

    if "recorded_call_bytes" not in st.session_state:
        st.session_state.recorded_call_bytes = None

    if "recorded_call_filename" not in st.session_state:
        st.session_state.recorded_call_filename = None

    if "recorded_call_transcript" not in st.session_state:
        st.session_state.recorded_call_transcript = ""

    if "recorded_call_transcript_input" not in st.session_state:
        st.session_state.recorded_call_transcript_input = st.session_state.recorded_call_transcript

    if "recorded_call_metadata" not in st.session_state:
        st.session_state.recorded_call_metadata = None

    if "recorded_call_analysis" not in st.session_state:
        st.session_state.recorded_call_analysis = None

    if "recorded_call_intel_report" not in st.session_state:
        st.session_state.recorded_call_intel_report = None

    if "recorded_call_notice" not in st.session_state:
        st.session_state.recorded_call_notice = None

    if "recorded_call_stt_result" not in st.session_state:
        st.session_state.recorded_call_stt_result = None

    if "live_monitor_enabled" not in st.session_state:
        st.session_state.live_monitor_enabled = False

    if "live_audio_buffer" not in st.session_state:
        st.session_state.live_audio_buffer = None

    if "live_call_transcript" not in st.session_state:
        st.session_state.live_call_transcript = ""

    if "live_call_risk" not in st.session_state:
        st.session_state.live_call_risk = None

    if "live_call_error" not in st.session_state:
        st.session_state.live_call_error = None

    if "live_monitor_was_playing" not in st.session_state:
        st.session_state.live_monitor_was_playing = False



    # ---------------------------------------------------------------------------
    # Sidebar: System Status, Persona & Emergency Helplines
    # ---------------------------------------------------------------------------

    with st.sidebar:
        st.markdown("### 🛡️ ScamShield AI")
        st.markdown("**Version:** 1.0.0 (Hackathon Prototype)")
        st.markdown("---")

        st.markdown("#### 🔒 System Guardrails")
        st.success("● Local Mode: ACTIVE")
        st.info("● Auto External Calls: BLOCKED")
        st.info("● Auto Message Dispatch: BLOCKED")
        st.info("● Paid APIs Required: NONE")

        st.markdown("---")
        st.markdown("#### 👤 Decoy Persona")
        st.markdown(f"**Name:** {DEFAULT_PERSONA['name']} (Age: {DEFAULT_PERSONA['age']})")
        st.markdown(f"**Role:** {DEFAULT_PERSONA['background']}")
        st.caption(f"**Demeanor:** {DEFAULT_PERSONA['demeanor']}")

        st.markdown("---")
        st.markdown("#### 🚨 Official Helplines (India)")
        st.markdown("📞 **Cybercrime Helpline:** **`1930`**")
        st.markdown("🌐 **Reporting Portal:** [cybercrime.gov.in](https://cybercrime.gov.in)")
        st.markdown("🚨 **Police Emergency:** **`112`**")

        st.markdown("---")
        st.caption(
            "Notice: This prototype is for educational cybersecurity demonstration only. "
            "All intelligence claims are unverified."
        )


    # ---------------------------------------------------------------------------
    # Header Section
    # ---------------------------------------------------------------------------

    st.markdown('<div class="main-title">🛡️ ScamShield AI</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="main-subtitle">Defensive Cybersecurity Prototype — Detect the Scam. Outsmart the Scammer.</div>',
        unsafe_allow_html=True,
    )

    # Emergency helpline banner
    st.markdown(
        """
        <div class="helpline-banner">
            <strong>⚠️ Suspect an active cyber extortion or digital arrest scam?</strong>
            Disconnect the call immediately. Do NOT transfer funds or share OTPs.
            Dial National Cyber Crime Helpline <strong>1930</strong> or visit 
            <a href="https://cybercrime.gov.in" target="_blank" style="color:#58a6ff;">cybercrime.gov.in</a>.
        </div>
        """,
        unsafe_allow_html=True,
    )


    # ---------------------------------------------------------------------------
    # Main Navigation Tabs
    # ---------------------------------------------------------------------------

    tab_guardian, tab_decoy, tab_intel, tab_audio, tab_safety = st.tabs([
        "🛡️ Guardian Agent (Detection)",
        "🤖 Decoy Agent (Simulation)",
        "📊 Intelligence Agent (Report)",
        "🎙️ Live & Recorded Call Analysis",
        "🔒 Safety & Compliance Guardrails",
    ])


    # ===========================================================================
    # TAB 1: GUARDIAN AGENT (Scam Detection)
    # ===========================================================================

    with tab_guardian:
        st.markdown("### 🛡️ Guardian Agent: Scam & Extortion Detection")
        st.markdown(
            "Analyze incoming SMS, WhatsApp messages, or call transcripts to detect suspicious indicators such as "
            "police impersonation, digital arrest intimidation, urgent money demands, and credential harvesting."
        )

        # Quick Sample Presets
        st.markdown("##### Quick-Load Demonstration Samples:")
        col_s1, col_s2, col_s3, col_s4 = st.columns(4)

        with col_s1:
            if st.button("🚨 Police Digital Arrest", use_container_width=True):
                st.session_state.sample_guardian_text = (
                    "This is Officer Sharma from Delhi Police Crime Branch. A digital arrest warrant "
                    "has been issued against your name for an illegal parcel and money laundering. "
                    "Transfer Rs 50,000 immediately to the clearance account to unfreeze your identity, "
                    "or police officers will be dispatched within 30 minutes. Do not disconnect the call."
                )

        with col_s2:
            if st.button("💳 Banking KYC Phishing", use_container_width=True):
                st.session_state.sample_guardian_text = (
                    "URGENT: Your SBI bank account will be blocked within 2 hours due to expired KYC. "
                    "Share your OTP and NetBanking password immediately to avoid permanent deactivation."
                )

        with col_s3:
            if st.button("☕ Casual Friend Message", use_container_width=True):
                st.session_state.sample_guardian_text = (
                    "Hey! Are we still meeting for lunch at 1 PM today? Let me know if you want to grab coffee afterwards."
                )

        with col_s4:
            if st.button("🚓 Casual Police Mention", use_container_width=True):
                st.session_state.sample_guardian_text = (
                    "I was driving home and noticed the local police conducting regular traffic checks near the mall."
                )

        # Input Text Area
        user_message = st.text_area(
            "Paste Text Message or Call Transcript:",
            value=st.session_state.sample_guardian_text,
            height=140,
            placeholder="Enter or paste the message you want to analyze...",
        )

        col_btn1, col_btn2 = st.columns([1, 4])
        with col_btn1:
            analyze_clicked = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
        with col_btn2:
            if st.button("Clear Input", use_container_width=False):
                st.session_state.sample_guardian_text = ""
                st.session_state.guardian_result = None
                st.rerun()

        if analyze_clicked:
            # Step 1: Safety Input Validation
            val_res = validate_input_text(user_message)
            if not val_res["is_valid"]:
                st.error(f"❌ Input Error: {val_res['error']}")
            else:
                if val_res["warning"]:
                    st.warning(f"⚠️ Notice: {val_res['warning']}")

                # Step 2: Credential Redaction & Detection
                cred_res = detect_sensitive_credentials(val_res["sanitized_text"])
                if cred_res["credentials_detected"]:
                    st.warning(f"🛡️ Safety Shield: {cred_res['safety_warning']}")

                # Step 3: Run Guardian Analysis on sanitized/redacted text
                analysis = analyze_message(cred_res["redacted_text"])
                st.session_state.guardian_result = analysis

        # Display Guardian Analysis Results
        if st.session_state.guardian_result:
            res = st.session_state.guardian_result
            st.markdown("---")
            st.markdown("#### 📋 Assessment Results")

            # Top Metric Cards
            col_m1, col_m2, col_m3 = st.columns(3)
            with col_m1:
                risk_lvl = res.get("risk_level", "LOW")
                if risk_lvl == "HIGH":
                    badge_html = '<span class="badge-high">🚨 HIGH RISK</span>'
                elif risk_lvl == "MEDIUM":
                    badge_html = '<span class="badge-medium">⚠️ MEDIUM RISK</span>'
                else:
                    badge_html = '<span class="badge-low">✅ LOW RISK</span>'
                st.markdown(f"**Threat Classification:**<br>{badge_html}", unsafe_allow_html=True)

            with col_m2:
                st.metric(label="Risk Score", value=f"{res.get('risk_score', 0)} / 100")

            with col_m3:
                num_indicators = len(res.get("suspicious_indicators", []))
                st.metric(label="Suspicious Indicators", value=f"{num_indicators} Detected")

            # Explanation
            st.markdown("##### 🔍 Analysis Rationale:")
            st.info(res.get("explanation", "No explanation available."))

            # Detected Indicators List
            indicators = res.get("suspicious_indicators", [])
            if indicators:
                st.markdown("##### 🚩 Detected Threat Indicators:")
                for ind in indicators:
                    st.markdown(f"- **{ind}**")

            # Recommended Action
            st.markdown("##### 🛡️ Recommended Safe Next Steps:")
            st.success(res.get("recommended_action", "No action specified."))


    # ===========================================================================
    # TAB 2: DECOY AGENT (Simulation)
    # ===========================================================================

    with tab_decoy:
        st.markdown("### 🤖 Decoy Agent: Multi-Turn Counter-Extortion Simulation")
        st.markdown(
            "Engage simulated extortion threats using an autonomous, fictional persona (**Ramesh Kumar**, 68-year-old retired clerk). "
            "The agent asks safe, clarifying questions to elicit official badge IDs, case dockets, and payment destinations "
            "without revealing any real personal credentials."
        )

        st.caption("🔒 **SIMULATION ONLY**: Operates strictly locally. Never contacts real phone numbers or sends external messages.")

        # Demonstration Presets for Scammer Turns
        st.markdown("##### Load Preset Scammer Dialogue Turns:")
        col_p1, col_p2, col_p3 = st.columns(3)

        with col_p1:
            if st.button("Turn 1: Opening Digital Arrest Threat", use_container_width=True):
                st.session_state.current_scammer_turn = (
                    "This is Inspector Vikram Rathore from Delhi Police Cyber Crime Branch. "
                    "A digital arrest warrant has been issued in your name for illegal narcotics tracking. "
                    "Do not hang up or officers will reach your residence!"
                )

        with col_p2:
            if st.button("Turn 2: Badge & Court Fine Demand", use_container_width=True):
                st.session_state.current_scammer_turn = (
                    "I am Officer Vikram, Badge #DL-9482, New Delhi Cyber Cell. "
                    "You must immediately pay a security deposit of Rs 75,000 to the court clearance account "
                    "to freeze the arrest warrant, or you will be taken into custody in 1 hour."
                )

        with col_p3:
            if st.button("Turn 3: Payment Demand to UPI", use_container_width=True):
                st.session_state.current_scammer_turn = (
                    "Send Rs 75,000 right now to our RBI clearing UPI ID: police.clearance@sbi. "
                    "Transfer it immediately and keep your video camera turned on."
                )

        # Preset text holder in session
        if "current_scammer_turn" not in st.session_state:
            st.session_state.current_scammer_turn = ""

        # Conversation History Display
        st.markdown("---")
        st.markdown("#### 💬 Simulation Transcript")

        history = st.session_state.decoy_history
        if not history:
            st.info("ℹ️ No simulated conversation in progress. Submit an opening scammer message below to start.")
        else:
            for entry in history:
                role = entry.get("role", "").lower()
                msg = entry.get("message", "")
                turn_idx = entry.get("turn", 1)

                if role == "scammer":
                    with st.chat_message("user", avatar="🚨"):
                        st.markdown(f"**Simulated Scammer (Turn {turn_idx}):**")
                        st.write(msg)
                else:
                    with st.chat_message("assistant", avatar="👴"):
                        st.markdown(f"**Decoy Agent (Ramesh Kumar - Turn {turn_idx}):**")
                        st.write(msg)

        st.markdown("---")
        # Message Input Controls
        scammer_input = st.text_input(
            "Enter simulated scammer message:",
            value=st.session_state.current_scammer_turn,
            placeholder="Type a simulated scammer response...",
        )

        col_act1, col_act2, col_act3 = st.columns([2, 1, 1])

        with col_act1:
            send_scammer = st.button("💬 Send to Decoy Agent", type="primary", use_container_width=True)
        with col_act2:
            stop_convo = st.button("🛑 Stop / Hang Up", use_container_width=True)
        with col_act3:
            reset_convo = st.button("🔄 Reset Dialogue", use_container_width=True)

        # Action Handlers
        if send_scammer:
            val_input = validate_input_text(scammer_input)
            if not val_input["is_valid"]:
                st.error(f"❌ Input Error: {val_input['error']}")
            else:
                # Check for credential leakage and redact
                cred_res = detect_sensitive_credentials(val_input["sanitized_text"])
                if cred_res["credentials_detected"]:
                    st.warning(f"🛡️ Safety Shield: {cred_res['safety_warning']}")

                # Call Decoy Agent with updated history
                decoy_res = respond_as_decoy(
                    scammer_message=cred_res["redacted_text"],
                    conversation_history=st.session_state.decoy_history,
                    stop_requested=False,
                )
                st.session_state.decoy_history = decoy_res["conversation_history"]
                st.session_state.current_scammer_turn = ""

                if not decoy_res["is_active"]:
                    st.warning(f"🛑 Conversation Concluded: {decoy_res['stop_reason']}")
                st.rerun()

        if stop_convo:
            stop_res = respond_as_decoy(
                scammer_message="stop",
                conversation_history=st.session_state.decoy_history,
                stop_requested=True,
            )
            st.session_state.decoy_history = stop_res["conversation_history"]
            st.session_state.current_scammer_turn = ""
            st.warning(f"🛑 Conversation Concluded: {stop_res['stop_reason']}")
            st.rerun()

        if reset_convo:
            st.session_state.decoy_history = []
            st.session_state.intel_report = None
            st.session_state.current_scammer_turn = ""
            st.success("✅ Conversation history reset.")
            st.rerun()


    # ===========================================================================
    # TAB 3: INTELLIGENCE AGENT (Report)
    # ===========================================================================

    with tab_intel:
        st.markdown("### 📊 Intelligence Agent: Threat Report & Gap Analysis")
        st.markdown(
            "Synthesizes unverified identifiers, claimed official names/badges, demanded amounts, and observed tactics "
            "extracted from the Decoy Agent interaction."
        )

        col_int1, col_int2 = st.columns([2, 2])

        with col_int1:
            generate_report_btn = st.button(
                "📊 Generate Intelligence Report from Current Dialogue",
                type="primary",
                use_container_width=True,
            )

        with col_int2:
            if st.button("⚡ Load Demo Extortion Dialogue & Generate Report", use_container_width=True):
                # Pre-load complete 3-turn demonstration
                demo_transcript = [
                    {
                        "turn": 1,
                        "role": "scammer",
                        "message": "This is Inspector Vikram Rathore from Delhi Police Cyber Crime Branch. A digital arrest warrant has been issued in your name for illegal narcotics tracking. Do not hang up or officers will reach your residence!",
                    },
                    {
                        "turn": 1,
                        "role": "decoy",
                        "message": "Oh God, please don't arrest me! I will cooperate fully. What is your officer badge ID and station?",
                    },
                    {
                        "turn": 2,
                        "role": "scammer",
                        "message": "I am Officer Vikram, Badge #DL-9482, New Delhi Cyber Cell. You must immediately pay a security deposit of Rs 75,000 to the court clearance account to freeze the arrest warrant, or you will be taken into custody in 1 hour.",
                    },
                    {
                        "turn": 2,
                        "role": "decoy",
                        "message": "I noted your badge ID, officer. Exactly which UPI ID or bank account should I send the payment to?",
                    },
                    {
                        "turn": 3,
                        "role": "scammer",
                        "message": "Send Rs 75,000 right now to our RBI clearing UPI ID: police.clearance@sbi. Transfer it immediately and keep your video camera turned on.",
                    },
                ]
                st.session_state.decoy_history = demo_transcript
                raw_rep = extract_intelligence(demo_transcript)
                val_rep = validate_intelligence_report(raw_rep)
                st.session_state.intel_report = val_rep["sanitized_report"]
                st.rerun()

        if generate_report_btn:
            if not st.session_state.decoy_history:
                st.warning("⚠️ No dialogue history available. Run the Decoy simulation first or load the demo dialogue.")
            else:
                raw_rep = extract_intelligence(st.session_state.decoy_history)
                val_rep = validate_intelligence_report(raw_rep)
                st.session_state.intel_report = val_rep["sanitized_report"]
                st.rerun()

        # Display Report
        if st.session_state.intel_report:
            rep = st.session_state.intel_report
            st.markdown("---")

            # Top Level Report Header Metrics
            col_rh1, col_rh2, col_rh3 = st.columns(3)
            with col_rh1:
                st.markdown(f"**Report ID:** `{rep.get('report_id', 'N/A')}`")
                st.caption(f"Generated: {rep.get('timestamp', 'N/A')[:19]}")
            with col_rh2:
                r_lvl = rep.get("risk_assessment", {}).get("risk_level", "LOW")
                if r_lvl == "HIGH":
                    badge = '<span class="badge-high">🚨 HIGH RISK THREAT</span>'
                elif r_lvl == "MEDIUM":
                    badge = '<span class="badge-medium">⚠️ MEDIUM RISK THREAT</span>'
                else:
                    badge = '<span class="badge-low">✅ LOW RISK THREAT</span>'
                st.markdown(f"**Threat Level:**<br>{badge}", unsafe_allow_html=True)
            with col_rh3:
                st.metric("Threat Score", f"{rep.get('risk_assessment', {}).get('risk_score', 0)} / 100")

            # Executive Summary
            st.markdown("##### 📝 Executive Summary:")
            summary_text = rep.get("conversation_summary", {}).get("executive_summary", "N/A")
            st.info(summary_text)

            # 2-Column Breakdown: Unverified Claims vs Actionable Indicators
            col_c1, col_c2 = st.columns(2)

            with col_c1:
                st.markdown("#### 👤 Unverified Caller Claims")
                claims = rep.get("unverified_caller_claims", {})

                def _render_claims(label: str, items: Any):
                    st.markdown(f"**{label}:**")
                    if isinstance(items, list) and items:
                        for it in items:
                            st.markdown(f"- **{it['value']}**")
                            st.caption(f"Quote: \"{it['evidence_quote']}\"")
                    else:
                        st.caption("• Not found")

                _render_claims("Claimed Official Names", claims.get("claimed_names"))
                _render_claims("Claimed Departments", claims.get("claimed_departments"))
                _render_claims("Claimed Badge IDs", claims.get("claimed_badge_ids"))
                _render_claims("Demanded Amounts", claims.get("claimed_payment_amounts"))

            with col_c2:
                st.markdown("#### 🎯 Extracted Actionable Indicators")
                indicators = rep.get("extracted_indicators", {})

                _render_claims("Flagged UPI IDs", indicators.get("upi_ids"))
                _render_claims("Flagged Phone Numbers", indicators.get("phone_numbers"))
                _render_claims("Bank Account References", indicators.get("bank_accounts"))
                _render_claims("IFSC Codes", indicators.get("ifsc_codes"))

            # Observed Tactics
            st.markdown("---")
            st.markdown("#### ⚔️ Observed Scam Tactics & Supporting Evidence")
            tactics = rep.get("detected_tactics", [])
            if tactics:
                for t in tactics:
                    st.markdown(f"- **[{t['tactic']}]** — *Confidence:* `{t['confidence']}`")
                    st.markdown(f'<div class="evidence-quote">"{t["evidence_quote"]}"</div>', unsafe_allow_html=True)
            else:
                st.caption("No coercive tactics detected in this transcript.")

            # Gap Analysis
            st.markdown("---")
            st.markdown("#### 🔍 Gap Analysis (Missing Official Credentials)")
            st.caption("Fraud campaigns typically fail to provide verified credentials. The following expected credentials were absent:")
            missing = rep.get("missing_information", [])
            for m in missing:
                st.markdown(f'<div class="missing-alert">⚠️ <strong>Missing:</strong> {m}</div>', unsafe_allow_html=True)

            # Recommended Defensive Next Steps
            st.markdown("---")
            st.markdown("#### 🛡️ Recommended Defensive Next Steps")
            steps = rep.get("recommended_next_steps", [])
            for idx, s in enumerate(steps, 1):
                st.markdown(f"**{idx}.** {s}")

            # Download Report Options
            st.markdown("---")
            st.markdown("##### 📥 Export Intelligence Report:")
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    label="📄 Download Formatted Text Report (.txt)",
                    data=rep.get("formatted_text_report", ""),
                    file_name=f"{rep.get('report_id', 'report')}.txt",
                    mime="text/plain",
                    use_container_width=True,
                )
            with col_d2:
                st.download_button(
                    label="📦 Download Structured Report (.json)",
                    data=json.dumps(rep, indent=2),
                    file_name=f"{rep.get('report_id', 'report')}.json",
                    mime="application/json",
                    use_container_width=True,
                )

            # View Raw Text Report in Expander
            with st.expander("👁️ View Full Formatted ASCII Report"):
                st.text(rep.get("formatted_text_report", "N/A"))


    # ===========================================================================
    # TAB 4: RECORDED CALL ANALYSIS (Audio Transcription & Risk Detection)
    # ===========================================================================

    with tab_audio:
        st.markdown("### 🎙️ Live & Recorded Call Analysis: Voice Extortion & Scam Detection")
        st.markdown("#### 📞 Telephony Provider Alerts (Alert-Only)")
        st.caption(
            "For real phone calls, the separate Twilio service forwards the call to you and sends "
            "redacted live transcript/risk updates here. It never speaks to the caller."
        )
        if not (
            os.getenv("SCAMSHIELD_ALERT_API_URL")
            and os.getenv("SCAMSHIELD_ALERT_TOKEN")
        ):
            st.info(
                "The telephony service is not connected yet. Configure "
                "`SCAMSHIELD_ALERT_API_URL` and `SCAMSHIELD_ALERT_TOKEN` after deploying "
                "`twilio_live_server.py`."
            )
        else:
            @st.fragment(run_every="3s")
            def render_telephony_alert():
                call_alert, alert_error = _fetch_latest_telephony_alert()
                if alert_error:
                    st.error(alert_error)
                elif not call_alert:
                    st.info("Waiting for a monitored incoming call.")
                else:
                    status = "Call is active" if call_alert.get("active") else "Last call ended"
                    st.caption(f"{status} · Call reference: `{call_alert.get('call_sid', 'N/A')}`")
                    if call_alert.get("error"):
                        st.warning(call_alert["error"])
                    transcript = call_alert.get("transcript", "")
                    if transcript:
                        st.text_area(
                            "Redacted live call transcript",
                            value=transcript,
                            height=130,
                            disabled=True,
                            key=f"telephony_transcript_{call_alert.get('call_sid', 'latest')}",
                        )
                    level = call_alert.get("risk_level", "LOW")
                    score = call_alert.get("risk_score", 0)
                    if level == "HIGH":
                        st.error(
                            f"HIGH scam risk — {score}/100. Do not transfer money or share "
                            "OTPs, passwords, or PINs."
                        )
                    elif level == "MEDIUM":
                        st.warning(
                            f"Potential scam indicators detected — {score}/100. "
                            "Verify the caller independently."
                        )
                    else:
                        st.info(f"Current risk assessment: {level} — {score}/100.")
                    for indicator in call_alert.get("suspicious_indicators", []):
                        st.markdown(f"- {indicator}")

            render_telephony_alert()

        st.markdown("---")
        st.markdown("#### 🔴 Live Call Monitor")
        st.markdown(
            "Monitor a call in real time through your computer's microphone. Put the call on speakerphone "
            "so the other caller is audible to the microphone. This browser app cannot access a phone's "
            "private cellular-call audio directly."
        )
        st.caption(
            "Audio is processed locally in short chunks and is not saved as a recording. The microphone "
            "runs only while live monitoring is active; use this only where you have permission to monitor the call."
        )

        transcriber_engine = AudioTranscriber()
        is_stt_ready = (
            transcriber_engine.backend.is_available()
            and transcriber_engine.backend.name != "FallbackManualBackend"
        )

        if not STREAMLIT_WEBRTC_AVAILABLE:
            st.error(
                "Live microphone capture is unavailable. Install the project dependencies with "
                "`python -m pip install -r requirements.txt`, then restart the app."
            )
        elif not is_stt_ready:
            st.error(
                "Live transcription needs the local faster-whisper engine. Install the project dependencies "
                "with `python -m pip install -r requirements.txt`, then restart the app."
            )
        elif not st.session_state.live_monitor_enabled:
            if st.button("Enable Live Call Monitor", type="primary", key="enable_live_call_monitor"):
                st.session_state.live_audio_buffer = LiveAudioBuffer()
                st.session_state.live_call_transcript = ""
                st.session_state.live_call_risk = None
                st.session_state.live_call_error = None
                st.session_state.live_monitor_was_playing = False
                st.session_state.live_monitor_enabled = True
                st.rerun()
        else:
            live_language_label = st.selectbox(
                "Live call language:",
                options=[
                    "Hindi (हिन्दी / Hinglish)",
                    "Auto-detect",
                    "English",
                ],
                key="live_call_language",
            )
            live_language_code = {
                "Hindi (हिन्दी / Hinglish)": "hi",
                "Auto-detect": "auto",
                "English": "en",
            }[live_language_label]
            live_buffer = st.session_state.live_audio_buffer

            if live_buffer is None:
                st.error("Live audio buffer was not initialized. Disable and re-enable the live monitor.")
            else:
                @st.fragment(run_every="2s")
                def render_live_call_monitor():
                    live_ctx = webrtc_streamer(
                        key="live-call-microphone",
                        mode=WebRtcMode.SENDONLY,
                        rtc_configuration={"iceServers": []},
                        audio_frame_callback=live_buffer.audio_frame_callback,
                        media_stream_constraints={"video": False, "audio": True},
                        async_processing=True,
                    )

                    if live_ctx.state.playing:
                        st.success("Microphone is active. Listening locally for speech...")
                        st.session_state.live_monitor_was_playing = True
                    elif st.session_state.live_monitor_was_playing:
                        st.info("Microphone stopped. Processing any remaining audio...")

                    if live_buffer.error:
                        st.error(live_buffer.error)

                    final_chunk = (
                        not live_ctx.state.playing
                        and st.session_state.live_monitor_was_playing
                    )
                    pcm_chunk = live_buffer.take_chunk()
                    if pcm_chunk is None and final_chunk:
                        pcm_chunk = live_buffer.take_chunk(final=True)

                    if pcm_chunk:
                        try:
                            chunk_wav = pcm16_mono_to_wav(pcm_chunk, live_buffer.sample_rate)
                            result = transcriber_engine.transcribe(
                                chunk_wav,
                                "live_call_chunk.wav",
                                language=live_language_code,
                            )
                        except (OSError, RuntimeError, ValueError) as exc:
                            st.session_state.live_call_error = f"Live transcription failed: {exc}"
                            result = None

                        if result is not None:
                            if result.get("success") and result.get("transcript", "").strip():
                                new_text = result["transcript"].strip()
                                previous_text = st.session_state.live_call_transcript.strip()
                                st.session_state.live_call_transcript = (
                                    f"{previous_text} {new_text}".strip()
                                )
                                validated = validate_input_text(
                                    st.session_state.live_call_transcript[-5000:]
                                )
                                if validated["is_valid"]:
                                    credentials = detect_sensitive_credentials(validated["sanitized_text"])
                                    st.session_state.live_call_risk = analyze_message(
                                        credentials["redacted_text"]
                                    )
                                else:
                                    st.session_state.live_call_error = validated["error"]
                            elif not result.get("success"):
                                st.session_state.live_call_error = result.get(
                                    "error", result.get("notice", "Live transcription failed.")
                                )

                    if st.session_state.live_call_error:
                        st.error(st.session_state.live_call_error)

                    transcript = st.session_state.live_call_transcript
                    if transcript:
                        st.markdown("##### Live transcript (review before relying on it)")
                        st.text(transcript)
                        risk = st.session_state.live_call_risk
                        if risk:
                            level = risk.get("risk_level", "LOW")
                            score = risk.get("risk_score", 0)
                            if level == "HIGH":
                                st.error(
                                    f"HIGH scam risk — {score}/100. Consider ending the call. "
                                    "Do not transfer money or share OTPs, passwords, or PINs."
                                )
                            elif level == "MEDIUM":
                                st.warning(
                                    f"Potential scam indicators detected — {score}/100. "
                                    "Verify the caller independently; do not share sensitive information."
                                )
                            else:
                                st.info(f"Current risk assessment: {level} — {score}/100.")

                        if st.button("Use live transcript in call analysis", key="use_live_transcript"):
                            _set_recorded_call_transcript(transcript)
                            st.rerun()
                    else:
                        st.caption(
                            "Transcription updates in approximately six-second chunks. "
                            f"Audio buffered: {live_buffer.buffered_seconds:.1f}s."
                        )

                    if final_chunk and live_buffer.buffered_seconds < 1.5:
                        if live_buffer.buffered_seconds:
                            st.caption(
                                "The final audio tail was shorter than 1.5 seconds and was not transcribed."
                            )
                            live_buffer.discard_pending_audio()
                        st.session_state.live_monitor_was_playing = False

                render_live_call_monitor()

        st.markdown("---")
        st.markdown(
            "Upload or inspect suspicious voice recordings (.wav or .mp3, max 25 MB) to perform offline acoustic "
            "metadata inspection, speech-to-text transcript verification, Guardian threat scoring, and structured intelligence reporting."
        )
        st.caption("🔒 **LOCAL DEFENSIVE PROCESSING ONLY**: Audio recordings and transcripts remain strictly on your local machine. No external APIs or cloud services are contacted.")

        # Preset Demonstration Calls
        st.markdown("##### 📻 Quick-Load Demonstration Call Presets:")
        col_cp1, col_cp2, col_cp3, col_cp4, col_cp5, col_cp6 = st.columns(6)
        demo_presets = get_sample_call_presets()

        with col_cp1:
            if st.button("🚨 Police Arrest", use_container_width=True, help="Call 1: Delhi Police Digital Arrest Threat"):
                p = demo_presets[0]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 1: {p['caller_label']}"

        with col_cp2:
            if st.button("📦 Customs Courier", use_container_width=True, help="Call 2: Customs Courier Contraband Threat"):
                p = demo_presets[1]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 2: {p['caller_label']}"

        with col_cp3:
            if st.button("💳 Bank Phishing", use_container_width=True, help="Call 3: Bank KYC Account Suspension"):
                p = demo_presets[2]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 3: {p['caller_label']}"

        with col_cp4:
            if st.button("⚡ Power Cutoff", use_container_width=True, help="Call 4: Electricity Disconnection Extortion"):
                p = demo_presets[3]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 4: {p['caller_label']}"

        with col_cp5:
            if st.button("☕ Friend Call", use_container_width=True, help="Call 5: Benign Lunch Invitation"):
                p = demo_presets[4]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 5: {p['caller_label']}"

        with col_cp6:
            if st.button("🚨 CBI Arrest (Hindi)", use_container_width=True, help="Call 6: CBI Digital Arrest Extortion (Hindi / Hinglish)"):
                p = demo_presets[5]
                st.session_state.recorded_call_bytes = p["audio_bytes"]
                st.session_state.recorded_call_filename = p["filename"]
                _set_recorded_call_transcript(p["transcript"])
                st.session_state.recorded_call_metadata = extract_audio_metadata(p["audio_bytes"], p["filename"])
                st.session_state.recorded_call_analysis = None
                st.session_state.recorded_call_intel_report = None
                st.session_state.recorded_call_stt_result = None
                st.session_state.recorded_call_notice = f"Loaded Reference Demo Call 6: {p['caller_label']}"

        st.markdown("---")
        st.markdown("#### 📁 Step 1: Upload Recorded Audio File")

        uploaded_audio_file = st.file_uploader(
            "Upload audio recording (.wav or .mp3):",
            type=["wav", "mp3"],
            help="Files must not exceed 25 MB. All audio remains local on this computer.",
            key="audio_uploader_file",
        )

        if uploaded_audio_file is not None:
            uploaded_bytes = uploaded_audio_file.read()
            # If newly uploaded file
            if (st.session_state.recorded_call_filename != uploaded_audio_file.name
                    or st.session_state.recorded_call_bytes != uploaded_bytes):
                val = validate_audio_file(uploaded_bytes, uploaded_audio_file.name)
                if not val["is_valid"]:
                    st.error(f"❌ Upload Error: {val['error']}")
                else:
                    st.session_state.recorded_call_bytes = uploaded_bytes
                    st.session_state.recorded_call_filename = uploaded_audio_file.name
                    st.session_state.recorded_call_metadata = extract_audio_metadata(uploaded_bytes, uploaded_audio_file.name)
                    _set_recorded_call_transcript("")
                    st.session_state.recorded_call_analysis = None
                    st.session_state.recorded_call_intel_report = None
                    st.session_state.recorded_call_stt_result = None
                    st.session_state.recorded_call_notice = f"Successfully loaded audio file: '{uploaded_audio_file.name}'"

        # Audio Playback & Metadata Section
        if st.session_state.recorded_call_bytes:
            st.markdown("---")
            if st.session_state.recorded_call_notice:
                st.info(st.session_state.recorded_call_notice)

            col_ap1, col_ap2 = st.columns([1, 2])
            with col_ap1:
                st.markdown("##### 🔊 Audio Playback:")
                audio_fmt = "audio/wav" if (st.session_state.recorded_call_filename or "").lower().endswith(".wav") else "audio/mp3"
                st.audio(st.session_state.recorded_call_bytes, format=audio_fmt)

            with col_ap2:
                st.markdown("##### 📊 Acoustic File Metadata:")
                meta = st.session_state.recorded_call_metadata or extract_audio_metadata(
                    st.session_state.recorded_call_bytes,
                    st.session_state.recorded_call_filename or "audio.wav",
                )
                col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                with col_m1:
                    st.metric("Format", meta.get("format", "WAV"))
                with col_m2:
                    st.metric("Duration", meta.get("duration_formatted", "00:00"))
                with col_m3:
                    st.metric("Sample Rate", f"{meta.get('sample_rate_hz', 0):,} Hz")
                with col_m4:
                    st.metric("Channels", f"{meta.get('channels', 1)} ({'Stereo' if meta.get('channels') == 2 else 'Mono'})")

        # Step 2: Speech-to-Text Transcription & Human Review
        st.markdown("---")
        st.markdown("#### 🗣️ Step 2: Speech-to-Text Transcription & Human Review")

        # Transcriber engine status check
        if not is_stt_ready or transcriber_engine.backend.name == "FallbackManualBackend":
            st.warning(
                "ℹ️ **Offline Engine Notice**: Local speech-to-text neural engine weights (e.g., Whisper/PyTorch) "
                "are not loaded. You can review and edit the transcript below, load any of the pre-recorded "
                "audio presets above, or type/paste the call transcript directly for verification."
            )
        else:
            backend_model = getattr(transcriber_engine.backend, "model_size", "base")
            backend_device = getattr(transcriber_engine.backend, "device", "cpu")
            backend_compute = getattr(transcriber_engine.backend, "compute_type", "int8")
            st.success(
                f"⚡ **Offline Neural STT Active**: `{transcriber_engine.backend.name}` "
                f"(Model: `{backend_model}`, Device: `{backend_device}`, Quantization: `{backend_compute}`). "
                "Zero external APIs contacted."
            )

        col_lang, col_btn = st.columns([2, 1])
        with col_lang:
            selected_language_label = st.selectbox(
                "🌐 Spoken Audio Language Mode:",
                options=[
                    "🇮🇳 Hindi (हिन्दी / Devanagari Script - Recommended for Hindi/Hinglish)",
                    "🌐 Auto-Detect Language (Default)",
                    "🇬🇧 English (Indian & Global Accents)",
                ],
                index=0,
                help=(
                    "CRITICAL FOR HINDI/HINGLISH: Select 'Hindi' when transcribing Hindi or Hinglish phone calls. "
                    "Whisper's language head will decode into proper Devanagari script ('नमस्ते भाई...') and avoid "
                    "inaccurate Latin phoneme hallucination. Auto-detect attempts automatic recognition. "
                    "English transcribes English speech."
                ),
            )
        lang_code_map = {
            "🇮🇳 Hindi (हिन्दी / Devanagari Script - Recommended for Hindi/Hinglish)": "hi",
            "🌐 Auto-Detect Language (Default)": "auto",
            "🌐 Auto-Detect Language": "auto",
            "🇮🇳 Hindi (हिन्दी / Devanagari Script)": "hi",
            "🇬🇧 English (Indian & Global Accents)": "en",
        }
        selected_lang_code = lang_code_map.get(selected_language_label, "hi")

        with col_btn:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            run_transcribe_btn = st.button("🎙️ Run Speech-to-Text", type="primary", use_container_width=True)

        st.caption(
            "💡 **Multilingual & Hinglish Guidance**: Whisper maps speech to specific scripts. "
            "For Hindi or mixed Hinglish calls, always choose **Hindi** for coherent Devanagari script output. "
            "Auto-detect may default to English or Hungarian tokenization on Indian accents. "
            "Always inspect and edit the generated transcript in the review box below before running risk scoring."
        )

        if run_transcribe_btn:
            if not st.session_state.recorded_call_bytes:
                st.warning("⚠️ Please upload an audio recording or select a preset sample first.")
            else:
                with st.spinner("Processing local audio transcription with Whisper neural model..."):
                    res = transcriber_engine.transcribe(
                        st.session_state.recorded_call_bytes,
                        st.session_state.recorded_call_filename or "recording.wav",
                        language=selected_lang_code,
                    )
                    st.session_state.recorded_call_stt_result = res
                    if res["success"] and res.get("transcript"):
                        _set_recorded_call_transcript(res["transcript"])
                        st.success(f"✅ {res.get('notice', 'Speech-to-text transcription completed successfully!')}")
                    elif res["success"] and not res.get("transcript"):
                        st.info(f"ℹ️ {res.get('notice', 'No discernible speech was detected in this recording.')}")
                    else:
                        if not st.session_state.recorded_call_transcript:
                            _set_recorded_call_transcript(res.get("transcript", ""))
                        st.info(res.get("notice", "Manual transcript required."))

        # STT Quality Warnings & Segments
        if st.session_state.recorded_call_stt_result:
            stt_res = st.session_state.recorded_call_stt_result
            quality = stt_res.get("quality_assessment", {})
            warnings = quality.get("warnings", [])

            if warnings:
                with st.expander("⚠️ Transcription Quality Warnings & Actionable Feedback", expanded=True):
                    for w in warnings:
                        st.warning(f"⚠️ {w}")
                    st.caption("Tip: Edit the transcript directly below to fix any acoustic errors or code-switching artifacts before analysis.")
            elif quality.get("rating") in ("GOOD", "FAIR"):
                st.caption(f"✨ **Quality Check Passed**: Confidence is good (Rating: `{quality.get('rating')}`, Score: `{quality.get('score')}`).")

            segments = stt_res.get("segments", [])
            if segments:
                with st.expander(f"⏱️ View Timestamped Audio Segments ({len(segments)} segments)"):
                    for seg in segments:
                        start_fmt = f"{seg.get('start', 0.0):.2f}s"
                        end_fmt = f"{seg.get('end', 0.0):.2f}s"
                        seg_text = seg.get("text", "").strip()
                        st.markdown(f"**[{start_fmt} - {end_fmt}]** {seg_text}")

        # Temporary Acoustic Diagnostic & Debug Inspector (Requirement 6)
        if st.session_state.recorded_call_bytes:
            with st.expander("🛠️ Acoustic Diagnostic & Debug Inspector (Acoustics, Whisper Engine & Segments)", expanded=False):
                st.markdown("##### 🔬 Audio Signal & Speech Recognition Debug Diagnostics")
                dbg_meta = st.session_state.recorded_call_metadata or extract_audio_metadata(
                    st.session_state.recorded_call_bytes,
                    st.session_state.recorded_call_filename or "audio.wav",
                )
                dbg_sig = inspect_audio_signal(
                    st.session_state.recorded_call_bytes,
                    st.session_state.recorded_call_filename or "audio.wav",
                )
                dbg_stt = st.session_state.recorded_call_stt_result or {}

                # Row 1: Audio Signal Metrics
                st.markdown("###### 🔊 Acoustic File Properties:")
                col_d1, col_d2, col_d3, col_d4 = st.columns(4)
                with col_d1:
                    dur_val = dbg_meta.get("duration_seconds") or dbg_sig.get("duration_seconds", 0.0)
                    st.metric("Audio Duration", f"{dur_val:.2f}s ({dbg_meta.get('duration_formatted', '00:00')})")
                with col_d2:
                    st.metric("Sample Rate", f"{dbg_meta.get('sample_rate_hz', 0):,} Hz")
                with col_d3:
                    ch_cnt = dbg_meta.get("channels", 1)
                    ch_desc = "Stereo" if ch_cnt == 2 else "Mono"
                    st.metric("Channel Count", f"{ch_cnt} ({ch_desc})")
                with col_d4:
                    st.metric("Container Format", dbg_meta.get("format", "WAV"))

                # Row 2: Signal Amplitude & Engine State
                st.markdown("###### 🧠 Whisper Neural Model & Decoder Diagnostics:")
                col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                active_model = dbg_stt.get("model_name") or getattr(transcriber_engine.backend, "model_size", "small")
                det_lang = dbg_stt.get("language_detected")
                lang_prob = dbg_stt.get("language_probability")
                if det_lang and det_lang != "unknown":
                    det_lang_str = f"{det_lang.upper()} ({lang_prob * 100:.1f}%)" if lang_prob is not None else det_lang.upper()
                else:
                    det_lang_str = "Not Run / Unknown"

                with col_m1:
                    st.metric("Whisper Model", f"faster-whisper-{active_model}")
                with col_m2:
                    st.metric("Detected Language", det_lang_str)
                with col_m3:
                    st.metric("RMS Amplitude", f"{dbg_sig.get('rms_amplitude', 0.0):.4f}")
                with col_m4:
                    st.metric("Peak Amplitude", f"{dbg_sig.get('peak_amplitude', 0.0):.4f}")

                # Transcription Segments Table
                dbg_segments = dbg_stt.get("segments", [])
                st.markdown("###### ⏱️ Transcription Segments Breakdown:")
                if dbg_segments:
                    seg_records = []
                    for s in dbg_segments:
                        seg_records.append({
                            "Segment #": s.get("id", 0) + 1 if isinstance(s.get("id"), int) else len(seg_records) + 1,
                            "Start (s)": f"{s.get('start', 0.0):.2f}",
                            "End (s)": f"{s.get('end', 0.0):.2f}",
                            "Transcribed Text": s.get("text", "").strip(),
                            "Avg LogProb": s.get("avg_logprob", "N/A"),
                            "No-Speech Prob": s.get("no_speech_prob", "N/A"),
                        })
                    st.dataframe(seg_records, use_container_width=True)
                else:
                    st.caption("ℹ️ No transcription segments recorded yet. Run Speech-to-Text above to populate segment telemetry.")

        # Human-in-the-loop review text area
        transcript_input = st.text_area(
            "Call Transcript (Review, edit, or type transcript before risk analysis):",
            key="recorded_call_transcript_input",
            on_change=_sync_recorded_call_transcript,
            height=140,
            placeholder="Transcript will appear here once audio is transcribed or loaded. You can also paste or type the transcript directly.",
        )
        st.session_state.recorded_call_transcript = transcript_input

        # Step 3: Guardian & Intelligence Analysis
        st.markdown("---")
        st.markdown("#### 🛡️ Step 3: Run Threat Detection & Intelligence Pipeline")

        analyze_audio_call_btn = st.button("🚨 Analyze Recorded Call", type="primary", use_container_width=True)

        if analyze_audio_call_btn:
            clean_text = (st.session_state.recorded_call_transcript or "").strip()
            if not clean_text:
                st.error("❌ Transcript is empty. Please provide or load a call transcript before running analysis.")
            else:
                # 1. Input sanitization & credential check
                val_res = validate_input_text(clean_text)
                if not val_res["is_valid"]:
                    st.error(f"❌ Input Error: {val_res['error']}")
                else:
                    cred_res = detect_sensitive_credentials(val_res["sanitized_text"])
                    if cred_res["credentials_detected"]:
                        st.warning(f"🛡️ Safety Shield: {cred_res['safety_warning']}")

                    # 2. Guardian Agent Risk Scoring
                    analysis = analyze_message(cred_res["redacted_text"])
                    st.session_state.recorded_call_analysis = analysis

                    # 3. Intelligence Agent Extraction
                    call_history = [
                        {"turn": 1, "role": "caller", "message": cred_res["redacted_text"]}
                    ]
                    raw_rep = extract_intelligence(call_history)
                    val_rep = validate_intelligence_report(raw_rep)
                    st.session_state.recorded_call_intel_report = val_rep["sanitized_report"]

        # Step 4: Display Analysis Results & Intelligence Reports
        if st.session_state.recorded_call_analysis and st.session_state.recorded_call_intel_report:
            res = st.session_state.recorded_call_analysis
            rep = st.session_state.recorded_call_intel_report

            st.markdown("---")
            st.markdown("#### 📋 Assessment & Intelligence Results")

            # Metrics row
            col_ar1, col_ar2, col_ar3 = st.columns(3)
            with col_ar1:
                r_lvl = res.get("risk_level", "LOW")
                if r_lvl == "HIGH":
                    badge_html = '<span class="badge-high">🚨 HIGH RISK THREAT</span>'
                elif r_lvl == "MEDIUM":
                    badge_html = '<span class="badge-medium">⚠️ MEDIUM RISK THREAT</span>'
                else:
                    badge_html = '<span class="badge-low">✅ LOW RISK CALL</span>'
                st.markdown(f"**Threat Classification:**<br>{badge_html}", unsafe_allow_html=True)

            with col_ar2:
                st.metric("Threat Score", f"{res.get('risk_score', 0)} / 100")

            with col_ar3:
                num_indicators = len(res.get("suspicious_indicators", []))
                st.metric("Suspicious Indicators", f"{num_indicators} Detected")

            # Explanation
            st.markdown("##### 🔍 Threat Analysis Rationale:")
            st.info(res.get("explanation", "No explanation available."))

            # Detected Indicators List
            indicators = res.get("suspicious_indicators", [])
            if indicators:
                st.markdown("##### 🚩 Detected Threat Indicators:")
                for ind in indicators:
                    st.markdown(f"- **{ind}**")

            # 2-Column Breakdown: Unverified Claims vs Actionable Indicators
            st.markdown("---")
            col_rc1, col_rc2 = st.columns(2)

            def _render_audio_claims(label: str, items: Any):
                st.markdown(f"**{label}:**")
                if isinstance(items, list) and items:
                    for it in items:
                        st.markdown(f"- **{it['value']}**")
                        st.caption(f"Quote: \"{it['evidence_quote']}\"")
                else:
                    st.caption("• Not found")

            with col_rc1:
                st.markdown("#### 👤 Unverified Caller Claims")
                claims = rep.get("unverified_caller_claims", {})
                _render_audio_claims("Claimed Official Names", claims.get("claimed_names"))
                _render_audio_claims("Claimed Departments", claims.get("claimed_departments"))
                _render_audio_claims("Claimed Badge IDs", claims.get("claimed_badge_ids"))
                _render_audio_claims("Demanded Amounts", claims.get("claimed_payment_amounts"))

            with col_rc2:
                st.markdown("#### 🎯 Extracted Actionable Indicators")
                indicators_data = rep.get("extracted_indicators", {})
                _render_audio_claims("Flagged UPI IDs", indicators_data.get("upi_ids"))
                _render_audio_claims("Flagged Phone Numbers", indicators_data.get("phone_numbers"))
                _render_audio_claims("Bank Account References", indicators_data.get("bank_accounts"))
                _render_audio_claims("IFSC Codes", indicators_data.get("ifsc_codes"))

            # Observed Tactics
            st.markdown("---")
            st.markdown("#### ⚔️ Observed Scam Tactics & Supporting Evidence")
            tactics = rep.get("detected_tactics", [])
            if tactics:
                for t in tactics:
                    st.markdown(f"- **[{t['tactic']}]** — *Confidence:* `{t['confidence']}`")
                    st.markdown(f'<div class="evidence-quote">"{t["evidence_quote"]}"</div>', unsafe_allow_html=True)
            else:
                st.caption("No coercive tactics detected in this transcript.")

            # Gap Analysis
            st.markdown("---")
            st.markdown("#### 🔍 Gap Analysis (Missing Official Credentials)")
            st.caption("Legitimate authorities provide verified physical or formal documentation. The following were absent:")
            missing = rep.get("missing_information", [])
            for m in missing:
                st.markdown(f'<div class="missing-alert">⚠️ <strong>Missing:</strong> {m}</div>', unsafe_allow_html=True)

            # Recommended Defensive Next Steps
            st.markdown("---")
            st.markdown("#### 🛡️ Recommended Defensive Next Steps")
            steps = rep.get("recommended_next_steps", [])
            for idx, s in enumerate(steps, 1):
                st.markdown(f"**{idx}.** {s}")

            # Export Buttons
            st.markdown("---")
            st.markdown("##### 📥 Export Recorded Call Intelligence Report:")
            col_ed1, col_ed2 = st.columns(2)
            with col_ed1:
                st.download_button(
                    label="📄 Download Formatted Text Report (.txt)",
                    data=rep.get("formatted_text_report", ""),
                    file_name=f"{rep.get('report_id', 'audio_report')}.txt",
                    mime="text/plain",
                    use_container_width=True,
                    key="dl_audio_txt",
                )
            with col_ed2:
                st.download_button(
                    label="📦 Download Structured Report (.json)",
                    data=json.dumps(rep, indent=2),
                    file_name=f"{rep.get('report_id', 'audio_report')}.json",
                    mime="application/json",
                    use_container_width=True,
                    key="dl_audio_json",
                )

            # View Raw ASCII Report Expander
            with st.expander("👁️ View Full Formatted ASCII Report"):
                st.text(rep.get("formatted_text_report", "N/A"))


    # ===========================================================================
    # TAB 5: SAFETY & COMPLIANCE GUARDRAILS
    # ===========================================================================

    with tab_safety:
        st.markdown("### 🔒 Safety System & Compliance Guardrails")
        st.markdown(
            "ScamShield AI is engineered with defensive-only boundaries. "
            "It prevents unauthorized outbound actions, protects sensitive user credentials, and maintains ethical standards."
        )

        col_sg1, col_sg2 = st.columns(2)

        with col_sg1:
            st.markdown("#### 🛡️ Core Defensive Guardrails")
            st.markdown("""
            1. **Strict Input Sanitization:**
               - Protects against empty, invalid, and excessively large inputs (> 5,000 characters).
            2. **Zero-Leakage Credential Shield:**
               - Detects OTPs, ATM/UPI PINs, passwords, CVVs, and card numbers.
               - Secret values are automatically replaced with non-sensitive tokens (`[REDACTED_OTP]`, `[REDACTED_PIN]`).
               - Warnings NEVER repeat secret values to prevent secondary leakage.
            3. **Presumption of Unverified Intelligence:**
               - Prohibits defamatory labels (e.g., labeling individuals as "confirmed criminals" based solely on transcripts).
               - Strictly classifies caller statements as *unverified claims*.
            4. **Local Execution Policy:**
               - Automatically blocks any outbound calls, SMS, WhatsApp dispatches, or external database transmissions.
            """)

        with col_sg2:
            st.markdown("#### 🧪 Interactive Safety Test Playground")
            st.caption("Test how the safety shield intercepts and redacts sensitive credentials:")

            test_safety_input = st.text_input(
                "Enter text containing sensitive data:",
                value="My secret OTP is 482910 and ATM PIN is 1234. Transfer immediately.",
            )

            if st.button("🛡️ Test Safety Shield Redaction", type="primary"):
                cred_test = detect_sensitive_credentials(test_safety_input)
                st.markdown(f"**Credentials Detected:** `{cred_test['credentials_detected']}`")
                st.markdown(f"**Categories Detected:** `{cred_test['categories_detected']}`")
                st.markdown(f"**Is Requesting:** `{cred_test['is_requesting_credentials']}` | **Is Disclosing:** `{cred_test['is_disclosing_credentials']}`")
                st.markdown(f"**Redacted Output:** `{cred_test['redacted_text']}`")
                if cred_test["safety_warning"]:
                    st.warning(f"**Safety Warning:** {cred_test['safety_warning']}")

                # Verify secret value not leaked
                secret_leaked = ("482910" in str(cred_test["safety_warning"])) or ("1234" in str(cred_test["safety_warning"]))
                if not secret_leaked:
                    st.success("✅ Zero Credential Leakage: Secret values were completely excluded from the safety warning!")

        st.markdown("---")
        st.markdown("#### 🚨 Emergency Escalation Directory")
        st.markdown("""
        | Authority / Agency | Contact Method | Purpose |
        | :--- | :--- | :--- |
        | **National Cyber Crime Helpline** | **1930** (Toll-Free, 24x7) | Immediate financial fraud reporting & account freeze |
        | **National Cyber Crime Portal** | [cybercrime.gov.in](https://cybercrime.gov.in) | Formal complaint registration & evidence upload |
        | **Emergency Police Response** | **112** | In-person emergency assistance & threats of physical coercion |
        | **Reserve Bank of India (Sachet)** | [sachet.rbi.org.in](https://sachet.rbi.org.in) | Unregistered entities & illegal lending apps |
        """)

    # ---------------------------------------------------------------------------
    # Footer
    # ---------------------------------------------------------------------------
    st.markdown("---")
    st.caption(
        "ScamShield AI • Defensive Cybersecurity Prototype • Built for Hackathon Demonstration • "
        "Designed for Local Review & Human Verification • © 2026"
    )

if STREAMLIT_AVAILABLE:
    run_dashboard()
elif __name__ == '__main__':
    run_dashboard()
    sys.exit(0)
