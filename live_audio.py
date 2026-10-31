"""Local microphone audio buffering for live call transcription."""

import io
import threading
import wave
from typing import Any, Optional


LIVE_SAMPLE_RATE = 16000
LIVE_CHUNK_SECONDS = 6
LIVE_MAX_BUFFER_SECONDS = 120


def pcm16_mono_to_wav(pcm_bytes: bytes, sample_rate: int = LIVE_SAMPLE_RATE) -> bytes:
    """Wrap mono 16-bit PCM samples in an in-memory WAV container."""
    if not pcm_bytes or len(pcm_bytes) % 2:
        raise ValueError("PCM audio must contain a non-empty, even number of bytes.")

    output = io.BytesIO()
    with wave.open(output, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(pcm_bytes)
    return output.getvalue()


class LiveAudioBuffer:
    """Thread-safe resampling buffer that yields fixed-duration PCM chunks."""

    def __init__(
        self,
        chunk_seconds: int = LIVE_CHUNK_SECONDS,
        max_buffer_seconds: int = LIVE_MAX_BUFFER_SECONDS,
        sample_rate: int = LIVE_SAMPLE_RATE,
        resampler: Optional[Any] = None,
    ):
        if chunk_seconds <= 0 or max_buffer_seconds < chunk_seconds or sample_rate <= 0:
            raise ValueError("Audio buffer durations and sample rate must be positive and consistent.")

        if resampler is None:
            from av.audio.resampler import AudioResampler

            resampler = AudioResampler(format="s16", layout="mono", rate=sample_rate)

        self._resampler = resampler
        self.sample_rate = sample_rate
        self.chunk_bytes = chunk_seconds * sample_rate * 2
        self.max_buffer_bytes = max_buffer_seconds * sample_rate * 2
        self._pcm_bytes = bytearray()
        self._error = None
        self._lock = threading.Lock()

    def audio_frame_callback(self, frame: Any) -> Any:
        """Resample incoming browser audio while passing it through unchanged."""
        try:
            for resampled_frame in self._resampler.resample(frame):
                self.append_pcm_bytes(resampled_frame.to_ndarray().tobytes())
        except Exception as exc:
            with self._lock:
                self._error = f"Live microphone audio processing failed: {exc}"
        return frame

    def append_pcm_bytes(self, pcm_bytes: bytes) -> None:
        if len(pcm_bytes) % 2:
            raise ValueError("PCM audio must contain an even number of bytes.")
        with self._lock:
            if self._error:
                return
            if len(self._pcm_bytes) + len(pcm_bytes) > self.max_buffer_bytes:
                self._error = (
                    "Live audio buffer is full. Stop monitoring and restart it before continuing."
                )
                return
            self._pcm_bytes.extend(pcm_bytes)

    def take_chunk(self, final: bool = False) -> Optional[bytes]:
        """Return a complete chunk, or a final speech-length remainder after stopping."""
        with self._lock:
            min_final_bytes = int(1.5 * self.sample_rate * 2)
            minimum_bytes = min_final_bytes if final else self.chunk_bytes
            if len(self._pcm_bytes) < minimum_bytes:
                return None
            chunk_size = min(len(self._pcm_bytes), self.chunk_bytes)
            chunk = bytes(self._pcm_bytes[:chunk_size])
            del self._pcm_bytes[:chunk_size]
            return chunk

    def discard_pending_audio(self) -> None:
        with self._lock:
            self._pcm_bytes.clear()

    @property
    def buffered_seconds(self) -> float:
        with self._lock:
            return len(self._pcm_bytes) / (self.sample_rate * 2)

    @property
    def error(self) -> Optional[str]:
        with self._lock:
            return self._error
