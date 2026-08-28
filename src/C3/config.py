from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class C3Config:
    # ------------------------------------------------------------------
    # LLM backend
    # ------------------------------------------------------------------

    llama_cli_path: str = "llama-cli"
    model_hf_repo: str = "Qwen/Qwen3-4B-GGUF:Q4_K_M"

    context_size: int = 8192
    threads: Optional[int] = None

    # 300 seconds was unnecessarily expensive for a single malformed
    # response. Keep a generous limit, but JSON retries are handled
    # separately and do not replay the malformed response.
    generation_timeout_s: int = 300

    # ------------------------------------------------------------------
    # llama-server
    # ------------------------------------------------------------------

    use_server: bool = True
    llama_server_path: str = "llama-server"

    server_host: str = "127.0.0.1"
    server_port: int = 8090

    server_startup_timeout_s: int = 600
    server_health_poll_interval_s: float = 2.0

    keep_server_running: bool = True

    # ------------------------------------------------------------------
    # Reproducible generation
    # ------------------------------------------------------------------

    temperature: float = 0.0
    top_p: float = 0.9
    top_k: int = 40

    # Keep this relatively small because C3 only needs to produce:
    #
    #   tool_call
    # or
    #   final_report
    #
    # A 4B model should not need hundreds of tokens of reasoning.
    max_tokens: int = 512

    seed: int = 42

    # ------------------------------------------------------------------
    # JSON safety
    # ------------------------------------------------------------------

    # 1 initial attempt + 2 retries = 3 total attempts.
    max_json_retries: int = 2

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

    max_iterations: int = 3

    # ------------------------------------------------------------------
    # Evidence context
    # ------------------------------------------------------------------

    context_max_records: int = 20
    context_max_chars: int = 6000

    conversation_max_chars: int = 16000

    # ------------------------------------------------------------------
    # Alert investigation window
    # ------------------------------------------------------------------

    # C3 is allowed to investigate activity occurring after the alert.
    #
    # Example:
    #
    # alert:
    #   2020-04-30T00:06:38Z
    #
    # investigation:
    #   00:06:38 -> 01:06:38
    #
    # This prevents the model from inventing arbitrary timestamps while
    # still allowing it to find activity that occurred after the alert.
    investigation_window_seconds: int = 3600

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    log_dir: Path = Path("logs/c3")