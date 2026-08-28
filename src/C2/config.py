from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class C2Config:
    """Configuration for the C2 (LLM-only, no Zeek) baseline condition.

    Mirrors C3Config's model/backend/reproducibility fields exactly, per
    the experimental control in the research design (Section 7.12): "the
    same model and configuration are used for C2, C3, and C4." Only the
    tool/evidence-related fields (max_iterations' meaning, context
    truncation caps) are dropped, since C2 has no Zeek access at all.
    """

    # --- llama-cli invocation (used when use_server=False) ---
    llama_cli_path: str = "llama-cli"
    model_hf_repo: str = "Qwen/Qwen3-4B-GGUF:Q4_K_M"
    context_size: int = 8192
    threads: Optional[int] = None
    generation_timeout_s: int = 300

    # --- llama-server invocation (used when use_server=True, the default) ---
    use_server: bool = True
    llama_server_path: str = "llama-server"
    server_host: str = "127.0.0.1"
    server_port: int = 8090
    server_startup_timeout_s: int = 600
    server_health_poll_interval_s: float = 2.0
    keep_server_running: bool = True

    # --- generation parameters (fixed for reproducibility, matches C3) ---
    temperature: float = 0.0
    top_p: float = 0.9
    top_k: int = 40
    max_tokens: int = 1024
    seed: int = 42

    # --- safeguard 1: JSON retry wrapper (same semantics as C3) ---
    max_json_retries: int = 2

    # --- safeguard 2: report-correction rounds ---
    # C2 has no tools, so there is no "iteration" of evidence-gathering
    # turns the way C3/Argus have. This instead bounds how many times the
    # model may be asked to correct a final_report that fails schema
    # validation, or to retry after attempting an invalid action (e.g.
    # a hallucinated tool_call, which C2 must reject). Kept small since
    # each round is a full extra generation on a CPU-only 16GB machine.
    max_correction_rounds: int = 3

    # --- reproducibility ---
    log_dir: Path = Path("logs/c2")
