from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class ArgusConfig:
    """Configuration for the Argus investigation condition.

    The model/backend and reproducibility defaults intentionally mirror C3.
    Argus-specific controls are limited to its workflow budgets.
    """

    llama_cli_path: str = "llama-cli"
    model_hf_repo: str = "Qwen/Qwen3-4B-GGUF:Q4_K_M"
    context_size: int = 8192
    threads: Optional[int] = None
    generation_timeout_s: int = 900

    use_server: bool = True
    llama_server_path: str = "llama-server"
    server_host: str = "127.0.0.1"
    server_port: int = 8090
    server_startup_timeout_s: int = 600
    server_health_poll_interval_s: float = 2.0
    keep_server_running: bool = True

    temperature: float = 0.0
    top_p: float = 0.9
    top_k: int = 40
    max_tokens: int = 1024
    seed: int = 42

    max_json_retries: int = 2
    max_planning_rounds: int = 2
    max_revisions: int = 2
    max_tool_calls_per_plan: int = 6

    context_max_records: int = 20
    context_max_chars: int = 6000
    prompt_max_chars: int = 12000
    log_dir: Path = Path("logs/argus")
