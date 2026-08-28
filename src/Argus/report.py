from typing import List, Literal
from pydantic import BaseModel, ConfigDict, Field


class ArgusReport(BaseModel):
    """Argus final report; its evidence field contains Ledger IDs."""

    model_config = ConfigDict(extra="ignore")

    finding: str = Field(min_length=1)
    affected_entities: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    interpretation: str = Field(min_length=1)
    attack_technique_mapping: List[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    limitations: str = Field(min_length=1)
