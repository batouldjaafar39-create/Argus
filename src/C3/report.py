from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field


class FinalReport(BaseModel):
    """C3's required final investigation report structure."""

    model_config = ConfigDict(extra="ignore")  # tolerate harmless extra fields, don't invent new ones

    finding: str = Field(min_length=1)
    affected_entities: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    interpretation: str = Field(min_length=1)
    attack_technique_mapping: List[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    limitations: str = Field(min_length=1)
