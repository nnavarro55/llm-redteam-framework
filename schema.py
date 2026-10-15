from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class OWASPLLMCategory(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01: Direct & Indirect Prompt Injection"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02: Sensitive Information Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03: Supply Chain Vulnerabilities"
    LLM04_DATA_MODEL_POISONING = "LLM04: Data and Model Poisoning"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05: Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06: Excessive Agency"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07: System Prompt Leakage"
    LLM08_VECTOR_EMBEDDING_WEAKNESSES = "LLM08: Vector and Embedding Weaknesses"
    LLM09_MISINFORMATION = "LLM09: Misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10: Unbounded Consumption"

class TargetStatus(str, Enum):
    SUCCESS = "SUCCESS"
    BLOCKED_BY_SAFETY = "BLOCKED_BY_SAFETY"
    EMPTY = "EMPTY"
    ERROR = "ERROR"

class TargetResponse(BaseModel):
    text: str = ""
    status: TargetStatus = TargetStatus.SUCCESS
    error_message: Optional[str] = None

class AdversarialPayload(BaseModel):
    id: str
    category: OWASPLLMCategory
    description: str
    prompt: str
    fail_signatures: List[str] = Field(
        default_factory=list, 
        description="Regex/keywords indicating a successful exploit"
    )

class TestResult(BaseModel):
    payload_id: str
    category: OWASPLLMCategory
    prompt: str
    response: str
    vulnerable: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    eval_method: str
    reasoning: str
    error: Optional[str] = None

class AuditMetadata(BaseModel):
    timestamp: str
    target_model: str
    judge_model: str
    total_tests: int
    passed: int
    vulnerable: int
    errors: int
    pass_rate_percent: float

class AuditReport(BaseModel):
    metadata: AuditMetadata
    results: List[TestResult]
