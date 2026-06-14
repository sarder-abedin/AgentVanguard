"""Shared enums used across the engine, policy, guards, and integrations."""

from enum import Enum


class ProvenanceLabel(str, Enum):
    """Trust label attached to every piece of content flowing through the engine."""

    USER = "user"
    SYSTEM = "system"
    ASSISTANT = "assistant"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_DOC = "retrieved_doc"
    SUB_AGENT = "sub_agent"


class ActionType(str, Enum):
    """What kind of operation a tool performs."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    SEND_EXTERNAL = "send_external"
    DELETE = "delete"
    FINANCIAL = "financial"


class SideEffect(str, Enum):
    """The real-world consequence of a tool call."""

    NONE = "none"
    INTERNAL_READ = "internal_read"
    INTERNAL_WRITE = "internal_write"
    EXTERNAL_COMMUNICATION = "external_communication"
    FINANCIAL_TRANSACTION = "financial_transaction"
    IRREVERSIBLE_CHANGE = "irreversible_change"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    """The outcome of evaluating a `PolicyInput`."""

    ALLOW = "ALLOW"
    ALLOW_WITH_MODIFICATIONS = "ALLOW_WITH_MODIFICATIONS"
    REQUIRE_USER_CONFIRMATION = "REQUIRE_USER_CONFIRMATION"
    DENY = "DENY"


class FindingType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    PII = "pii"
    SECRET = "secret"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    EGRESS_DENIED = "egress_denied"
    SCHEMA_VIOLATION = "schema_violation"
    EXFIL_PATTERN = "exfil_pattern"
    BUDGET_EXCEEDED = "budget_exceeded"
    REPETITION_LOOP = "repetition_loop"
    UNKNOWN_TOOL = "unknown_tool"
    CALLER_NOT_ALLOWED = "caller_not_allowed"
    COMMAND_INJECTION = "command_injection"


class GuardStage(str, Enum):
    INPUT = "input_guard"
    TOOL_CALL = "tool_call_guard"
    OUTPUT = "output_guard"
    SESSION = "session_guard"
    POLICY = "policy"


class ActionKind(str, Enum):
    """The `action` field of a `PolicyInput` — what is being authorized."""

    INGRESS = "ingress"
    MODEL_REQUEST = "model_request"
    TOOL_CALL = "tool_call"
    OUTPUT = "output"
