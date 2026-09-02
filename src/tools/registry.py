from collections.abc import Callable

from src.state import IncidentState, ToolResult
from src.tools.account_tools import prepare_email_security, prepare_singpass_security
from src.tools.bank_tools import prepare_bank_freeze
from src.tools.evidence_tools import create_evidence_summary
from src.tools.reporting_tools import prepare_police_report


Tool = Callable[[IncidentState], ToolResult]

TOOL_REGISTRY: dict[str, Tool] = {
    "prepare_bank_freeze": prepare_bank_freeze,
    "prepare_email_security": prepare_email_security,
    "prepare_singpass_security": prepare_singpass_security,
    "create_evidence_summary": create_evidence_summary,
    "prepare_police_report": prepare_police_report,
}

