"""Domain exceptions."""


class ScannerError(RuntimeError):
    """Base scanner error."""


class ScopeValidationError(ValueError):
    """Target is malformed, unsafe, or outside the engagement scope."""


class ToolUnavailableError(ScannerError):
    """An optional external scanner is not installed."""


class CommandExecutionError(ScannerError):
    """A controlled scanner process failed."""


class ScanCancelled(ScannerError):
    """A running scan was cancelled by its operator."""
