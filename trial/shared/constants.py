"""
Global constants shared between server and agent.
TODO: Define ports, protocol names, action types, severity levels.
"""

# Version
APP_VERSION = "1.0.0"

# Default ports
DEFAULT_SERVER_PORT = 5000

# Severity levels
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# IPS Actions
ACTION_IGNORE = "IGNORE"
ACTION_LOG = "LOG"
ACTION_DROP = "DROP"
ACTION_BLOCK = "BLOCK"
