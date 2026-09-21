"""Module 4: evidence-based access review with human-controlled remediation."""
from .domain import EngineConfig, Scan, Correlation, User, InputError
from .engine import evaluate

__all__ = ['EngineConfig', 'Scan', 'Correlation', 'User', 'InputError', 'evaluate']
