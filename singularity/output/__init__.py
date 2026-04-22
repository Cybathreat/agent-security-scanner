"""
Output/reporting modules for Singularity.

Provides JSON and Markdown report generation from scan results.
"""

from .json_report import JSONReport
from .markdown_report import MarkdownReport

__all__ = ["JSONReport", "MarkdownReport"]
