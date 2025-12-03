from .utils import logger, Timer, write_github_output
from .github_api import GitHubAPIClient
from .bnvd_api import BNVDAPIClient
from .parsers import (
    merge_alert_with_enrichment,
    deduplicate_cves,
    filter_by_severity,
    sort_by_severity,
    count_by_severity,
    generate_statistics
)
from .reporters import ReportGenerator, JSONReporter, MarkdownReporter

__all__ = [
    "logger",
    "Timer",
    "write_github_output",
    "GitHubAPIClient",
    "BNVDAPIClient",
    "merge_alert_with_enrichment",
    "deduplicate_cves",
    "filter_by_severity",
    "sort_by_severity",
    "count_by_severity",
    "generate_statistics",
    "ReportGenerator",
    "JSONReporter",
    "MarkdownReporter"
]

__version__ = "1.0.0"
