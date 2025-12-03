from typing import Any, Dict, List, Optional, Set
from .utils import logger, sanitize_cve_id, get_severity_from_score


def merge_alert_with_enrichment(alert: Dict, enrichment: Optional[Dict]) -> Dict:
    merged = {
        **alert,
        "enriched": enrichment is not None,
        "bnvd_data": enrichment
    }
    
    if enrichment:
        if not merged.get("cvss_score"):
            merged["cvss_score"] = enrichment.get("cvss_score", 0.0)
        if not merged.get("cvss_severity") or merged.get("cvss_severity") == "unknown":
            merged["cvss_severity"] = enrichment.get("cvss_severity", "NONE")
        
        if not merged.get("description"):
            descriptions = enrichment.get("descriptions", [])
            descriptions_pt = enrichment.get("descriptions_pt", [])
            
            if descriptions_pt:
                merged["description_pt"] = descriptions_pt[0].get("value", "")
            if descriptions:
                merged["description_en"] = descriptions[0].get("value", "")
    
    return merged


def deduplicate_cves(cve_list: List[Dict]) -> List[Dict]:
    seen: Set[str] = set()
    unique_cves = []
    
    for cve in cve_list:
        cve_id = cve.get("cve_id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_cves.append(cve)
        elif cve_id in seen:
            for existing in unique_cves:
                if existing.get("cve_id") == cve_id:
                    sources = existing.get("sources", [existing.get("source")])
                    new_source = cve.get("source")
                    if new_source and new_source not in sources:
                        sources.append(new_source)
                    existing["sources"] = sources
                    break
    
    return unique_cves


def filter_by_severity(alerts: List[Dict], severity_filter: str) -> List[Dict]:
    if severity_filter == "ALL":
        return alerts
    
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "NONE": 0
    }
    
    filter_level = severity_order.get(severity_filter.upper(), 0)
    
    filtered = []
    for alert in alerts:
        severity = alert.get("cvss_severity") or alert.get("severity", "NONE")
        severity = severity.upper() if severity else "NONE"
        
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "NONE": "NONE"
        }
        normalized_severity = severity_map.get(severity, "NONE")
        
        if severity_order.get(normalized_severity, 0) >= filter_level:
            filtered.append(alert)
    
    return filtered


def sort_by_severity(alerts: List[Dict], descending: bool = True) -> List[Dict]:
    def get_score(alert: Dict) -> float:
        bnvd_data = alert.get("bnvd_data")
        if bnvd_data:
            return bnvd_data.get("cvss_score", 0.0)
        return alert.get("cvss_score", 0.0)
    
    return sorted(alerts, key=get_score, reverse=descending)


def count_by_severity(alerts: List[Dict]) -> Dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
        "unknown": 0
    }
    
    for alert in alerts:
        bnvd_data = alert.get("bnvd_data")
        if bnvd_data:
            score = bnvd_data.get("cvss_score", 0.0)
            severity = get_severity_from_score(score).lower()
        else:
            severity = alert.get("severity", "unknown")
            if severity:
                severity = severity.lower()
                if severity == "moderate":
                    severity = "medium"
            else:
                severity = "unknown"
        
        if severity in counts:
            counts[severity] += 1
        else:
            counts["unknown"] += 1
    
    return counts


def extract_all_cwes(alerts: List[Dict]) -> List[str]:
    cwes = set()
    
    for alert in alerts:
        bnvd_data = alert.get("bnvd_data")
        if bnvd_data:
            for weakness in bnvd_data.get("weaknesses", []):
                cwe_id = weakness.get("cwe_id")
                if cwe_id:
                    cwes.add(cwe_id)
        
        for cwe in alert.get("cwes", []):
            cwe_id = cwe.get("cwe_id") if isinstance(cwe, dict) else cwe
            if cwe_id:
                cwes.add(cwe_id)
    
    return sorted(list(cwes))


def extract_all_packages(alerts: List[Dict]) -> List[Dict]:
    packages = {}
    
    for alert in alerts:
        if alert.get("source") == "Dependabot":
            pkg_name = alert.get("package_name")
            pkg_ecosystem = alert.get("package_ecosystem")
            
            if pkg_name:
                key = f"{pkg_ecosystem}:{pkg_name}"
                if key not in packages:
                    packages[key] = {
                        "name": pkg_name,
                        "ecosystem": pkg_ecosystem,
                        "cves": [],
                        "count": 0
                    }
                packages[key]["cves"].append(alert.get("cve_id"))
                packages[key]["count"] += 1
    
    return sorted(packages.values(), key=lambda x: x["count"], reverse=True)


def generate_statistics(alerts: List[Dict]) -> Dict:
    severity_counts = count_by_severity(alerts)
    cwes = extract_all_cwes(alerts)
    packages = extract_all_packages(alerts)
    
    sources = {}
    for alert in alerts:
        source = alert.get("source", "Unknown")
        sources[source] = sources.get(source, 0) + 1
    
    enriched_count = sum(1 for a in alerts if a.get("enriched", False))
    
    total_score = 0.0
    scored_count = 0
    max_score = 0.0
    
    for alert in alerts:
        bnvd_data = alert.get("bnvd_data")
        if bnvd_data:
            score = bnvd_data.get("cvss_score", 0.0)
            if score > 0:
                total_score += score
                scored_count += 1
                max_score = max(max_score, score)
    
    avg_score = total_score / scored_count if scored_count > 0 else 0.0
    
    cisa_kev_count = sum(
        1 for a in alerts 
        if a.get("bnvd_data", {}).get("cisa_kev") is not None
    )
    
    return {
        "total_cves": len(alerts),
        "enriched_cves": enriched_count,
        "severity_counts": severity_counts,
        "by_source": sources,
        "unique_cwes": len(cwes),
        "cwes": cwes[:20],
        "affected_packages": len(packages),
        "top_packages": packages[:10],
        "average_cvss_score": round(avg_score, 2),
        "max_cvss_score": max_score,
        "cisa_kev_count": cisa_kev_count
    }
