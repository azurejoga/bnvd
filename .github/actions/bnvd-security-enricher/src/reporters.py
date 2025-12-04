import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .utils import (
    logger, 
    get_severity_emoji, 
    get_severity_badge,
    format_timestamp
)
from .parsers import generate_statistics, sort_by_severity


class JSONReporter:
    
    def __init__(self, repo_name: str):
        self.repo_name = repo_name
    
    def generate(self, alerts: List[Dict], statistics: Optional[Dict] = None) -> Dict:
        if statistics is None:
            statistics = generate_statistics(alerts)
        
        report = {
            "metadata": {
                "report_type": "BNVD Security Enrichment Report",
                "version": "1.0.0",
                "generated_at": format_timestamp(),
                "repository": self.repo_name,
                "generator": "BNVD Security Enricher Action"
            },
            "summary": {
                "total_vulnerabilities": statistics["total_cves"],
                "enriched_vulnerabilities": statistics["enriched_cves"],
                "by_severity": statistics["severity_counts"],
                "by_source": statistics["by_source"],
                "average_cvss_score": statistics["average_cvss_score"],
                "max_cvss_score": statistics["max_cvss_score"],
                "cisa_kev_count": statistics["cisa_kev_count"],
                "unique_cwes": statistics["unique_cwes"],
                "affected_packages": statistics["affected_packages"]
            },
            "vulnerabilities": sort_by_severity(alerts),
            "analysis": {
                "top_cwes": statistics["cwes"],
                "top_affected_packages": statistics["top_packages"]
            }
        }
        
        return report
    
    def save(self, report: Dict, filepath: str) -> str:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Relatório JSON salvo em: {filepath}")
        return filepath


class MarkdownReporter:
    
    def __init__(self, repo_name: str):
        self.repo_name = repo_name
    
    def generate(self, alerts: List[Dict], statistics: Optional[Dict] = None, cwe_only_alerts: Optional[List[Dict]] = None) -> str:
        if statistics is None:
            statistics = generate_statistics(alerts)
        
        sorted_alerts = sort_by_severity(alerts)
        
        lines = []
        
        lines.append(f"# Relatório de Segurança BNVD")
        lines.append(f"## Repositório: {self.repo_name}")
        lines.append("")
        lines.append(f"**Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        lines.append("---")
        lines.append("")
        lines.append("## Resumo Executivo")
        lines.append("")
        
        severity_counts = statistics["severity_counts"]
        lines.append("| Severidade | Quantidade |")
        lines.append("|:-----------|:----------:|")
        lines.append(f"| {get_severity_emoji('CRITICAL')} **Crítica** | {severity_counts.get('critical', 0)} |")
        lines.append(f"| {get_severity_emoji('HIGH')} **Alta** | {severity_counts.get('high', 0)} |")
        lines.append(f"| {get_severity_emoji('MEDIUM')} **Média** | {severity_counts.get('medium', 0)} |")
        lines.append(f"| {get_severity_emoji('LOW')} **Baixa** | {severity_counts.get('low', 0)} |")
        lines.append(f"| **Total** | **{statistics['total_cves']}** |")
        lines.append("")
        
        lines.append("### Estatísticas")
        lines.append("")
        lines.append(f"- **CVEs Enriquecidos:** {statistics['enriched_cves']}/{statistics['total_cves']}")
        lines.append(f"- **Score CVSS Médio:** {statistics['average_cvss_score']}/10.0")
        lines.append(f"- **Score CVSS Máximo:** {statistics['max_cvss_score']}/10.0")
        lines.append(f"- **CVEs no CISA KEV:** {statistics['cisa_kev_count']}")
        lines.append(f"- **CWEs Únicos:** {statistics['unique_cwes']}")
        lines.append(f"- **Pacotes Afetados:** {statistics['affected_packages']}")
        lines.append("")
        
        lines.append("### Por Fonte")
        lines.append("")
        for source, count in statistics["by_source"].items():
            lines.append(f"- **{source}:** {count} alertas")
        lines.append("")
        
        if statistics["cwes"]:
            lines.append("### Top CWEs")
            lines.append("")
            for cwe in statistics["cwes"][:10]:
                lines.append(f"- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)")
            lines.append("")
        
        lines.append("---")
        lines.append("")
        lines.append("## Detalhes das Vulnerabilidades")
        lines.append("")
        
        if not sorted_alerts:
            lines.append("*Nenhuma vulnerabilidade encontrada ou que corresponda aos filtros aplicados.*")
            lines.append("")
        else:
            for i, alert in enumerate(sorted_alerts, 1):
                cve_id = alert.get("cve_id", "N/A")
                bnvd_data = alert.get("bnvd_data")
                source = alert.get("source", "Unknown")
                alert_url = alert.get("alert_url", "#")
                
                if bnvd_data:
                    score = bnvd_data.get("cvss_score", 0.0)
                    severity = bnvd_data.get("cvss_severity", "NONE")
                else:
                    score = alert.get("cvss_score", 0.0)
                    severity = alert.get("severity", "unknown").upper()
                
                emoji = get_severity_emoji(severity)
                
                lines.append(f"### {i}. {emoji} {cve_id}")
                lines.append("")
                
                lines.append(f"| Campo | Valor |")
                lines.append(f"|:------|:------|")
                lines.append(f"| **Fonte** | {source} |")
                lines.append(f"| **Severidade** | {severity} |")
                lines.append(f"| **CVSS Score** | {score}/10.0 |")
                
                if bnvd_data:
                    if bnvd_data.get("cvss_vector"):
                        lines.append(f"| **CVSS Vector** | `{bnvd_data['cvss_vector']}` |")
                    if bnvd_data.get("published"):
                        lines.append(f"| **Publicado** | {bnvd_data['published'][:10]} |")
                    if bnvd_data.get("last_modified"):
                        lines.append(f"| **Última Atualização** | {bnvd_data['last_modified'][:10]} |")
                    if bnvd_data.get("vuln_status"):
                        lines.append(f"| **Status** | {bnvd_data['vuln_status']} |")
                    if bnvd_data.get("data_source"):
                        lines.append(f"| **Fonte de Dados** | {bnvd_data['data_source']} |")
                
                lines.append(f"| **Link GitHub** | [Ver Alerta]({alert_url}) |")
                lines.append(f"| **Link BNVD** | [Ver no BNVD](https://bnvd.org/vulnerabilidade/{cve_id}) |")
                lines.append("")
                
                if bnvd_data:
                    descriptions_pt = bnvd_data.get("descriptions_pt", [])
                    descriptions_en = bnvd_data.get("descriptions", [])
                    
                    if descriptions_pt:
                        lines.append("**Descrição (PT):**")
                        lines.append(f"> {descriptions_pt[0].get('value', 'N/A')}")
                        lines.append("")
                    
                    if descriptions_en:
                        lines.append("**Descrição (EN):**")
                        lines.append(f"> {descriptions_en[0].get('value', 'N/A')}")
                        lines.append("")
                    
                    weaknesses = bnvd_data.get("weaknesses", [])
                    if weaknesses:
                        cwes = [w.get("cwe_id") for w in weaknesses if w.get("cwe_id")]
                        if cwes:
                            lines.append(f"**CWEs:** {', '.join(cwes)}")
                            lines.append("")
                    
                    cisa_kev = bnvd_data.get("cisa_kev")
                    if cisa_kev:
                        lines.append("**CISA KEV (Known Exploited Vulnerability):**")
                        lines.append(f"- Adicionado: {cisa_kev.get('exploit_add', 'N/A')}")
                        lines.append(f"- Ação Requerida: {cisa_kev.get('required_action', 'N/A')}")
                        lines.append(f"- Prazo: {cisa_kev.get('action_due', 'N/A')}")
                        lines.append("")
                    
                    references = bnvd_data.get("references", [])
                    if references:
                        lines.append("**Referências:**")
                        for ref in references[:5]:
                            url = ref.get("url", "")
                            tags = ref.get("tags", [])
                            tag_str = f" ({', '.join(tags)})" if tags else ""
                            lines.append(f"- [{url[:60]}...]({url}){tag_str}")
                        if len(references) > 5:
                            lines.append(f"- *... e mais {len(references) - 5} referências*")
                        lines.append("")
                
                if source == "Dependabot":
                    pkg_name = alert.get("package_name")
                    pkg_ecosystem = alert.get("package_ecosystem")
                    patched = alert.get("first_patched_version")
                    
                    if pkg_name:
                        lines.append(f"**Pacote Afetado:** `{pkg_ecosystem}/{pkg_name}`")
                    if patched:
                        lines.append(f"**Versão Corrigida:** `{patched}`")
                    lines.append("")
                
                elif source == "CodeQL":
                    file_path = alert.get("file_path")
                    start_line = alert.get("start_line")
                    rule_name = alert.get("rule_name")
                    
                    if file_path:
                        location = file_path
                        if start_line:
                            location += f":{start_line}"
                        lines.append(f"**Localização:** `{location}`")
                    if rule_name:
                        lines.append(f"**Regra CodeQL:** {rule_name}")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        if cwe_only_alerts:
            lines.append("## Alertas CWE-Only (Code Scanning)")
            lines.append("")
            lines.append("Os seguintes alertas do Code Scanning contêm apenas CWEs (sem CVE para enriquecimento):")
            lines.append("")
            
            for alert in cwe_only_alerts:
                rule_id = alert.get("rule_id", "Desconhecido")
                rule_name = alert.get("rule_name", "")
                severity = alert.get("severity", "unknown")
                cwes = alert.get("cwes", [])
                file_path = alert.get("file_path")
                start_line = alert.get("start_line")
                alert_url = alert.get("alert_url")
                
                lines.append(f"### {rule_id}")
                if rule_name:
                    lines.append(f"**Nome:** {rule_name}")
                lines.append(f"**Severidade:** {get_severity_emoji(severity.upper())} {severity.upper()}")
                if cwes:
                    lines.append(f"**CWEs:** {', '.join(cwes)}")
                if file_path:
                    location = file_path
                    if start_line:
                        location += f":{start_line}"
                    lines.append(f"**Localização:** `{location}`")
                if alert_url:
                    lines.append(f"**Ver no GitHub:** [{rule_id}]({alert_url})")
                lines.append("")
                lines.append("---")
                lines.append("")
        
        lines.append("## Sobre este Relatório")
        lines.append("")
        lines.append("Este relatório foi gerado automaticamente pela [BNVD Security Enricher Action](https://github.com/marketplace/actions/bnvd-security-enricher).")
        lines.append("")
        lines.append("**Fontes de Dados:**")
        lines.append("- [BNVD - Banco Nacional de Vulnerabilidades](https://bnvd.org)")
        lines.append("- [NVD - National Vulnerability Database](https://nvd.nist.gov)")
        lines.append("- [GitHub Security Advisories](https://github.com/advisories)")
        lines.append("")
        lines.append("---")
        lines.append(f"*Relatório gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC*")
        
        return "\n".join(lines)
    
    def save(self, content: str, filepath: str) -> str:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        logger.info(f"Relatório Markdown salvo em: {filepath}")
        return filepath


class ReportGenerator:
    
    def __init__(self, repo_name: str, output_dir: str = "."):
        self.repo_name = repo_name
        self.output_dir = output_dir
        self.json_reporter = JSONReporter(repo_name)
        self.md_reporter = MarkdownReporter(repo_name)
    
    def generate_all(
        self, 
        alerts: List[Dict], 
        output_format: str = "both",
        json_filename: str = "bnvd-security-report.json",
        md_filename: str = "bnvd-security-report.md",
        cwe_only_alerts: Optional[List[Dict]] = None
    ) -> Dict[str, str]:
        statistics = generate_statistics(alerts)
        
        if cwe_only_alerts:
            statistics["cwe_only_count"] = len(cwe_only_alerts)
        else:
            statistics["cwe_only_count"] = 0
        
        outputs = {}
        
        if output_format in ("json", "both"):
            json_report = self.json_reporter.generate(alerts, statistics)
            if cwe_only_alerts:
                json_report["cwe_only_alerts"] = cwe_only_alerts
                json_report["summary"]["cwe_only_count"] = len(cwe_only_alerts)
            json_path = os.path.join(self.output_dir, json_filename)
            self.json_reporter.save(json_report, json_path)
            outputs["json"] = json_path
        
        if output_format in ("markdown", "md", "both"):
            md_content = self.md_reporter.generate(alerts, statistics, cwe_only_alerts)
            md_path = os.path.join(self.output_dir, md_filename)
            self.md_reporter.save(md_content, md_path)
            outputs["markdown"] = md_path
        
        return outputs
