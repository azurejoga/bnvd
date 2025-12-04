#!/usr/bin/env python3
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils import (
    logger,
    Timer,
    get_env,
    get_env_bool,
    get_env_int,
    write_github_output,
    write_github_summary,
    log_group_start,
    log_group_end,
    log_error,
    log_warning,
    log_notice
)
from src.github_api import GitHubAPIClient
from src.bnvd_api import BNVDAPIClient
from src.parsers import (
    merge_alert_with_enrichment,
    deduplicate_cves,
    filter_by_severity,
    count_by_severity,
    generate_statistics
)
from src.reporters import ReportGenerator


def main():
    timer = Timer().start()
    
    logger.info("=" * 60)
    logger.info("BNVD Security Enricher - Iniciando...")
    logger.info("=" * 60)
    
    log_group_start("Configuração")
    
    github_token = get_env("INPUT_GITHUB_TOKEN")
    if not github_token:
        log_error("O input 'github_token' é obrigatório!")
        sys.exit(1)
    
    dependabot_token = get_env("INPUT_DEPENDABOT_TOKEN", "")
    include_cwe_only = get_env_bool("INPUT_INCLUDE_CWE_ONLY", True)
    
    bnvd_api_url = get_env("INPUT_BNVD_API_URL", "https://bnvd.org/api/v1")
    nvd_api_key = get_env("INPUT_NVD_API_KEY", "")
    include_pt = get_env_bool("INPUT_INCLUDE_PT", True)
    severity_filter = get_env("INPUT_SEVERITY_FILTER", "ALL").upper()
    fail_on_critical = get_env_bool("INPUT_FAIL_ON_CRITICAL", False)
    fail_on_high = get_env_bool("INPUT_FAIL_ON_HIGH", False)
    output_format = get_env("INPUT_OUTPUT_FORMAT", "both").lower()
    max_concurrent = get_env_int("INPUT_MAX_CONCURRENT_REQUESTS", 5)
    timeout = get_env_int("INPUT_REQUEST_TIMEOUT", 30)
    retry_attempts = get_env_int("INPUT_RETRY_ATTEMPTS", 3)
    
    repo_full = get_env("GITHUB_REPOSITORY")
    workspace = get_env("GITHUB_WORKSPACE", ".")
    
    if not repo_full:
        log_error("GITHUB_REPOSITORY não definido!")
        sys.exit(1)
    
    owner, repo = repo_full.split("/")
    
    logger.info(f"Repositório: {repo_full}")
    logger.info(f"API BNVD: {bnvd_api_url}")
    logger.info(f"Incluir PT: {include_pt}")
    logger.info(f"Filtro de Severidade: {severity_filter}")
    logger.info(f"Formato de Saída: {output_format}")
    logger.info(f"Requisições Paralelas: {max_concurrent}")
    logger.info(f"Incluir alertas CWE-only: {include_cwe_only}")
    logger.info(f"Token Dependabot separado: {'Sim' if dependabot_token else 'Não (usando token padrão)'}")
    
    log_group_end()
    
    log_group_start("Coletando Alertas do GitHub")
    
    github_client = GitHubAPIClient(
        token=github_token,
        timeout=timeout,
        retry_attempts=retry_attempts
    )
    
    dependabot_client = None
    if dependabot_token:
        dependabot_client = GitHubAPIClient(
            token=dependabot_token,
            timeout=timeout,
            retry_attempts=retry_attempts
        )
    
    dependabot_alerts = []
    codeql_alerts = []
    codeql_cwe_only_alerts = []
    dependabot_cves = []
    codeql_cves = []
    
    try:
        client_for_dependabot = dependabot_client if dependabot_client else github_client
        dependabot_alerts = client_for_dependabot.get_dependabot_alerts(owner, repo)
        logger.info(f"Alertas Dependabot obtidos: {len(dependabot_alerts)}")
    except Exception as e:
        logger.warning(f"Falha ao obter alertas Dependabot: {e}")
        if "403" in str(e) or "Resource not accessible" in str(e):
            log_warning("O token GITHUB_TOKEN padrão não tem acesso à API Dependabot. Use o input 'dependabot_token' com um PAT que tenha permissão 'security_events'.")
        else:
            log_warning(f"Não foi possível obter alertas Dependabot: {e}")
    
    try:
        codeql_alerts = github_client.get_code_scanning_alerts(owner, repo)
        logger.info(f"Alertas Code Scanning obtidos: {len(codeql_alerts)}")
    except Exception as e:
        logger.warning(f"Falha ao obter alertas Code Scanning: {e}")
        log_warning(f"Não foi possível obter alertas Code Scanning: {e}")
    
    try:
        if dependabot_alerts:
            dependabot_cves = github_client.extract_cves_from_dependabot(dependabot_alerts)
            logger.info(f"CVEs extraídos de Dependabot: {len(dependabot_cves)}")
    except Exception as e:
        logger.warning(f"Erro ao processar alertas Dependabot: {e}")
        log_warning(f"Falha ao extrair CVEs de alertas Dependabot: {e}")
    
    try:
        if codeql_alerts:
            codeql_cves, codeql_cwe_only_alerts = github_client.extract_cves_from_code_scanning(
                codeql_alerts, 
                include_cwe_only=include_cwe_only
            )
            logger.info(f"CVEs extraídos de Code Scanning: {len(codeql_cves)}")
            if codeql_cwe_only_alerts:
                logger.info(f"Alertas CWE-only de Code Scanning: {len(codeql_cwe_only_alerts)}")
    except Exception as e:
        logger.warning(f"Erro ao processar alertas Code Scanning: {e}")
        log_warning(f"Falha ao extrair CVEs de alertas Code Scanning: {e}")
    
    github_client.close()
    if dependabot_client:
        dependabot_client.close()
    
    all_cves = dependabot_cves + codeql_cves
    unique_cves = deduplicate_cves(all_cves)
    
    logger.info(f"CVEs encontrados - Dependabot: {len(dependabot_cves)}, Code Scanning: {len(codeql_cves)}")
    logger.info(f"Total de CVEs únicos: {len(unique_cves)}")
    
    if codeql_cwe_only_alerts:
        logger.info(f"Alertas CWE-only (sem enriquecimento CVE): {len(codeql_cwe_only_alerts)}")
    
    log_group_end()
    
    cwe_only_count = len(codeql_cwe_only_alerts) if codeql_cwe_only_alerts else 0
    
    if not unique_cves and cwe_only_count == 0:
        logger.info("Nenhum CVE ou CWE encontrado nos alertas.")
        
        write_github_output("total_cves_found", 0)
        write_github_output("total_enriched", 0)
        write_github_output("critical_count", 0)
        write_github_output("high_count", 0)
        write_github_output("medium_count", 0)
        write_github_output("low_count", 0)
        write_github_output("cwe_only_count", 0)
        write_github_output("has_critical", "false")
        write_github_output("has_high", "false")
        write_github_output("cve_list", "[]")
        write_github_output("execution_time", timer.elapsed)
        
        log_notice("Nenhuma vulnerabilidade CVE ou CWE encontrada nos alertas de segurança.", "Scan Completo")
        
        report_gen = ReportGenerator(repo_full, workspace)
        outputs = report_gen.generate_all([], output_format, cwe_only_alerts=[])
        
        if "json" in outputs:
            write_github_output("report_json_path", outputs["json"])
        if "markdown" in outputs:
            write_github_output("report_md_path", outputs["markdown"])
        
        logger.info(f"Execução finalizada em {timer}")
        return
    
    if not unique_cves and cwe_only_count > 0:
        logger.info(f"Nenhum CVE encontrado, mas {cwe_only_count} alertas CWE-only detectados.")
        
        write_github_output("total_cves_found", 0)
        write_github_output("total_enriched", 0)
        write_github_output("critical_count", 0)
        write_github_output("high_count", 0)
        write_github_output("medium_count", 0)
        write_github_output("low_count", 0)
        write_github_output("cwe_only_count", cwe_only_count)
        write_github_output("has_critical", "false")
        write_github_output("has_high", "false")
        write_github_output("cve_list", "[]")
        write_github_output("execution_time", timer.elapsed)
        
        log_notice(f"{cwe_only_count} alertas Code Scanning com CWEs encontrados (sem CVE para enriquecimento).", "Scan Completo")
        
        report_gen = ReportGenerator(repo_full, workspace)
        outputs = report_gen.generate_all([], output_format, cwe_only_alerts=codeql_cwe_only_alerts)
        
        if "json" in outputs:
            write_github_output("report_json_path", outputs["json"])
        if "markdown" in outputs:
            write_github_output("report_md_path", outputs["markdown"])
        
        logger.info(f"Execução finalizada em {timer}")
        return
    
    log_group_start("Enriquecendo CVEs com BNVD/NVD")
    
    bnvd_client = BNVDAPIClient(
        bnvd_api_url=bnvd_api_url,
        nvd_api_key=nvd_api_key if nvd_api_key else None,
        include_pt=include_pt,
        timeout=timeout,
        retry_attempts=retry_attempts,
        max_concurrent=max_concurrent
    )
    
    try:
        cve_ids = [cve["cve_id"] for cve in unique_cves]
        enrichments = bnvd_client.fetch_multiple_cves(cve_ids)
        
        enriched_alerts = []
        for cve in unique_cves:
            cve_id = cve["cve_id"]
            enrichment = enrichments.get(cve_id)
            merged = merge_alert_with_enrichment(cve, enrichment)
            enriched_alerts.append(merged)
        
    finally:
        bnvd_client.close()
    
    log_group_end()
    
    log_group_start("Aplicando Filtros e Gerando Estatísticas")
    
    filtered_alerts = filter_by_severity(enriched_alerts, severity_filter)
    logger.info(f"Alertas após filtro ({severity_filter}): {len(filtered_alerts)}")
    
    statistics = generate_statistics(filtered_alerts)
    severity_counts = statistics["severity_counts"]
    
    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    medium_count = severity_counts.get("medium", 0)
    low_count = severity_counts.get("low", 0)
    
    has_critical = critical_count > 0
    has_high = high_count > 0 or has_critical
    
    logger.info(f"Distribuição por severidade:")
    logger.info(f"  - Crítica: {critical_count}")
    logger.info(f"  - Alta: {high_count}")
    logger.info(f"  - Média: {medium_count}")
    logger.info(f"  - Baixa: {low_count}")
    
    log_group_end()
    
    log_group_start("Gerando Relatórios")
    
    report_gen = ReportGenerator(repo_full, workspace)
    outputs = report_gen.generate_all(filtered_alerts, output_format, cwe_only_alerts=codeql_cwe_only_alerts)
    
    log_group_end()
    
    execution_time = timer.stop()
    
    log_group_start("Definindo Outputs")
    
    cve_list = [
        {
            "cve_id": a["cve_id"],
            "severity": a.get("bnvd_data", {}).get("cvss_severity") or a.get("severity", "unknown"),
            "score": a.get("bnvd_data", {}).get("cvss_score", 0.0),
            "source": a.get("source", "unknown")
        }
        for a in filtered_alerts
    ]
    
    write_github_output("total_cves_found", len(unique_cves))
    write_github_output("total_enriched", statistics["enriched_cves"])
    write_github_output("critical_count", critical_count)
    write_github_output("high_count", high_count)
    write_github_output("medium_count", medium_count)
    write_github_output("low_count", low_count)
    write_github_output("cwe_only_count", cwe_only_count)
    write_github_output("has_critical", str(has_critical).lower())
    write_github_output("has_high", str(has_high).lower())
    write_github_output("cve_list", cve_list)
    write_github_output("execution_time", round(execution_time, 2))
    
    if "json" in outputs:
        write_github_output("report_json_path", outputs["json"])
    if "markdown" in outputs:
        write_github_output("report_md_path", outputs["markdown"])
    
    log_group_end()
    
    cwe_summary_line = f"| **Alertas CWE-only** | {cwe_only_count} |" if cwe_only_count > 0 else ""
    
    summary = f"""
## BNVD Security Enricher - Resumo

| Métrica | Valor |
|:--------|:------|
| **Total de CVEs** | {len(unique_cves)} |
| **CVEs Enriquecidos** | {statistics['enriched_cves']} |
| **Críticas** | {critical_count} |
| **Altas** | {high_count} |
| **Médias** | {medium_count} |
| **Baixas** | {low_count} |
{cwe_summary_line}
| **Tempo de Execução** | {execution_time:.2f}s |

[Ver relatório completo]({outputs.get('markdown', '#')})
"""
    write_github_summary(summary)
    
    logger.info("=" * 60)
    logger.info(f"Execução finalizada com sucesso em {execution_time:.2f}s")
    logger.info(f"Total de CVEs: {len(unique_cves)}")
    logger.info(f"CVEs Enriquecidos: {statistics['enriched_cves']}")
    logger.info("=" * 60)
    
    if has_critical:
        log_warning(f"Encontradas {critical_count} vulnerabilidades CRÍTICAS!")
    if has_high and not has_critical:
        log_warning(f"Encontradas {high_count} vulnerabilidades de severidade ALTA!")
    
    if fail_on_critical and has_critical:
        log_error(f"Falha: {critical_count} vulnerabilidades críticas encontradas!")
        sys.exit(1)
    
    if fail_on_high and has_high:
        log_error(f"Falha: Vulnerabilidades de alta severidade encontradas! (Critical: {critical_count}, High: {high_count})")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(f"Erro fatal: {e}")
        log_error(f"Erro fatal durante execução: {e}")
        sys.exit(1)
