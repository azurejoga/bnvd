import requests
from typing import Any, Dict, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .utils import logger, sanitize_cve_id, sanitize_cwe_id


class GitHubAPIClient:

    BASE_URL = "https://api.github.com"
    API_VERSION = "2022-11-28"

    def __init__(self, token: str, timeout: int = 30, retry_attempts: int = 3):
        self.token = token
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": "BNVD-Security-Enricher/1.0"
        })

    def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None) -> Any:
        url = f"{self.BASE_URL}{endpoint}"

        @retry(
            stop=stop_after_attempt(self.retry_attempts),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type((requests.exceptions.Timeout, requests.exceptions.ConnectionError))
        )
        def _request():
            response = self.session.request(method, url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()

        return _request()

    def _paginate(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        all_results = []
        page = 1
        per_page = 100

        if params is None:
            params = {}
        params["per_page"] = per_page

        while True:
            params["page"] = page
            try:
                results = self._make_request("GET", endpoint, params)
                if not results:
                    break
                all_results.extend(results)
                if len(results) < per_page:
                    break
                page += 1
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.warning(f"Endpoint não encontrado: {endpoint}")
                    break
                raise

        return all_results

    def get_dependabot_alerts(self, owner: str, repo: str, state: str = "open") -> List[Dict]:
        """
        Busca alertas do Dependabot via API do GitHub.
        
        Endpoint: GET /repos/{owner}/{repo}/dependabot/alerts
        Requer permissão: security_events:read
        """
        endpoint = f"/repos/{owner}/{repo}/dependabot/alerts"
        params = {"state": state}

        try:
            logger.info(f"Buscando alertas Dependabot em: {self.BASE_URL}{endpoint}")
            logger.info(f"Parâmetros: state={state}")
            
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Dependabot no estado '{state}'")
            
            # Log detalhado dos primeiros alertas para debug
            if len(alerts) > 0:
                first = alerts[0]
                logger.info(f"Primeiro alerta: #{first.get('number', 'N/A')} - {first.get('security_advisory', {}).get('ghsa_id', 'N/A')}")
                logger.debug(f"CVE: {first.get('security_advisory', {}).get('cve_id', 'N/A')}")
            else:
                logger.warning("⚠️  Nenhum alerta Dependabot encontrado no estado 'open'")
                logger.info("Verificando outros estados para diagnóstico...")
                
                # Buscar todos os estados para diagnóstico
                all_states = []
                for check_state in ["dismissed", "fixed", "auto_dismissed"]:
                    try:
                        state_alerts = self._paginate(endpoint, {"state": check_state})
                        if state_alerts:
                            all_states.append((check_state, len(state_alerts)))
                            logger.info(f"  - {len(state_alerts)} alertas no estado '{check_state}'")
                    except Exception:
                        pass
                
                if not all_states:
                    logger.warning("Nenhum alerta Dependabot encontrado em qualquer estado.")
                    logger.warning("Possíveis causas:")
                    logger.warning("  1. Dependabot não está habilitado no repositório")
                    logger.warning("  2. O token não tem permissão 'security_events:read'")
                    logger.warning("  3. O repositório não possui dependências com vulnerabilidades")
                    logger.warning("  4. O repositório não possui arquivos de manifesto (package.json, requirements.txt, etc.)")

            return alerts
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("❌ Sem permissão para acessar alertas Dependabot")
                logger.error("Verifique se o token tem permissão 'security_events:read'")
                logger.error(f"Response: {e.response.text}")
            elif e.response.status_code == 404:
                logger.error("❌ Endpoint não encontrado ou Dependabot não habilitado")
                logger.error("Verifique se:")
                logger.error("  1. O repositório existe e está acessível")
                logger.error("  2. Dependabot está ativado nas configurações de segurança")
                logger.error("  3. O nome do repositório está correto (owner/repo)")
            else:
                logger.error(f"❌ Erro HTTP {e.response.status_code} ao buscar alertas Dependabot")
                logger.error(f"Response: {e.response.text}")
            return []

    def get_code_scanning_alerts(self, owner: str, repo: str, state: str = "open") -> List[Dict]:
        """
        Busca alertas do Code Scanning (CodeQL) via API do GitHub.
        
        Endpoint: GET /repos/{owner}/{repo}/code-scanning/alerts
        Requer permissão: security_events:read
        """
        endpoint = f"/repos/{owner}/{repo}/code-scanning/alerts"
        params = {"state": state}

        try:
            logger.info(f"Buscando alertas Code Scanning em: {self.BASE_URL}{endpoint}")
            logger.info(f"Parâmetros: state={state}")
            
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Code Scanning no estado '{state}'")
            
            # Log detalhado para debug
            if len(alerts) > 0:
                first = alerts[0]
                rule = first.get('rule', {})
                logger.info(f"Primeiro alerta: #{first.get('number', 'N/A')} - {rule.get('id', 'N/A')}")
                logger.debug(f"Severidade: {rule.get('security_severity_level', 'N/A')}")
                logger.debug(f"Tags: {rule.get('tags', [])}")
            else:
                logger.warning("⚠️  Nenhum alerta Code Scanning encontrado no estado 'open'")
                logger.info("Verificando outros estados para diagnóstico...")
                
                # Buscar todos os estados para diagnóstico
                all_states = []
                for check_state in ["dismissed", "fixed"]:
                    try:
                        state_alerts = self._paginate(endpoint, {"state": check_state})
                        if state_alerts:
                            all_states.append((check_state, len(state_alerts)))
                            logger.info(f"  - {len(state_alerts)} alertas no estado '{check_state}'")
                    except Exception:
                        pass
                
                if not all_states:
                    logger.warning("Nenhum alerta Code Scanning encontrado em qualquer estado.")
                    logger.warning("Possíveis causas:")
                    logger.warning("  1. CodeQL não está configurado no repositório")
                    logger.warning("  2. O workflow CodeQL não executou ainda")
                    logger.warning("  3. O token não tem permissão 'security_events:read'")
                    logger.warning("  4. Não há vulnerabilidades detectadas no código")

            return alerts
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("❌ Sem permissão para acessar alertas Code Scanning")
                logger.error("Verifique se o token tem permissão 'security_events:read'")
                logger.error(f"Response: {e.response.text}")
            elif e.response.status_code == 404:
                logger.error("❌ Endpoint não encontrado ou Code Scanning não habilitado")
                logger.error("Verifique se:")
                logger.error("  1. O repositório tem CodeQL configurado")
                logger.error("  2. O workflow CodeQL já executou pelo menos uma vez")
                logger.error("  3. O nome do repositório está correto")
            else:
                logger.error(f"❌ Erro HTTP {e.response.status_code} ao buscar alertas Code Scanning")
                logger.error(f"Response: {e.response.text}")
            return []

    def extract_cves_from_dependabot(self, alerts: List[Dict]) -> List[Dict]:
        """
        Extrai CVEs de alertas Dependabot.
        
        Endpoint: GET /repos/{owner}/{repo}/dependabot/alerts
        Os alertas contêm security_advisory com cve_id ou identifiers.
        """
        if not alerts:
            return []
            
        cves = []
        for alert in alerts:
            if not alert or not isinstance(alert, dict):
                continue
                
            security_advisory = alert.get("security_advisory") or {}
            cve_id = security_advisory.get("cve_id")

            if not cve_id:
                identifiers = security_advisory.get("identifiers") or []
                for identifier in identifiers:
                    if isinstance(identifier, dict) and identifier.get("type") == "CVE":
                        cve_id = identifier.get("value")
                        break

            cve_id = sanitize_cve_id(cve_id)
            if cve_id:
                dependency = alert.get("dependency") or {}
                package = dependency.get("package") or {}
                security_vulnerability = alert.get("security_vulnerability") or {}
                first_patched = security_vulnerability.get("first_patched_version") or {}

                cves.append({
                    "cve_id": cve_id,
                    "source": "Dependabot",
                    "alert_number": alert.get("number"),
                    "alert_url": alert.get("html_url"),
                    "state": alert.get("state"),
                    "severity": security_advisory.get("severity") or "unknown",
                    "package_name": package.get("name"),
                    "package_ecosystem": package.get("ecosystem"),
                    "vulnerable_version_range": security_vulnerability.get("vulnerable_version_range"),
                    "first_patched_version": first_patched.get("identifier"),
                    "ghsa_id": security_advisory.get("ghsa_id"),
                    "summary": security_advisory.get("summary"),
                    "description": security_advisory.get("description"),
                    "published_at": security_advisory.get("published_at"),
                    "updated_at": security_advisory.get("updated_at"),
                    "references": security_advisory.get("references") or [],
                    "cvss": security_advisory.get("cvss") or {},
                    "cvss_severities": security_advisory.get("cvss_severities") or {},
                    "cwes": security_advisory.get("cwes") or []
                })

        logger.info(f"Extraídos {len(cves)} CVEs de alertas Dependabot")
        return cves

    def extract_cves_from_code_scanning(self, alerts: List[Dict], include_cwe_only: bool = False) -> tuple:
        """
        Extrai CVEs e CWEs de alertas Code Scanning.
        
        A API do GitHub Code Scanning retorna alertas com CVEs/CWEs nas tags da regra.
        Exemplos de tags: 
          - "external/cve/CVE-2024-12345" (CVE)
          - "external/cwe/cwe-89" (CWE)
        
        Nota: Alertas CodeQL geralmente contêm CWEs, não CVEs.
        CVEs são mais comuns em alertas Dependabot.
        
        Args:
            alerts: Lista de alertas do Code Scanning
            include_cwe_only: Se True, retorna também alertas que têm apenas CWEs (sem CVE)
            
        Returns:
            Tupla (cve_alerts, cwe_only_alerts) onde:
            - cve_alerts: Lista de alertas com CVE IDs
            - cwe_only_alerts: Lista de alertas com CWEs mas sem CVE (só se include_cwe_only=True)
        """
        if not alerts:
            return [], []
        
        cves = []
        cwe_only_alerts = []
        
        for alert in alerts:
            if not alert or not isinstance(alert, dict):
                continue
                
            rule = alert.get("rule") or {}
            
            tags = rule.get("tags") or alert.get("tags") or []
            
            cve_id = None
            cwes = []
            
            for tag in tags:
                if isinstance(tag, str):
                    tag_lower = tag.lower()
                    if "/cve/" in tag_lower or tag_lower.startswith("cve-"):
                        parts = tag.split("/")
                        for part in parts:
                            if part.upper().startswith("CVE-"):
                                cve_id = part.upper()
                                break
                        if cve_id:
                            break
                    
                    if "/cwe/" in tag_lower or "cwe-" in tag_lower:
                        parts = tag.split("/")
                        for part in parts:
                            part_lower = part.lower()
                            if part_lower.startswith("cwe-"):
                                cwe_num = part_lower.replace("cwe-", "")
                                try:
                                    int(cwe_num)
                                    cwe_formatted = f"CWE-{cwe_num}"
                                    sanitized_cwe = sanitize_cwe_id(cwe_formatted)
                                    if sanitized_cwe and sanitized_cwe not in cwes:
                                        cwes.append(sanitized_cwe)
                                except ValueError:
                                    pass
                                break

            most_recent_instance = alert.get("most_recent_instance") or {}
            location_raw = most_recent_instance.get("location")
            location = location_raw if isinstance(location_raw, dict) else {}
            
            tool = alert.get("tool") or {}
            dismissed_by = alert.get("dismissed_by") or {}
            
            alert_data = {
                "source": "Code Scanning",
                "alert_number": alert.get("number"),
                "alert_url": alert.get("html_url"),
                "state": alert.get("state"),
                "severity": rule.get("security_severity_level") or alert.get("severity") or "unknown",
                "rule_id": rule.get("id"),
                "rule_name": rule.get("name"),
                "rule_description": rule.get("description"),
                "rule_full_description": rule.get("full_description"),
                "tool_name": tool.get("name"),
                "tool_version": tool.get("version"),
                "file_path": location.get("path"),
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
                "created_at": alert.get("created_at"),
                "updated_at": alert.get("updated_at"),
                "dismissed_at": alert.get("dismissed_at"),
                "dismissed_reason": alert.get("dismissed_reason"),
                "dismissed_by": dismissed_by.get("login"),
                "dismissed_comment": alert.get("dismissed_comment"),
                "tags": tags,
                "cwes": cwes
            }
            
            if cve_id:
                cve_id = sanitize_cve_id(cve_id)
                if cve_id:
                    alert_data["cve_id"] = cve_id
                    cves.append(alert_data)
            elif cwes and include_cwe_only:
                alert_data["cve_id"] = None
                cwe_only_alerts.append(alert_data)

        logger.info(f"Extraídos {len(cves)} CVEs de {len(alerts)} alertas Code Scanning")
        
        cwe_only_count = len(cwe_only_alerts)
        no_cve_count = len(alerts) - len(cves) - cwe_only_count
        
        if cwe_only_count > 0:
            logger.info(f"{cwe_only_count} alertas Code Scanning com CWEs apenas (incluídos)")
            for alert_info in cwe_only_alerts[:3]:
                cwes_str = ", ".join(alert_info.get("cwes", []))
                logger.debug(f"  - Alert #{alert_info['alert_number']}: {alert_info['rule_id']} - CWEs: {cwes_str}")
        
        if no_cve_count > 0:
            logger.info(f"{no_cve_count} alertas Code Scanning sem CVE nem CWE (ignorados)")
        
        return cves, cwe_only_alerts

    def close(self):
        self.session.close()