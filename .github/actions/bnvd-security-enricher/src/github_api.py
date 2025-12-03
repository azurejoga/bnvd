import requests
from typing import Any, Dict, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .utils import logger, sanitize_cve_id


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
        endpoint = f"/repos/{owner}/{repo}/dependabot/alerts"
        params = {"state": state}

        try:
            logger.info(f"Buscando alertas Dependabot em: {self.BASE_URL}{endpoint}")
            logger.info(f"Parâmetros: state={state}")
            
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Dependabot")
            
            # Log detalhado dos primeiros alertas para debug
            if len(alerts) > 0:
                logger.info(f"Primeiro alerta (preview): {alerts[0].get('number', 'N/A')} - {alerts[0].get('security_advisory', {}).get('ghsa_id', 'N/A')}")
            
            # Tentar também buscar alertas fechados para verificar se existem vulnerabilidades
            if len(alerts) == 0:
                logger.warning("Nenhum alerta Dependabot ABERTO encontrado. Tentando buscar todos os estados...")
                try:
                    all_alerts = self._paginate(endpoint, {"state": "dismissed"})
                    logger.info(f"Encontrados {len(all_alerts)} alertas DISMISSED")
                    all_alerts_closed = self._paginate(endpoint, {"state": "fixed"})
                    logger.info(f"Encontrados {len(all_alerts_closed)} alertas FIXED")
                except Exception as ex:
                    logger.debug(f"Erro ao buscar outros estados: {ex}")
                
                logger.warning("Nenhum alerta Dependabot ABERTO encontrado. Verifique se:")
                logger.warning("  1. Dependabot está habilitado no repositório")
                logger.warning("  2. O token tem permissão 'security_events'")
                logger.warning("  3. Existem alertas abertos no repositório")
                logger.warning("  4. As dependências têm vulnerabilidades conhecidas")

            return alerts
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("Sem permissão para acessar alertas Dependabot.")
                logger.error("Verifique se o token tem scope 'security_events'")
                logger.error(f"Response: {e.response.text}")
            elif e.response.status_code == 404:
                logger.error("Dependabot alerts não habilitado ou repositório não encontrado.")
                logger.error("Verifique se o repositório existe e se Dependabot está ativado")
            else:
                logger.error(f"Erro HTTP {e.response.status_code} ao buscar alertas Dependabot: {e}")
                logger.error(f"Response: {e.response.text}")
            return []

    def get_code_scanning_alerts(self, owner: str, repo: str, state: str = "open") -> List[Dict]:
        endpoint = f"/repos/{owner}/{repo}/code-scanning/alerts"
        params = {"state": state}

        try:
            logger.info(f"Buscando alertas CodeQL/Code Scanning em: {self.BASE_URL}{endpoint}")
            logger.info(f"Parâmetros: state={state}")
            
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Code Scanning")
            
            # Log detalhado dos primeiros alertas para debug
            if len(alerts) > 0:
                logger.info(f"Primeiro alerta (preview): {alerts[0].get('number', 'N/A')} - {alerts[0].get('rule', {}).get('id', 'N/A')}")
            
            # Tentar também buscar alertas de outros estados
            if len(alerts) == 0:
                logger.warning("Nenhum alerta CodeQL ABERTO encontrado. Tentando buscar todos os estados...")
                try:
                    all_alerts = self._paginate(endpoint, {"state": "dismissed"})
                    logger.info(f"Encontrados {len(all_alerts)} alertas DISMISSED")
                    all_alerts_closed = self._paginate(endpoint, {"state": "fixed"})
                    logger.info(f"Encontrados {len(all_alerts_closed)} alertas FIXED")
                except Exception as ex:
                    logger.debug(f"Erro ao buscar outros estados: {ex}")
                
                logger.warning("Nenhum alerta CodeQL ABERTO encontrado. Verifique se:")
                logger.warning("  1. CodeQL está configurado no repositório (.github/workflows/codeql.yml)")
                logger.warning("  2. O token tem permissão 'security_events'")
                logger.warning("  3. Existem alertas abertos no repositório")
                logger.warning("  4. CodeQL já executou pelo menos uma vez")

            return alerts
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("Sem permissão para acessar alertas Code Scanning.")
                logger.error("Verifique se o token tem scope 'security_events'")
                logger.error(f"Response: {e.response.text}")
            elif e.response.status_code == 404:
                logger.error("Code Scanning não habilitado ou repositório não encontrado.")
                logger.error("Verifique se o repositório tem CodeQL configurado")
            else:
                logger.error(f"Erro HTTP {e.response.status_code} ao buscar alertas Code Scanning: {e}")
                logger.error(f"Response: {e.response.text}")
            return []

    def extract_cves_from_dependabot(self, alerts: List[Dict]) -> List[Dict]:
        cves = []
        for alert in alerts:
            security_advisory = alert.get("security_advisory", {})
            cve_id = security_advisory.get("cve_id")

            if not cve_id:
                identifiers = security_advisory.get("identifiers", [])
                for identifier in identifiers:
                    if identifier.get("type") == "CVE":
                        cve_id = identifier.get("value")
                        break

            cve_id = sanitize_cve_id(cve_id)
            if cve_id:
                dependency = alert.get("dependency", {})
                package = dependency.get("package", {})

                cves.append({
                    "cve_id": cve_id,
                    "source": "Dependabot",
                    "alert_number": alert.get("number"),
                    "alert_url": alert.get("html_url"),
                    "state": alert.get("state"),
                    "severity": security_advisory.get("severity", "unknown"),
                    "package_name": package.get("name"),
                    "package_ecosystem": package.get("ecosystem"),
                    "vulnerable_version_range": dependency.get("scope"),
                    "first_patched_version": alert.get("security_vulnerability", {}).get("first_patched_version", {}).get("identifier"),
                    "ghsa_id": security_advisory.get("ghsa_id"),
                    "summary": security_advisory.get("summary"),
                    "description": security_advisory.get("description"),
                    "published_at": security_advisory.get("published_at"),
                    "updated_at": security_advisory.get("updated_at"),
                    "references": security_advisory.get("references", []),
                    "cvss": security_advisory.get("cvss", {}),
                    "cwes": security_advisory.get("cwes", [])
                })

        logger.info(f"Extraídos {len(cves)} CVEs de alertas Dependabot")
        return cves

    def extract_cves_from_code_scanning(self, alerts: List[Dict]) -> List[Dict]:
        cves = []
        for alert in alerts:
            rule = alert.get("rule", {})
            tags = rule.get("tags", [])

            cve_id = None
            for tag in tags:
                if tag.startswith("external/cve/"):
                    cve_id = tag.split("/")[-1].upper()
                    break

            cve_id = sanitize_cve_id(cve_id)
            if cve_id:
                most_recent_instance = alert.get("most_recent_instance", {})
                location = most_recent_instance.get("location", {})

                cves.append({
                    "cve_id": cve_id,
                    "source": "CodeQL",
                    "alert_number": alert.get("number"),
                    "alert_url": alert.get("html_url"),
                    "state": alert.get("state"),
                    "severity": rule.get("security_severity_level", "unknown"),
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "rule_description": rule.get("description"),
                    "rule_full_description": rule.get("full_description"),
                    "tool_name": alert.get("tool", {}).get("name"),
                    "tool_version": alert.get("tool", {}).get("version"),
                    "file_path": location.get("path"),
                    "start_line": location.get("start_line"),
                    "end_line": location.get("end_line"),
                    "created_at": alert.get("created_at"),
                    "updated_at": alert.get("updated_at"),
                    "dismissed_at": alert.get("dismissed_at"),
                    "dismissed_reason": alert.get("dismissed_reason"),
                    "tags": tags
                })

        logger.info(f"Extraídos {len(cves)} CVEs de alertas Code Scanning")
        return cves

    def close(self):
        self.session.close()