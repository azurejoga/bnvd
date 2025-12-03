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
        logger.info(f"Buscando alertas Dependabot para {owner}/{repo}...")
        endpoint = f"/repos/{owner}/{repo}/dependabot/alerts"
        params = {"state": state}
        
        try:
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Dependabot")
            return alerts
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning("Sem permissão para acessar alertas Dependabot. Verifique se o token tem scope 'security_events'.")
            elif e.response.status_code == 404:
                logger.warning("Dependabot alerts não habilitado ou repositório não encontrado.")
            else:
                logger.error(f"Erro ao buscar alertas Dependabot: {e}")
            return []
    
    def get_code_scanning_alerts(self, owner: str, repo: str, state: str = "open") -> List[Dict]:
        logger.info(f"Buscando alertas CodeQL/Code Scanning para {owner}/{repo}...")
        endpoint = f"/repos/{owner}/{repo}/code-scanning/alerts"
        params = {"state": state}
        
        try:
            alerts = self._paginate(endpoint, params)
            logger.info(f"Encontrados {len(alerts)} alertas Code Scanning")
            return alerts
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning("Sem permissão para acessar alertas Code Scanning. Verifique se o token tem scope 'security_events'.")
            elif e.response.status_code == 404:
                logger.warning("Code Scanning não habilitado ou repositório não encontrado.")
            else:
                logger.error(f"Erro ao buscar alertas Code Scanning: {e}")
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
