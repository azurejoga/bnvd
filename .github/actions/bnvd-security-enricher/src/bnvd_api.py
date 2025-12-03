import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .utils import logger, get_severity_from_score


class BNVDAPIClient:
    
    def __init__(
        self,
        bnvd_api_url: str = "https://bnvd.org/api/v1",
        nvd_api_key: Optional[str] = None,
        include_pt: bool = True,
        timeout: int = 30,
        retry_attempts: int = 3,
        max_concurrent: int = 5
    ):
        self.bnvd_api_url = bnvd_api_url.rstrip("/")
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_api_key = nvd_api_key
        self.include_pt = include_pt
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.max_concurrent = max_concurrent
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "BNVD-Security-Enricher/1.0",
            "Accept": "application/json"
        })
        
        self.nvd_last_request = 0
        self.nvd_rate_limit = 6.0 if not nvd_api_key else 0.6
    
    def _wait_nvd_rate_limit(self):
        elapsed = time.time() - self.nvd_last_request
        if elapsed < self.nvd_rate_limit:
            time.sleep(self.nvd_rate_limit - elapsed)
        self.nvd_last_request = time.time()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((requests.exceptions.Timeout, requests.exceptions.ConnectionError))
    )
    def _fetch_from_bnvd(self, cve_id: str) -> Optional[Dict]:
        url = f"{self.bnvd_api_url}/vulnerabilities/{cve_id}"
        params = {"include_pt": str(self.include_pt).lower()}
        
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data"):
                    return data.get("data")
            elif response.status_code == 404:
                logger.debug(f"CVE {cve_id} não encontrado no BNVD")
            else:
                logger.warning(f"BNVD retornou status {response.status_code} para {cve_id}")
            
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erro ao consultar BNVD para {cve_id}: {e}")
            return None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((requests.exceptions.Timeout, requests.exceptions.ConnectionError))
    )
    def _fetch_from_nvd(self, cve_id: str) -> Optional[Dict]:
        self._wait_nvd_rate_limit()
        
        params = {"cveId": cve_id}
        headers = {}
        
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        try:
            response = self.session.get(
                self.nvd_api_url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    return vulnerabilities[0].get("cve")
            elif response.status_code == 404:
                logger.debug(f"CVE {cve_id} não encontrado no NVD")
            elif response.status_code == 429:
                logger.warning(f"Rate limit NVD atingido para {cve_id}")
                time.sleep(30)
            else:
                logger.warning(f"NVD retornou status {response.status_code} para {cve_id}")
            
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erro ao consultar NVD para {cve_id}: {e}")
            return None
    
    def fetch_cve_data(self, cve_id: str) -> Optional[Dict]:
        bnvd_data = self._fetch_from_bnvd(cve_id)
        
        if bnvd_data:
            logger.debug(f"Dados obtidos do BNVD para {cve_id}")
            bnvd_data["_source"] = "BNVD"
            return self._normalize_cve_data(bnvd_data)
        
        logger.debug(f"Tentando fallback NVD para {cve_id}")
        nvd_data = self._fetch_from_nvd(cve_id)
        
        if nvd_data:
            logger.debug(f"Dados obtidos do NVD para {cve_id}")
            nvd_data["_source"] = "NVD"
            return self._normalize_cve_data(nvd_data)
        
        logger.warning(f"Não foi possível obter dados para {cve_id} de nenhuma fonte")
        return None
    
    def fetch_multiple_cves(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        results = {}
        unique_cves = list(set(cve_ids))
        
        logger.info(f"Buscando dados para {len(unique_cves)} CVEs únicos...")
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future_to_cve = {
                executor.submit(self.fetch_cve_data, cve_id): cve_id
                for cve_id in unique_cves
            }
            
            for future in as_completed(future_to_cve):
                cve_id = future_to_cve[future]
                try:
                    results[cve_id] = future.result()
                except Exception as e:
                    logger.error(f"Erro ao processar {cve_id}: {e}")
                    results[cve_id] = None
        
        enriched_count = sum(1 for v in results.values() if v is not None)
        logger.info(f"Enriquecidos {enriched_count}/{len(unique_cves)} CVEs")
        
        return results
    
    def _normalize_cve_data(self, raw_data: Dict) -> Dict:
        normalized = {
            "cve_id": raw_data.get("id") or raw_data.get("cve_id"),
            "source_identifier": raw_data.get("sourceIdentifier"),
            "vuln_status": raw_data.get("vulnStatus"),
            "published": raw_data.get("published"),
            "last_modified": raw_data.get("lastModified"),
            "data_source": raw_data.get("_source", "unknown"),
            "descriptions": [],
            "descriptions_pt": [],
            "metrics": {
                "cvss_v31": None,
                "cvss_v30": None,
                "cvss_v2": None
            },
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "vendor_comments": [],
            "cisa_kev": None,
            "cvss_score": 0.0,
            "cvss_severity": "NONE",
            "cvss_vector": None
        }
        
        descriptions = raw_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                normalized["descriptions"].append({
                    "lang": "en",
                    "value": desc.get("value", "")
                })
            elif desc.get("lang") == "pt":
                normalized["descriptions_pt"].append({
                    "lang": "pt",
                    "value": desc.get("value", "")
                })
        
        descriptions_pt = raw_data.get("descriptions_pt", [])
        for desc in descriptions_pt:
            normalized["descriptions_pt"].append({
                "lang": "pt",
                "value": desc.get("value", "") if isinstance(desc, dict) else str(desc)
            })
        
        metrics = raw_data.get("metrics", {})
        
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            primary = next((m for m in cvss_v31 if m.get("type") == "Primary"), cvss_v31[0])
            cvss_data = primary.get("cvssData", {})
            normalized["metrics"]["cvss_v31"] = {
                "version": cvss_data.get("version", "3.1"),
                "vector_string": cvss_data.get("vectorString"),
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
                "base_score": cvss_data.get("baseScore", 0.0),
                "base_severity": cvss_data.get("baseSeverity", "NONE"),
                "exploitability_score": primary.get("exploitabilityScore"),
                "impact_score": primary.get("impactScore")
            }
            normalized["cvss_score"] = cvss_data.get("baseScore", 0.0)
            normalized["cvss_severity"] = cvss_data.get("baseSeverity", "NONE")
            normalized["cvss_vector"] = cvss_data.get("vectorString")
        
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            primary = next((m for m in cvss_v30 if m.get("type") == "Primary"), cvss_v30[0])
            cvss_data = primary.get("cvssData", {})
            normalized["metrics"]["cvss_v30"] = {
                "version": cvss_data.get("version", "3.0"),
                "vector_string": cvss_data.get("vectorString"),
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
                "base_score": cvss_data.get("baseScore", 0.0),
                "base_severity": cvss_data.get("baseSeverity", "NONE"),
                "exploitability_score": primary.get("exploitabilityScore"),
                "impact_score": primary.get("impactScore")
            }
            if not normalized["cvss_score"]:
                normalized["cvss_score"] = cvss_data.get("baseScore", 0.0)
                normalized["cvss_severity"] = cvss_data.get("baseSeverity", "NONE")
                normalized["cvss_vector"] = cvss_data.get("vectorString")
        
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            primary = next((m for m in cvss_v2 if m.get("type") == "Primary"), cvss_v2[0])
            cvss_data = primary.get("cvssData", {})
            normalized["metrics"]["cvss_v2"] = {
                "version": cvss_data.get("version", "2.0"),
                "vector_string": cvss_data.get("vectorString"),
                "access_vector": cvss_data.get("accessVector"),
                "access_complexity": cvss_data.get("accessComplexity"),
                "authentication": cvss_data.get("authentication"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
                "base_score": cvss_data.get("baseScore", 0.0),
                "exploitability_score": primary.get("exploitabilityScore"),
                "impact_score": primary.get("impactScore"),
                "ac_insuf_info": primary.get("acInsufInfo"),
                "obtain_all_privilege": primary.get("obtainAllPrivilege"),
                "obtain_user_privilege": primary.get("obtainUserPrivilege"),
                "obtain_other_privilege": primary.get("obtainOtherPrivilege"),
                "user_interaction_required": primary.get("userInteractionRequired")
            }
            if not normalized["cvss_score"]:
                normalized["cvss_score"] = cvss_data.get("baseScore", 0.0)
                normalized["cvss_severity"] = get_severity_from_score(cvss_data.get("baseScore", 0.0))
                normalized["cvss_vector"] = cvss_data.get("vectorString")
        
        weaknesses = raw_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_value = desc.get("value", "")
                if cwe_value and cwe_value != "NVD-CWE-noinfo" and cwe_value != "NVD-CWE-Other":
                    normalized["weaknesses"].append({
                        "type": weakness.get("type"),
                        "source": weakness.get("source"),
                        "cwe_id": cwe_value
                    })
        
        configurations = raw_data.get("configurations", [])
        for config in configurations:
            nodes = []
            for node in config.get("nodes", []):
                cpe_matches = []
                for cpe in node.get("cpeMatch", []):
                    cpe_matches.append({
                        "vulnerable": cpe.get("vulnerable"),
                        "criteria": cpe.get("criteria"),
                        "version_start_including": cpe.get("versionStartIncluding"),
                        "version_start_excluding": cpe.get("versionStartExcluding"),
                        "version_end_including": cpe.get("versionEndIncluding"),
                        "version_end_excluding": cpe.get("versionEndExcluding"),
                        "match_criteria_id": cpe.get("matchCriteriaId")
                    })
                nodes.append({
                    "operator": node.get("operator"),
                    "negate": node.get("negate"),
                    "cpe_match": cpe_matches
                })
            if nodes:
                normalized["configurations"].append({"nodes": nodes})
        
        references = raw_data.get("references", [])
        for ref in references:
            normalized["references"].append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })
        
        vendor_comments = raw_data.get("vendorComments", [])
        for comment in vendor_comments:
            normalized["vendor_comments"].append({
                "organization": comment.get("organization"),
                "comment": comment.get("comment"),
                "last_modified": comment.get("lastModified")
            })
        
        if any([
            raw_data.get("cisaExploitAdd"),
            raw_data.get("cisaActionDue"),
            raw_data.get("cisaRequiredAction"),
            raw_data.get("cisaVulnerabilityName")
        ]):
            normalized["cisa_kev"] = {
                "exploit_add": raw_data.get("cisaExploitAdd"),
                "action_due": raw_data.get("cisaActionDue"),
                "required_action": raw_data.get("cisaRequiredAction"),
                "vulnerability_name": raw_data.get("cisaVulnerabilityName")
            }
        
        return normalized
    
    def close(self):
        self.session.close()
