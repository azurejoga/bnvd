import requests
from urllib.parse import urlencode
from .exceptions import BNVDAPIError, BNVDConnectionError, BNVDInvalidResponse


class BNVDClient:
    BASE_URL = "https://bnvd.org/api/v1"

    def __init__(self, timeout=10, user_agent="bnvd-python-client/1.0"):
        self.session = requests.Session()
        self.timeout = timeout
        self.session.headers.update({"User-Agent": user_agent})

    def _handle_response(self, response):
        try:
            response.raise_for_status()
            json_data = response.json()
        except requests.exceptions.HTTPError as e:
            raise BNVDAPIError(str(e), response.status_code)
        except requests.exceptions.RequestException as e:
            raise BNVDConnectionError(str(e))
        except ValueError:
            raise BNVDInvalidResponse("Resposta não é JSON válido")

        if json_data.get("status") != "success":
            raise BNVDAPIError(json_data.get("message", "Erro desconhecido"), json_data.get("code", 400))

        return json_data.get("data", {})

    def _get(self, endpoint, params=None):
        url = f"{self.BASE_URL}{endpoint}"
        if params:
            query = urlencode({k: v for k, v in params.items() if v is not None})
            url = f"{url}?{query}"

        response = self.session.get(url, timeout=self.timeout)
        return self._handle_response(response)

    # Endpoints
    def get_endpoints(self):
        return self._get("/")

    def get_vulnerabilities(self, page=1, per_page=20, year=None, severity=None, vendor=None, include_pt=True):
        return self._get("/vulnerabilities", {
            "page": page,
            "per_page": per_page,
            "year": year,
            "severity": severity,
            "vendor": vendor,
            "include_pt": str(include_pt).lower(),
        })

    def get_vulnerability(self, cve_id):
        return self._get(f"/vulnerabilities/{cve_id}")

    def get_recent(self, days=None, page=1, per_page=20):
        return self._get("/search/recent", {
            "days": days,
            "page": page,
            "per_page": per_page
        })

    def get_by_year(self, year):
        return self._get(f"/search/year/{year}")

    def get_by_severity(self, severity):
        if severity.upper() not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise ValueError("Severidade inválida. Use: LOW, MEDIUM, HIGH, CRITICAL")
        return self._get(f"/search/severity/{severity.upper()}")

    def get_by_vendor(self, vendor):
        return self._get(f"/search/vendor/{vendor}")

    def get_stats(self):
        return self._get("/stats")

    def get_stats_by_year(self):
        return self._get("/stats/years")
