import requests
import time
import logging
from typing import Dict, Optional, Any, List
from datetime import datetime
from vulns import VulnerabilityDatabase

class NVDClient:
    """Cliente para interação com a API NVD 2.0 integrado com banco de dados"""
    
    def __init__(self, api_key: str, database_url: str = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.history_url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
        
        # Handle development mode
        if api_key == "development-mode":
            self.headers = {
                'User-Agent': 'bnvd/1.1',
                'Accept': 'application/json'
            }
            self.min_request_interval = 6.0  # Still respect rate limits
        else:
            self.headers = {
                'apiKey': api_key,
                'User-Agent': 'bnvd/1.1',
                'Accept': 'application/json'
            }
            # Com API key: 50 requests per 30 seconds, sem API key: 5 requests per 30 seconds
            self.min_request_interval = 0.6  # 600ms between requests
            
        self.last_request_time = 0
        
        # Inicializar banco de dados se URL fornecida
        self.db = None
        if database_url:
            try:
                self.db = VulnerabilityDatabase(database_url)
                logging.info("Banco de dados integrado ao NVDClient")
            except Exception as e:
                logging.warning(f"Erro ao inicializar banco de dados: {e}")
    
    def _rate_limit(self):
        """Implementa rate limiting para respeitar limites da API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, url: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Faz uma requisição para a API NVD com rate limiting e error handling aprimorado"""
        self._rate_limit()
        
        try:
            logging.debug(f"Fazendo requisição NVD para {url} com parâmetros: {params}")
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            logging.debug(f"Status da resposta: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                # Verifica se há resultados mesmo com status 200
                if 'vulnerabilities' in data and len(data['vulnerabilities']) == 0:
                    logging.info("Requisição bem-sucedida mas sem resultados encontrados")
                return data
            elif response.status_code == 400:
                logging.error(f"Parâmetros inválidos na requisição: {response.text}")
                raise Exception("Parâmetros de busca inválidos")
            elif response.status_code == 403:
                logging.error("Chave de API inválida ou limite de requisições excedido")
                raise Exception("Erro de autenticação ou limite de requisições excedido")
            elif response.status_code == 404:
                logging.warning("Nenhum resultado encontrado")
                return {'vulnerabilities': [], 'totalResults': 0}
            elif response.status_code == 503:
                logging.error("Serviço NVD temporariamente indisponível")
                raise Exception("Serviço NVD temporariamente indisponível. Tente novamente em alguns minutos.")
            else:
                logging.error(f"Erro na API NVD: {response.status_code} - {response.text}")
                response.raise_for_status()
                
        except requests.exceptions.Timeout:
            logging.error("Timeout na requisição à API NVD")
            raise Exception("Timeout na requisição à API NVD")
        except requests.exceptions.ConnectionError:
            logging.error("Erro de conexão com a API NVD")
            raise Exception("Erro de conexão com a API NVD. Verifique sua conexão com a internet.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro na requisição à API NVD: {str(e)}")
            raise Exception(f"Erro ao conectar com a API NVD: {str(e)}")
    
    def search_cves(self, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Busca CVEs com parâmetros especificados da API NVD 2.0
        
        Parâmetros suportados:
        - cveId: ID específico do CVE (CVE-YYYY-NNNN)
        - cpeName: Nome CPE para filtrar por produto específico
        - cveTag: Filtrar por tags (disputed, unsupported-when-assigned, exclusively-hosted-service)
        - cvssV2Metrics: String de vetor CVSS v2 (completa ou parcial)
        - cvssV2Severity: Severidade CVSS v2 (LOW, MEDIUM, HIGH)
        - cvssV3Metrics: String de vetor CVSS v3 (completa ou parcial)
        - cvssV3Severity: Severidade CVSS v3 (LOW, MEDIUM, HIGH, CRITICAL)
        - cvssV4Metrics: String de vetor CVSS v4 (completa ou parcial)
        - cvssV4Severity: Severidade CVSS v4 (LOW, MEDIUM, HIGH, CRITICAL)
        - cweId: ID da Common Weakness Enumeration (CWE-XXX)
        - hasCertAlerts: Filtrar CVEs com alertas técnicos US-CERT (sem valor)
        - hasCertNotes: Filtrar CVEs com notas de vulnerabilidade CERT/CC (sem valor)
        - hasKev: Filtrar CVEs no catálogo CISA KEV (sem valor)
        - hasOval: Filtrar CVEs com registros OVAL (sem valor)
        - isVulnerable: Filtrar CPEs vulneráveis (requer cpeName, sem valor)
        - keywordExactMatch: Busca frase exata (requer keywordSearch, sem valor)
        - keywordSearch: Busca por palavras-chave na descrição
        - lastModStartDate/lastModEndDate: Filtros de data de última modificação (ISO-8601)
        - noRejected: Excluir CVEs rejeitados (sem valor)
        - pubStartDate/pubEndDate: Filtros de data de publicação (ISO-8601)
        - resultsPerPage: Número de resultados por página (máx 2000)
        - sourceIdentifier: Identificador da fonte (ex: cve@mitre.org)
        - startIndex: Índice inicial para paginação
        - versionEnd/versionEndType: Filtro de versão final (including/excluding)
        - versionStart/versionStartType: Filtro de versão inicial (including/excluding)
        - virtualMatchString: String de correspondência CPE mais ampla
        """
        # Validar parâmetros mutuamente exclusivos
        cvss_metrics = [k for k in kwargs.keys() if k.endswith('Metrics')]
        if len(cvss_metrics) > 1:
            raise ValueError("Apenas um tipo de CVSS Metrics pode ser usado por vez")
        
        cvss_severity = [k for k in kwargs.keys() if k.endswith('Severity')]
        if len(cvss_severity) > 1:
            raise ValueError("Apenas um tipo de CVSS Severity pode ser usado por vez")
        
        # Validar parâmetros dependentes
        if kwargs.get('isVulnerable') and not kwargs.get('cpeName'):
            raise ValueError("isVulnerable requer cpeName")
        
        if kwargs.get('keywordExactMatch') and not kwargs.get('keywordSearch'):
            raise ValueError("keywordExactMatch requer keywordSearch")
        
        if kwargs.get('versionEnd') and not kwargs.get('virtualMatchString'):
            raise ValueError("versionEnd requer virtualMatchString")
        
        if kwargs.get('versionStart') and not kwargs.get('virtualMatchString'):
            raise ValueError("versionStart requer virtualMatchString")
        
        # Validar formato de datas
        date_params = ['pubStartDate', 'pubEndDate', 'lastModStartDate', 'lastModEndDate']
        for param in date_params:
            if param in kwargs and kwargs[param]:
                try:
                    # Validar formato ISO-8601 básico
                    if 'T' not in kwargs[param]:
                        raise ValueError(f"{param} deve estar no formato ISO-8601 (YYYY-MM-DDTHH:MM:SS.sssZ)")
                except:
                    raise ValueError(f"Formato de data inválido para {param}")
        
        # Validar ranges de data
        if (kwargs.get('pubStartDate') and kwargs.get('pubEndDate')) or \
           (kwargs.get('lastModStartDate') and kwargs.get('lastModEndDate')):
            # Verificar se ambas as datas estão presentes quando uma é especificada
            if kwargs.get('pubStartDate') and not kwargs.get('pubEndDate'):
                raise ValueError("pubEndDate é obrigatório quando pubStartDate é especificado")
            if kwargs.get('pubEndDate') and not kwargs.get('pubStartDate'):
                raise ValueError("pubStartDate é obrigatório quando pubEndDate é especificado")
            if kwargs.get('lastModStartDate') and not kwargs.get('lastModEndDate'):
                raise ValueError("lastModEndDate é obrigatório quando lastModStartDate é especificado")
            if kwargs.get('lastModEndDate') and not kwargs.get('lastModStartDate'):
                raise ValueError("lastModStartDate é obrigatório quando lastModEndDate é especificado")
        
        # Validar severidades
        valid_v2_severities = ['LOW', 'MEDIUM', 'HIGH']
        valid_v3_v4_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        if kwargs.get('cvssV2Severity') and kwargs['cvssV2Severity'].upper() not in valid_v2_severities:
            raise ValueError(f"cvssV2Severity deve ser: {', '.join(valid_v2_severities)}")
        
        if kwargs.get('cvssV3Severity') and kwargs['cvssV3Severity'].upper() not in valid_v3_v4_severities:
            raise ValueError(f"cvssV3Severity deve ser: {', '.join(valid_v3_v4_severities)}")
        
        if kwargs.get('cvssV4Severity') and kwargs['cvssV4Severity'].upper() not in valid_v3_v4_severities:
            raise ValueError(f"cvssV4Severity deve ser: {', '.join(valid_v3_v4_severities)}")
        
        # Limpar parâmetros vazios e normalizar
        params = {}
        for k, v in kwargs.items():
            if v is not None and v != '':
                # Normalizar severidades para uppercase
                if k.endswith('Severity') and isinstance(v, str):
                    params[k] = v.upper()
                elif k == 'cveId' and isinstance(v, str):
                    # Normalizar CVE ID para uppercase
                    params[k] = v.upper()
                elif k == 'cweId' and isinstance(v, str):
                    # Normalizar CWE ID
                    cwe_id = v.upper()
                    if not cwe_id.startswith('CWE-'):
                        cwe_id = f"CWE-{cwe_id}"
                    params[k] = cwe_id
                else:
                    params[k] = v
        
        return self._make_request(self.base_url, params)
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Busca um CVE específico pelo ID, primeiro no banco, depois na API
        Implementa o sistema transparente de cache/atualização
        """
        if not self.db:
            # Se não há banco, buscar diretamente na API
            return self.search_cves(cveId=cve_id)
        
        try:
            # STEP 1: Verificar se existe no banco
            db_vuln = self.db.get_vulnerability_by_cve_id(cve_id)
            
            if db_vuln:
                logging.info(f"CVE {cve_id} encontrado no banco de dados")
                
                # STEP 2: Buscar dados atualizados da API para comparar datas
                try:
                    api_response = self.search_cves(cveId=cve_id)
                    if api_response and 'vulnerabilities' in api_response and len(api_response['vulnerabilities']) > 0:
                        api_vuln = api_response['vulnerabilities'][0]
                        api_last_modified = self._parse_date(api_vuln['cve'].get('lastModified'))
                        db_last_modified = db_vuln.get('last_modified')
                        
                        # STEP 3: Comparar datas de modificação - se JSON for maior, atualiza
                        if api_last_modified and db_last_modified:
                            if api_last_modified > db_last_modified:
                                logging.info(f"CVE {cve_id} desatualizado no banco")
                                logging.info(f"  API: {api_vuln['cve'].get('lastModified')}")
                                logging.info(f"  Banco: {db_last_modified}")
                                logging.info(f"Atualizando vulnerabilidade no banco...")
                                
                                # Atualizar banco com dados mais recentes da API
                                if self.db.insert_or_update_vulnerability(api_vuln['cve']):
                                    logging.info(f"CVE {cve_id} atualizado no banco com sucesso")
                                    return api_response
                                else:
                                    logging.warning(f"Falha ao atualizar CVE {cve_id} no banco")
                                    return api_response
                            else:
                                logging.info(f"CVE {cve_id} está atualizado no banco")
                                logging.info(f"  API: {api_vuln['cve'].get('lastModified')}")
                                logging.info(f"  Banco: {db_last_modified}")
                                # Retornar dados do banco - estão atualizados
                                return self._convert_db_to_api_format(db_vuln)
                        else:
                            logging.info(f"CVE {cve_id} sem comparação de datas, usando dados do banco")
                            return self._convert_db_to_api_format(db_vuln)
                    else:
                        logging.warning(f"CVE {cve_id} não encontrado na API, usando dados do banco")
                        return self._convert_db_to_api_format(db_vuln)
                        
                except Exception as e:
                    logging.warning(f"Erro ao verificar atualizações da API para {cve_id}: {e}")
                    # Se falhou na API, usar dados do banco
                    return self._convert_db_to_api_format(db_vuln)
            
            # STEP 4: Se não existe no banco, buscar na API
            logging.info(f"CVE {cve_id} não encontrado no banco, buscando na API")
            api_response = self.search_cves(cveId=cve_id)
            
            if api_response and 'vulnerabilities' in api_response and len(api_response['vulnerabilities']) > 0:
                api_vuln = api_response['vulnerabilities'][0]
                
                # STEP 5: Salvar no banco organizando por ano automaticamente
                cve_year = self.db._extract_year_from_cve_id(cve_id)
                logging.info(f"CVE {cve_id} do ano {cve_year} - salvando no banco")
                
                if self.db.insert_or_update_vulnerability(api_vuln['cve']):
                    logging.info(f"CVE {cve_id} salvo no banco de dados")
                else:
                    logging.warning(f"Falha ao salvar CVE {cve_id} no banco")
                
                return api_response
            else:
                logging.warning(f"CVE {cve_id} não encontrado na API")
                return None
                
        except Exception as e:
            logging.error(f"Erro ao buscar CVE {cve_id}: {e}")
            # Fallback para API se houver erro
            return self.search_cves(cveId=cve_id)
    
    def search_cve_history(self, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Busca histórico de mudanças de CVEs
        
        Parâmetros suportados:
        - changeStartDate/changeEndDate: Filtros de data de mudança (ISO-8601, obrigatórios)
        - cveId: ID específico do CVE para buscar histórico
        - eventName: Tipo de evento (Initial Analysis, CVE Modified, CVE Translated, etc.)
        - resultsPerPage: Número de resultados por página (máx 5000)
        - startIndex: Índice inicial para paginação
        """
        # Validar parâmetros obrigatórios
        if not kwargs.get('changeStartDate') or not kwargs.get('changeEndDate'):
            raise ValueError("changeStartDate e changeEndDate são obrigatórios para busca de histórico")
        
        # Limpar parâmetros vazios
        params = {k: v for k, v in kwargs.items() if v is not None and v != ''}
        
        return self._make_request(self.history_url, params)
    
    def get_cves_by_year(self, year: int, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs por ano de publicação"""
        return self.search_cves(
            pubStartDate=f"{year}-01-01T00:00:00.000",
            pubEndDate=f"{year}-12-31T23:59:59.999",
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def get_cves_by_vendor(self, vendor: str, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs por vendor/fabricante usando keyword search"""
        return self.search_cves(
            keywordSearch=vendor,
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def get_cves_by_severity(self, severity: str, cvss_version: str = "v3", start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs por severidade CVSS"""
        severity = severity.upper()
        
        if cvss_version.lower() == "v2":
            if severity not in ['LOW', 'MEDIUM', 'HIGH']:
                raise ValueError("Severidade CVSS v2 deve ser: LOW, MEDIUM, HIGH")
            return self.search_cves(
                cvssV2Severity=severity,
                startIndex=start_index,
                resultsPerPage=results_per_page
            )
        elif cvss_version.lower() == "v3":
            if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                raise ValueError("Severidade CVSS v3 deve ser: LOW, MEDIUM, HIGH, CRITICAL")
            return self.search_cves(
                cvssV3Severity=severity,
                startIndex=start_index,
                resultsPerPage=results_per_page
            )
        elif cvss_version.lower() == "v4":
            if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                raise ValueError("Severidade CVSS v4 deve ser: LOW, MEDIUM, HIGH, CRITICAL")
            return self.search_cves(
                cvssV4Severity=severity,
                startIndex=start_index,
                resultsPerPage=results_per_page
            )
        else:
            raise ValueError("Versão CVSS deve ser: v2, v3 ou v4")
    
    def get_cves_by_cpe(self, cpe_name: str, is_vulnerable: bool = False, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs por CPE name específico"""
        params = {
            'cpeName': cpe_name,
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        if is_vulnerable:
            params['isVulnerable'] = True
        
        return self.search_cves(**params)
    
    def get_cves_by_cwe(self, cwe_id: str, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs por CWE ID"""
        return self.search_cves(
            cweId=cwe_id,
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def get_recent_cves(self, days: int = 7, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs publicados nos últimos N dias"""
        from datetime import datetime, timedelta
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return self.search_cves(
            pubStartDate=start_date.strftime("%Y-%m-%dT00:00:00.000"),
            pubEndDate=end_date.strftime("%Y-%m-%dT23:59:59.999"),
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def get_modified_cves(self, days: int = 7, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs modificados nos últimos N dias"""
        from datetime import datetime, timedelta
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return self.search_cves(
            lastModStartDate=start_date.strftime("%Y-%m-%dT00:00:00.000"),
            lastModEndDate=end_date.strftime("%Y-%m-%dT23:59:59.999"),
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def get_kev_cves(self, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs que estão no catálogo CISA KEV (Known Exploited Vulnerabilities)"""
        return self.search_cves(
            hasKev=True,
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def search_keyword_exact(self, phrase: str, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict[str, Any]]:
        """Busca CVEs com frase exata na descrição"""
        return self.search_cves(
            keywordSearch=phrase,
            keywordExactMatch=True,
            startIndex=start_index,
            resultsPerPage=results_per_page
        )
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Converte string de data ISO para datetime"""
        if not date_str:
            return None
        
        try:
            # Remove timezone info se presente e converte
            if date_str.endswith('Z'):
                date_str = date_str[:-1] + '+00:00'
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception as e:
            logging.warning(f"Erro ao converter data {date_str}: {e}")
            return None
    
    def _convert_db_to_api_format(self, db_vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converte dados do banco para formato da API NVD
        
        Args:
            db_vuln: Dados da vulnerabilidade do banco
            
        Returns:
            Dicionário no formato da API NVD
        """
        try:
            # Se raw_data existe, usar diretamente
            if db_vuln.get('raw_data'):
                return {'vulnerabilities': [db_vuln['raw_data']], 'totalResults': 1}
            
            # Caso contrário, reconstruir formato da API
            cve_data = {
                'cve': {
                    'id': db_vuln['cve_id'],
                    'published': db_vuln['published_date'].isoformat() if db_vuln.get('published_date') else None,
                    'lastModified': db_vuln['last_modified'].isoformat() if db_vuln.get('last_modified') else None,
                    'vulnStatus': db_vuln.get('vulnstatus', ''),
                    'descriptions': db_vuln.get('descriptions', []),
                    'metrics': db_vuln.get('cvss_metrics', {}),
                    'weaknesses': db_vuln.get('weaknesses', []),
                    'configurations': db_vuln.get('configurations', []),
                    'references': db_vuln.get('references', []),
                    'sourceIdentifier': db_vuln.get('source_identifier', '')
                }
            }
            
            return {'vulnerabilities': [cve_data], 'totalResults': 1}
            
        except Exception as e:
            logging.error(f"Erro ao converter dados do banco para formato API: {e}")
            return {'vulnerabilities': [], 'totalResults': 0}
