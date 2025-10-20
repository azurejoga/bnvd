/**
 * BNVD API Client - TypeScript
 * Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
 * @version 1.0.0
 */

export interface BNVDConfig {
  baseUrl: string;
  timeout?: number;
  headers?: Record<string, string>;
}

export interface PaginationParams {
  page?: number;
  per_page?: number;
}

export interface SearchParams extends PaginationParams {
  year?: number;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vendor?: string;
  include_pt?: boolean;
}

export interface RecentSearchParams extends PaginationParams {
  days?: number;
  include_pt?: boolean;
}

export interface CVEDescription {
  lang: string;
  value: string;
  value_pt?: string;
}

export interface CVSSMetric {
  source?: string;
  type?: string;
  cvssData?: {
    version?: string;
    vectorString?: string;
    baseScore?: number;
    baseSeverity?: string;
  };
}

export interface CVEReference {
  url: string;
  source?: string;
  tags?: string[];
}

export interface CVEData {
  id: string;
  sourceIdentifier?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: CVEDescription[];
  metrics?: {
    cvssMetricV31?: CVSSMetric[];
    cvssMetricV30?: CVSSMetric[];
    cvssMetricV2?: CVSSMetric[];
  };
  weaknesses?: Array<{
    source?: string;
    type?: string;
    description?: Array<{
      lang: string;
      value: string;
    }>;
  }>;
  references?: CVEReference[];
}

export interface Vulnerability {
  cve: CVEData;
}

export interface APIResponse<T> {
  status: 'success' | 'error';
  data?: T;
  message?: string;
  pagination?: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

export interface StatsData {
  total_vulnerabilities: number;
  by_severity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  by_year: Record<string, number>;
  last_updated: string;
}

export interface YearStats {
  year: number;
  total: number;
  by_severity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  by_month: Record<string, number>;
}

export class BNVDClient {
  private config: BNVDConfig;

  constructor(config: Partial<BNVDConfig> = {}) {
    this.config = {
      baseUrl: 'https://bnvd.org/api/v1',
      timeout: 30000,
      ...config,
      headers: {
        'Content-Type': 'application/json',
        ...(config.headers || {}),
      },
    };
  }

  /**
   * Faz requisição HTTP para a API
   */
  private async request<T>(
    endpoint: string,
    params?: Record<string, any>
  ): Promise<APIResponse<T>> {
    const url = new URL(endpoint, this.config.baseUrl);
    
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== undefined && params[key] !== null) {
          url.searchParams.append(key, String(params[key]));
        }
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url.toString(), {
        method: 'GET',
        headers: this.config.headers,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeout);
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error('Request timeout');
        }
        throw error;
      }
      throw new Error('Unknown error occurred');
    }
  }

  /**
   * Retorna informações sobre a API
   */
  async getAPIInfo(): Promise<APIResponse<any>> {
    return this.request('/api/v1/');
  }

  /**
   * Lista todas as vulnerabilidades com suporte a paginação e filtros
   */
  async listVulnerabilities(params?: SearchParams): Promise<APIResponse<Vulnerability[]>> {
    return this.request('/api/v1/vulnerabilities', params);
  }

  /**
   * Busca uma vulnerabilidade específica pelo CVE ID
   */
  async getVulnerability(
    cveId: string,
    includePt: boolean = true
  ): Promise<APIResponse<Vulnerability>> {
    return this.request(`/api/v1/vulnerabilities/${cveId}`, {
      include_pt: includePt,
    });
  }

  /**
   * Busca vulnerabilidades recentes
   */
  async getRecentVulnerabilities(
    params?: RecentSearchParams
  ): Promise<APIResponse<Vulnerability[]>> {
    return this.request('/api/v1/search/recent', params);
  }

  /**
   * Retorna as 5 vulnerabilidades mais recentes
   */
  async getTop5Recent(includePt: boolean = true): Promise<APIResponse<Vulnerability[]>> {
    return this.request('/api/v1/search/recent/5', {
      include_pt: includePt,
    });
  }

  /**
   * Busca vulnerabilidades por ano
   */
  async searchByYear(
    year: number,
    params?: PaginationParams & { include_pt?: boolean }
  ): Promise<APIResponse<Vulnerability[]>> {
    return this.request(`/api/v1/search/year/${year}`, params);
  }

  /**
   * Busca vulnerabilidades por severidade
   */
  async searchBySeverity(
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    params?: PaginationParams & { include_pt?: boolean }
  ): Promise<APIResponse<Vulnerability[]>> {
    return this.request(`/api/v1/search/severity/${severity}`, params);
  }

  /**
   * Busca vulnerabilidades por vendor/fabricante
   */
  async searchByVendor(
    vendor: string,
    params?: PaginationParams & { include_pt?: boolean }
  ): Promise<APIResponse<Vulnerability[]>> {
    return this.request(`/api/v1/search/vendor/${vendor}`, params);
  }

  /**
   * Retorna estatísticas gerais
   */
  async getStats(): Promise<APIResponse<StatsData>> {
    return this.request('/api/v1/stats');
  }

  /**
   * Retorna estatísticas por ano
   */
  async getYearStats(): Promise<APIResponse<YearStats[]>> {
    return this.request('/api/v1/stats/years');
  }

  /**
   * Busca CVEs recentes pela API pública (limitada)
   */
  async getPublicRecentCVEs(params?: {
    days?: number;
    page?: number;
    per_page?: number;
    include_pt?: boolean;
  }): Promise<any> {
    return this.request('/api/cves/recent', params);
  }

  /**
   * Busca CVEs do catálogo CISA KEV pela API pública (limitada)
   */
  async getPublicKEVCVEs(): Promise<any> {
    return this.request('/api/cves/kev');
  }

  /**
   * Lista todas as notícias de segurança cibernética
   */
  async listNoticias(params?: Record<string, any>): Promise<any> {
    return this.request('/api/v1/noticias', params);
  }

  /**
   * Retorna as notícias mais recentes
   */
  async getRecentNoticias(limit: number = 5): Promise<any> {
    return this.request('/api/v1/noticias/recentes', { limit });
  }

  /**
   * Retorna uma notícia específica pelo slug
   */
  async getNoticiaBySlug(slug: string): Promise<any> {
    return this.request(`/api/v1/noticias/${slug}`);
  }

  /**
   * Informações sobre endpoints MITRE ATT&CK
   */
  async getMitreInfo(): Promise<any> {
    return this.request('/api/v1/mitre');
  }

  /**
   * Lista todas as matrizes MITRE ATT&CK disponíveis
   */
  async listMitreMatrices(): Promise<any> {
    return this.request('/api/v1/mitre/matrices');
  }

  /**
   * Retorna dados completos de uma matriz MITRE ATT&CK
   */
  async getMitreMatrix(matrixType: string, translate: boolean = false): Promise<any> {
    return this.request(`/api/v1/mitre/matrix/${matrixType}`, { translate });
  }

  /**
   * Lista todas as técnicas MITRE ATT&CK
   */
  async listMitreTechniques(params?: Record<string, any>): Promise<any> {
    return this.request('/api/v1/mitre/techniques', params);
  }

  /**
   * Retorna detalhes de uma técnica específica
   */
  async getMitreTechnique(techniqueId: string, params?: Record<string, any>): Promise<any> {
    return this.request(`/api/v1/mitre/technique/${techniqueId}`, params);
  }

  /**
   * Lista todas as subtécnicas MITRE ATT&CK
   */
  async listMitreSubtechniques(params?: Record<string, any>): Promise<any> {
    return this.request('/api/v1/mitre/subtechniques', params);
  }

  /**
   * Lista todos os grupos de ameaças MITRE ATT&CK
   */
  async listMitreGroups(params?: Record<string, any>): Promise<any> {
    return this.request('/api/v1/mitre/groups', params);
  }

  /**
   * Retorna detalhes de um grupo específico
   */
  async getMitreGroup(groupId: string, params?: Record<string, any>): Promise<any> {
    return this.request(`/api/v1/mitre/group/${groupId}`, params);
  }

  /**
   * Lista todas as mitigações MITRE ATT&CK
   */
  async listMitreMitigations(params?: Record<string, any>): Promise<any> {
    return this.request('/api/v1/mitre/mitigations', params);
  }

  /**
   * Retorna detalhes de uma mitigação específica
   */
  async getMitreMitigation(mitigationId: string, params?: Record<string, any>): Promise<any> {
    return this.request(`/api/v1/mitre/mitigation/${mitigationId}`, params);
  }
}

// Export para uso em CommonJS (Node.js)
export default BNVDClient;
