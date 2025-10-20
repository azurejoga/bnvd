/**
 * BNVD API Client - JavaScript (ES6+)
 * Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
 * @version 1.0.0
 */

class BNVDClient {
  constructor(config = {}) {
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
  async request(endpoint, params = {}) {
    const url = new URL(endpoint, this.config.baseUrl);
    
    Object.keys(params).forEach(key => {
      if (params[key] !== undefined && params[key] !== null) {
        url.searchParams.append(key, String(params[key]));
      }
    });

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
      if (error.name === 'AbortError') {
        throw new Error('Request timeout');
      }
      throw error;
    }
  }

  /**
   * Retorna informações sobre a API
   */
  async getAPIInfo() {
    return this.request('/api/v1/');
  }

  /**
   * Lista todas as vulnerabilidades com suporte a paginação e filtros
   */
  async listVulnerabilities(params = {}) {
    return this.request('/api/v1/vulnerabilities', params);
  }

  /**
   * Busca uma vulnerabilidade específica pelo CVE ID
   */
  async getVulnerability(cveId, includePt = true) {
    return this.request(`/api/v1/vulnerabilities/${cveId}`, {
      include_pt: includePt,
    });
  }

  /**
   * Busca vulnerabilidades recentes
   */
  async getRecentVulnerabilities(params = {}) {
    return this.request('/api/v1/search/recent', params);
  }

  /**
   * Retorna as 5 vulnerabilidades mais recentes
   */
  async getTop5Recent(includePt = true) {
    return this.request('/api/v1/search/recent/5', {
      include_pt: includePt,
    });
  }

  /**
   * Busca vulnerabilidades por ano
   */
  async searchByYear(year, params = {}) {
    return this.request(`/api/v1/search/year/${year}`, params);
  }

  /**
   * Busca vulnerabilidades por severidade
   */
  async searchBySeverity(severity, params = {}) {
    return this.request(`/api/v1/search/severity/${severity}`, params);
  }

  /**
   * Busca vulnerabilidades por vendor/fabricante
   */
  async searchByVendor(vendor, params = {}) {
    return this.request(`/api/v1/search/vendor/${vendor}`, params);
  }

  /**
   * Retorna estatísticas gerais
   */
  async getStats() {
    return this.request('/api/v1/stats');
  }

  /**
   * Retorna estatísticas por ano
   */
  async getYearStats() {
    return this.request('/api/v1/stats/years');
  }

  /**
   * Busca CVEs recentes pela API pública (limitada)
   */
  async getPublicRecentCVEs(params = {}) {
    return this.request('/api/cves/recent', params);
  }

  /**
   * Busca CVEs do catálogo CISA KEV pela API pública (limitada)
   */
  async getPublicKEVCVEs() {
    return this.request('/api/cves/kev');
  }

  /**
   * Lista todas as notícias de segurança cibernética
   */
  async listNoticias(params = {}) {
    return this.request('/api/v1/noticias', params);
  }

  /**
   * Retorna as notícias mais recentes
   */
  async getRecentNoticias(limit = 5) {
    return this.request('/api/v1/noticias/recentes', { limit });
  }

  /**
   * Retorna uma notícia específica pelo slug
   */
  async getNoticiaBySlug(slug) {
    return this.request(`/api/v1/noticias/${slug}`);
  }

  /**
   * Informações sobre endpoints MITRE ATT&CK
   */
  async getMitreInfo() {
    return this.request('/api/v1/mitre');
  }

  /**
   * Lista todas as matrizes MITRE ATT&CK disponíveis
   */
  async listMitreMatrices() {
    return this.request('/api/v1/mitre/matrices');
  }

  /**
   * Retorna dados completos de uma matriz MITRE ATT&CK
   */
  async getMitreMatrix(matrixType, translate = false) {
    return this.request(`/api/v1/mitre/matrix/${matrixType}`, { translate });
  }

  /**
   * Lista todas as técnicas MITRE ATT&CK
   */
  async listMitreTechniques(params = {}) {
    return this.request('/api/v1/mitre/techniques', params);
  }

  /**
   * Retorna detalhes de uma técnica específica
   */
  async getMitreTechnique(techniqueId, params = {}) {
    return this.request(`/api/v1/mitre/technique/${techniqueId}`, params);
  }

  /**
   * Lista todas as subtécnicas MITRE ATT&CK
   */
  async listMitreSubtechniques(params = {}) {
    return this.request('/api/v1/mitre/subtechniques', params);
  }

  /**
   * Lista todos os grupos de ameaças MITRE ATT&CK
   */
  async listMitreGroups(params = {}) {
    return this.request('/api/v1/mitre/groups', params);
  }

  /**
   * Retorna detalhes de um grupo específico
   */
  async getMitreGroup(groupId, params = {}) {
    return this.request(`/api/v1/mitre/group/${groupId}`, params);
  }

  /**
   * Lista todas as mitigações MITRE ATT&CK
   */
  async listMitreMitigations(params = {}) {
    return this.request('/api/v1/mitre/mitigations', params);
  }

  /**
   * Retorna detalhes de uma mitigação específica
   */
  async getMitreMitigation(mitigationId, params = {}) {
    return this.request(`/api/v1/mitre/mitigation/${mitigationId}`, params);
  }
}

// Export para módulos ES6
export default BNVDClient;

// Export para CommonJS (Node.js)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BNVDClient;
  module.exports.BNVDClient = BNVDClient;
}
