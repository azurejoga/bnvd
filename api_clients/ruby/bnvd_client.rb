# frozen_string_literal: true

# BNVD API Client - Ruby
# Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
# @version 1.0.0

require 'net/http'
require 'json'
require 'uri'

module BNVD
  # Níveis de severidade CVSS
  module Severity
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'
  end

  # Configuração do cliente
  class Config
    attr_accessor :base_url, :timeout, :headers

    def initialize(base_url: 'https://bnvd.org/api/v1', timeout: 30, headers: {})
      @base_url = base_url
      @timeout = timeout
      @headers = {
        'Content-Type' => 'application/json'
      }.merge(headers)
    end
  end

  # Parâmetros de paginação
  class PaginationParams
    attr_accessor :page, :per_page

    def initialize(page: nil, per_page: nil)
      @page = page
      @per_page = per_page
    end

    def to_query_params
      params = {}
      params['page'] = @page.to_s if @page
      params['per_page'] = @per_page.to_s if @per_page
      params
    end
  end

  # Parâmetros de busca
  class SearchParams < PaginationParams
    attr_accessor :year, :severity, :vendor, :include_pt

    def initialize(page: nil, per_page: nil, year: nil, severity: nil, vendor: nil, include_pt: true)
      super(page: page, per_page: per_page)
      @year = year
      @severity = severity
      @vendor = vendor
      @include_pt = include_pt
    end

    def to_query_params
      params = super
      params['year'] = @year.to_s if @year
      params['severity'] = @severity if @severity
      params['vendor'] = @vendor if @vendor
      params['include_pt'] = @include_pt.to_s if @include_pt
      params
    end
  end

  # Parâmetros de busca recente
  class RecentSearchParams < PaginationParams
    attr_accessor :days, :include_pt

    def initialize(page: nil, per_page: nil, days: nil, include_pt: true)
      super(page: page, per_page: per_page)
      @days = days
      @include_pt = include_pt
    end

    def to_query_params
      params = super
      params['days'] = @days.to_s if @days
      params['include_pt'] = @include_pt.to_s if @include_pt
      params
    end
  end

  # Resposta da API
  class APIResponse
    attr_reader :status, :data, :message, :pagination

    def initialize(json)
      @status = json['status']
      @data = json['data']
      @message = json['message']
      @pagination = json['pagination']
    end

    def success?
      @status == 'success'
    end

    def error?
      @status == 'error'
    end
  end

  # Cliente da API BNVD
  class Client
    def initialize(config)
      @config = config
    end

    # Faz requisição HTTP para a API
    def request(endpoint, params = {})
      uri = URI.parse(@config.base_url + endpoint)
      uri.query = URI.encode_www_form(params) unless params.empty?

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.read_timeout = @config.timeout

      request = Net::HTTP::Get.new(uri.request_uri)
      @config.headers.each { |key, value| request[key] = value }

      response = http.request(request)

      case response
      when Net::HTTPSuccess
        APIResponse.new(JSON.parse(response.body))
      else
        raise "HTTP Error: #{response.code} #{response.message}"
      end
    end

    # Retorna informações sobre a API
    def get_api_info
      request('/api/v1/')
    end

    # Lista todas as vulnerabilidades com suporte a paginação e filtros
    def list_vulnerabilities(params = SearchParams.new)
      query_params = params.is_a?(SearchParams) ? params.to_query_params : params
      request('/api/v1/vulnerabilities', query_params)
    end

    # Busca uma vulnerabilidade específica pelo CVE ID
    def get_vulnerability(cve_id, include_pt: true)
      request("/api/v1/vulnerabilities/#{cve_id}", { include_pt: include_pt })
    end

    # Busca vulnerabilidades recentes
    def get_recent_vulnerabilities(params = RecentSearchParams.new)
      query_params = params.is_a?(RecentSearchParams) ? params.to_query_params : params
      request('/api/v1/search/recent', query_params)
    end

    # Retorna as 5 vulnerabilidades mais recentes
    def get_top5_recent(include_pt: true)
      request('/api/v1/search/recent/5', { include_pt: include_pt })
    end

    # Busca vulnerabilidades por ano
    def search_by_year(year, params = PaginationParams.new)
      query_params = params.is_a?(PaginationParams) ? params.to_query_params : params
      request("/api/v1/search/year/#{year}", query_params)
    end

    # Busca vulnerabilidades por severidade
    def search_by_severity(severity, params = PaginationParams.new)
      query_params = params.is_a?(PaginationParams) ? params.to_query_params : params
      request("/api/v1/search/severity/#{severity}", query_params)
    end

    # Busca vulnerabilidades por vendor/fabricante
    def search_by_vendor(vendor, params = PaginationParams.new)
      query_params = params.is_a?(PaginationParams) ? params.to_query_params : params
      request("/api/v1/search/vendor/#{vendor}", query_params)
    end

    # Retorna estatísticas gerais
    def get_stats
      request('/api/v1/stats')
    end

    # Retorna estatísticas por ano
    def get_year_stats
      request('/api/v1/stats/years')
    end

    # === Notícias ===

    # Lista todas as notícias
    def list_noticias(params = PaginationParams.new)
      query_params = params.is_a?(PaginationParams) ? params.to_query_params : params
      request('/api/v1/noticias', query_params)
    end

    # Retorna notícias recentes
    def get_recent_noticias(limit = 5)
      request("/api/v1/noticias/recentes/#{limit}")
    end

    # Busca notícia por slug
    def get_noticia_by_slug(slug)
      request("/api/v1/noticias/#{slug}")
    end

    # === MITRE ATT&CK ===

    # Retorna informações sobre o sistema MITRE ATT&CK
    def get_mitre_info
      request('/api/v1/mitre')
    end

    # Lista todas as matrizes MITRE ATT&CK disponíveis
    def list_mitre_matrices
      request('/api/v1/mitre/matrices')
    end

    # Retorna uma matriz específica
    def get_mitre_matrix(matrix_name, include_pt = true)
      request("/api/v1/mitre/matrix/#{matrix_name}", { include_pt: include_pt })
    end

    # Lista todas as técnicas MITRE ATT&CK
    def list_mitre_techniques(params = {})
      request('/api/v1/mitre/techniques', params)
    end

    # Retorna detalhes de uma técnica específica
    def get_mitre_technique(technique_id, include_pt = true)
      request("/api/v1/mitre/technique/#{technique_id}", { include_pt: include_pt })
    end

    # Lista todas as subtécnicas MITRE ATT&CK
    def list_mitre_subtechniques(params = {})
      request('/api/v1/mitre/subtechniques', params)
    end

    # Lista todos os grupos de ameaças MITRE ATT&CK
    def list_mitre_groups(params = {})
      request('/api/v1/mitre/groups', params)
    end

    # Retorna detalhes de um grupo específico
    def get_mitre_group(group_id, include_pt = true)
      request("/api/v1/mitre/group/#{group_id}", { include_pt: include_pt })
    end

    # Lista todas as mitigações MITRE ATT&CK
    def list_mitre_mitigations(params = {})
      request('/api/v1/mitre/mitigations', params)
    end

    # Retorna detalhes de uma mitigação específica
    def get_mitre_mitigation(mitigation_id, include_pt = true)
      request("/api/v1/mitre/mitigation/#{mitigation_id}", { include_pt: include_pt })
    end
  end
end