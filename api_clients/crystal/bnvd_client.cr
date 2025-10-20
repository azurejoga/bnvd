# BNVD API Client - Crystal
# Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
# @version 1.0.0

require "http/client"
require "json"
require "uri"

module BNVD
  alias Severity = String

  SEVERITY_LOW      = "LOW"
  SEVERITY_MEDIUM   = "MEDIUM"
  SEVERITY_HIGH     = "HIGH"
  SEVERITY_CRITICAL = "CRITICAL"

  class Config
    property base_url : String
    property timeout : Time::Span
    property headers : HTTP::Headers

    def initialize(@base_url : String = "https://bnvd.org/api/v1", @timeout : Time::Span = 30.seconds)
      @headers = HTTP::Headers{
        "Content-Type" => "application/json",
      }
    end
  end

  class PaginationParams
    property page : Int32?
    property per_page : Int32?

    def initialize(@page = nil, @per_page = nil)
    end

    def to_query_params : Hash(String, String)
      params = {} of String => String
      params["page"] = @page.to_s if @page
      params["per_page"] = @per_page.to_s if @per_page
      params
    end
  end

  class SearchParams < PaginationParams
    property year : Int32?
    property severity : String?
    property vendor : String?
    property include_pt : Bool?

    def initialize(@page = nil, @per_page = nil, @year = nil, @severity = nil, @vendor = nil, @include_pt = true)
      super(@page, @per_page)
    end

    def to_query_params : Hash(String, String)
      params = super
      params["year"] = @year.to_s if @year
      params["severity"] = @severity.to_s if @severity
      params["vendor"] = @vendor.to_s if @vendor
      params["include_pt"] = @include_pt.to_s if @include_pt
      params
    end
  end

  class RecentSearchParams < PaginationParams
    property days : Int32?
    property include_pt : Bool?

    def initialize(@page = nil, @per_page = nil, @days = nil, @include_pt = true)
      super(@page, @per_page)
    end

    def to_query_params : Hash(String, String)
      params = super
      params["days"] = @days.to_s if @days
      params["include_pt"] = @include_pt.to_s if @include_pt
      params
    end
  end

  class Client
    @config : Config

    def initialize(@config : Config)
    end

    # Faz requisição HTTP para a API
    private def request(endpoint : String, params : Hash(String, String) = {} of String => String) : JSON::Any
      uri = URI.parse(@config.base_url + endpoint)
      
      unless params.empty?
        query = HTTP::Params.encode(params)
        uri.query = query
      end

      response = HTTP::Client.get(uri.to_s, headers: @config.headers) do |resp|
        if resp.status.success?
          JSON.parse(resp.body_io)
        else
          raise "HTTP Error: #{resp.status}"
        end
      end
    end

    # Retorna informações sobre a API
    def get_api_info : JSON::Any
      request("/api/v1/")
    end

    # Lista todas as vulnerabilidades com suporte a paginação e filtros
    def list_vulnerabilities(params : SearchParams = SearchParams.new) : JSON::Any
      request("/api/v1/vulnerabilities", params.to_query_params)
    end

    # Busca uma vulnerabilidade específica pelo CVE ID
    def get_vulnerability(cve_id : String, include_pt : Bool = true) : JSON::Any
      request("/api/v1/vulnerabilities/#{cve_id}", {"include_pt" => include_pt.to_s})
    end

    # Busca vulnerabilidades recentes
    def get_recent_vulnerabilities(params : RecentSearchParams = RecentSearchParams.new) : JSON::Any
      request("/api/v1/search/recent", params.to_query_params)
    end

    # Retorna as 5 vulnerabilidades mais recentes
    def get_top5_recent(include_pt : Bool = true) : JSON::Any
      request("/api/v1/search/recent/5", {"include_pt" => include_pt.to_s})
    end

    # Busca vulnerabilidades por ano
    def search_by_year(year : Int32, params : PaginationParams = PaginationParams.new) : JSON::Any
      query_params = params.to_query_params
      request("/api/v1/search/year/#{year}", query_params)
    end

    # Busca vulnerabilidades por severidade
    def search_by_severity(severity : String, params : PaginationParams = PaginationParams.new) : JSON::Any
      query_params = params.to_query_params
      request("/api/v1/search/severity/#{severity}", query_params)
    end

    # Busca vulnerabilidades por vendor/fabricante
    def search_by_vendor(vendor : String, params : PaginationParams = PaginationParams.new) : JSON::Any
      query_params = params.to_query_params
      request("/api/v1/search/vendor/#{vendor}", query_params)
    end

    # Retorna estatísticas gerais
    def get_stats : JSON::Any
      request("/api/v1/stats")
    end

    # Retorna estatísticas por ano
    def get_year_stats : JSON::Any
      request("/api/v1/stats/years")
    end

    # === Notícias ===

    # Lista todas as notícias
    def list_noticias(params : PaginationParams = PaginationParams.new) : JSON::Any
      request("/api/v1/noticias", params.to_query_params)
    end

    # Retorna notícias recentes
    def get_recent_noticias(limit : Int32 = 5) : JSON::Any
      request("/api/v1/noticias/recentes/#{limit}")
    end

    # Busca notícia por slug
    def get_noticia_by_slug(slug : String) : JSON::Any
      request("/api/v1/noticias/#{slug}")
    end

    # === MITRE ATT&CK ===

    # Retorna informações sobre o sistema MITRE ATT&CK
    def get_mitre_info : JSON::Any
      request("/api/v1/mitre")
    end

    # Lista todas as matrizes MITRE ATT&CK disponíveis
    def list_mitre_matrices : JSON::Any
      request("/api/v1/mitre/matrices")
    end

    # Retorna uma matriz específica
    def get_mitre_matrix(matrix_name : String, include_pt : Bool = true) : JSON::Any
      request("/api/v1/mitre/matrix/#{matrix_name}", {"include_pt" => include_pt.to_s})
    end

    # Lista todas as técnicas MITRE ATT&CK
    def list_mitre_techniques(params : Hash(String, String) = {} of String => String) : JSON::Any
      request("/api/v1/mitre/techniques", params)
    end

    # Retorna detalhes de uma técnica específica
    def get_mitre_technique(technique_id : String, include_pt : Bool = true) : JSON::Any
      request("/api/v1/mitre/technique/#{technique_id}", {"include_pt" => include_pt.to_s})
    end

    # Lista todas as subtécnicas MITRE ATT&CK
    def list_mitre_subtechniques(params : Hash(String, String) = {} of String => String) : JSON::Any
      request("/api/v1/mitre/subtechniques", params)
    end

    # Lista todos os grupos de ameaças MITRE ATT&CK
    def list_mitre_groups(params : Hash(String, String) = {} of String => String) : JSON::Any
      request("/api/v1/mitre/groups", params)
    end

    # Retorna detalhes de um grupo específico
    def get_mitre_group(group_id : String, include_pt : Bool = true) : JSON::Any
      request("/api/v1/mitre/group/#{group_id}", {"include_pt" => include_pt.to_s})
    end

    # Lista todas as mitigações MITRE ATT&CK
    def list_mitre_mitigations(params : Hash(String, String) = {} of String => String) : JSON::Any
      request("/api/v1/mitre/mitigations", params)
    end

    # Retorna detalhes de uma mitigação específica
    def get_mitre_mitigation(mitigation_id : String, include_pt : Bool = true) : JSON::Any
      request("/api/v1/mitre/mitigation/#{mitigation_id}", {"include_pt" => include_pt.to_s})
    end
  end
end
