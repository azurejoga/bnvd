package org.bnvd.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * BNVD API Client - Java
 * Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
 * @version 1.0.0
 */
public class BNVDClient {

    /**
     * Níveis de severidade CVSS
     */
    public enum Severity {
        LOW("LOW"),
        MEDIUM("MEDIUM"),
        HIGH("HIGH"),
        CRITICAL("CRITICAL");

        private final String value;

        Severity(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Configuração do cliente
     */
    public static class Config {
        private final String baseUrl;
        private final Duration timeout;
        private final Map<String, String> headers;

        public Config() {
            this("https://bnvd.org/api/v1", Duration.ofSeconds(30), new HashMap<>());
        }

        public Config(String baseUrl) {
            this(baseUrl, Duration.ofSeconds(30), new HashMap<>());
        }

        public Config(String baseUrl, Duration timeout, Map<String, String> headers) {
            this.baseUrl = baseUrl;
            this.timeout = timeout;
            this.headers = new HashMap<>(headers);
            this.headers.putIfAbsent("Content-Type", "application/json");
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public Duration getTimeout() {
            return timeout;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }
    }

    /**
     * Parâmetros de paginação
     */
    public static class PaginationParams {
        private Integer page;
        private Integer perPage;

        public PaginationParams() {}

        public PaginationParams(Integer page, Integer perPage) {
            this.page = page;
            this.perPage = perPage;
        }

        public Map<String, String> toQueryParams() {
            Map<String, String> params = new HashMap<>();
            if (page != null) params.put("page", page.toString());
            if (perPage != null) params.put("per_page", perPage.toString());
            return params;
        }

        public Integer getPage() { return page; }
        public void setPage(Integer page) { this.page = page; }
        public Integer getPerPage() { return perPage; }
        public void setPerPage(Integer perPage) { this.perPage = perPage; }
    }

    /**
     * Parâmetros de busca
     */
    public static class SearchParams extends PaginationParams {
        private Integer year;
        private String severity;
        private String vendor;
        private Boolean includePt;

        public SearchParams() {
            this.includePt = true;
        }

        @Override
        public Map<String, String> toQueryParams() {
            Map<String, String> params = super.toQueryParams();
            if (year != null) params.put("year", year.toString());
            if (severity != null) params.put("severity", severity);
            if (vendor != null) params.put("vendor", vendor);
            if (includePt != null) params.put("include_pt", includePt.toString());
            return params;
        }

        public Integer getYear() { return year; }
        public void setYear(Integer year) { this.year = year; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getVendor() { return vendor; }
        public void setVendor(String vendor) { this.vendor = vendor; }
        public Boolean getIncludePt() { return includePt; }
        public void setIncludePt(Boolean includePt) { this.includePt = includePt; }
    }

    /**
     * Parâmetros de busca recente
     */
    public static class RecentSearchParams extends PaginationParams {
        private Integer days;
        private Boolean includePt;

        public RecentSearchParams() {
            this.includePt = true;
        }

        @Override
        public Map<String, String> toQueryParams() {
            Map<String, String> params = super.toQueryParams();
            if (days != null) params.put("days", days.toString());
            if (includePt != null) params.put("include_pt", includePt.toString());
            return params;
        }

        public Integer getDays() { return days; }
        public void setDays(Integer days) { this.days = days; }
        public Boolean getIncludePt() { return includePt; }
        public void setIncludePt(Boolean includePt) { this.includePt = includePt; }
    }

    /**
     * Resposta da API
     */
    public static class APIResponse<T> {
        private String status;
        private T data;
        private String message;
        private Map<String, Object> pagination;

        public boolean isSuccess() {
            return "success".equals(status);
        }

        public boolean isError() {
            return "error".equals(status);
        }

        public String getStatus() { return status; }
        public T getData() { return data; }
        public String getMessage() { return message; }
        public Map<String, Object> getPagination() { return pagination; }
    }

    private final Config config;
    private final HttpClient httpClient;
    private final Gson gson;

    /**
     * Cria um novo cliente
     */
    public BNVDClient(Config config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(config.getTimeout())
                .build();
        this.gson = new Gson();
    }

    /**
     * Lista todas as notícias de segurança cibernética
     */
    public APIResponse<?> listNoticias(SearchParams params) throws IOException, InterruptedException {
        return request("/noticias", params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Retorna as notícias mais recentes
     */
    public APIResponse<?> getRecentNoticias(Integer limit) throws IOException, InterruptedException {
        Map<String, String> paramMap = new HashMap<>();
        if (limit != null) {
            paramMap.put("limit", limit.toString());
        }
        return request("/noticias/recentes", paramMap);
    }

    /**
     * Retorna uma notícia específica pelo slug
     */
    public APIResponse<?> getNoticiaBySlug(String slug) throws IOException, InterruptedException {
        return request("/noticias/" + slug, new HashMap<>());
    }

    /**
     * Informações sobre endpoints MITRE ATT&CK
     */
    public APIResponse<?> getMitreInfo() throws IOException, InterruptedException {
        return request("/mitre", new HashMap<>());
    }

    /**
     * Lista todas as matrizes MITRE ATT&CK disponíveis
     */
    public APIResponse<?> listMitreMatrices() throws IOException, InterruptedException {
        return request("/mitre/matrices", new HashMap<>());
    }

    /**
     * Retorna dados completos de uma matriz MITRE ATT&CK
     */
    public APIResponse<?> getMitreMatrix(String matrixType, Boolean translate) throws IOException, InterruptedException {
        Map<String, String> paramMap = new HashMap<>();
        if (translate != null) {
            paramMap.put("translate", translate.toString());
        }
        return request("/mitre/matrix/" + matrixType, paramMap);
    }

    /**
     * Lista todas as técnicas MITRE ATT&CK
     */
    public APIResponse<?> listMitreTechniques(SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/techniques", params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Retorna detalhes de uma técnica específica
     */
    public APIResponse<?> getMitreTechnique(String techniqueId, SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/technique/" + techniqueId, params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Lista todas as subtécnicas MITRE ATT&CK
     */
    public APIResponse<?> listMitreSubtechniques(SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/subtechniques", params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Lista todos os grupos de ameaças MITRE ATT&CK
     */
    public APIResponse<?> listMitreGroups(SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/groups", params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Retorna detalhes de um grupo específico
     */
    public APIResponse<?> getMitreGroup(String groupId, SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/group/" + groupId, params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Lista todas as mitigações MITRE ATT&CK
     */
    public APIResponse<?> listMitreMitigations(SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/mitigations", params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Retorna detalhes de uma mitigação específica
     */
    public APIResponse<?> getMitreMitigation(String mitigationId, SearchParams params) throws IOException, InterruptedException {
        return request("/mitre/mitigation/" + mitigationId, params != null ? params.toMap() : new HashMap<>());
    }

    /**
     * Faz requisição HTTP para a API
     */
    private <T> APIResponse<T> request(String endpoint, Map<String, String> params, TypeToken<APIResponse<T>> typeToken) 
            throws IOException, InterruptedException {
        String url = config.getBaseUrl() + endpoint;

        if (params != null && !params.isEmpty()) {
            url += "?" + encodeParams(params);
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(config.getTimeout())
                .GET();

        config.getHeaders().forEach(requestBuilder::header);

        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return gson.fromJson(response.body(), typeToken.getType());
        } else {
            throw new IOException("HTTP Error: " + response.statusCode());
        }
    }

    private String encodeParams(Map<String, String> params) {
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (result.length() > 0) {
                result.append("&");
            }
            result.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return result.toString();
    }

    /**
     * Retorna informações sobre a API
     */
    public APIResponse<JsonObject> getAPIInfo() throws IOException, InterruptedException {
        return request("/api/v1/", null, new TypeToken<APIResponse<JsonObject>>() {});
    }

    /**
     * Lista todas as vulnerabilidades com suporte a paginação e filtros
     */
    public APIResponse<List<JsonObject>> listVulnerabilities(SearchParams params) throws IOException, InterruptedException {
        Map<String, String> queryParams = params != null ? params.toQueryParams() : new HashMap<>();
        return request("/api/v1/vulnerabilities", queryParams, new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Busca uma vulnerabilidade específica pelo CVE ID
     */
    public APIResponse<JsonObject> getVulnerability(String cveId, boolean includePt) throws IOException, InterruptedException {
        Map<String, String> params = new HashMap<>();
        params.put("include_pt", String.valueOf(includePt));
        return request("/api/v1/vulnerabilities/" + cveId, params, new TypeToken<APIResponse<JsonObject>>() {});
    }

    /**
     * Busca vulnerabilidades recentes
     */
    public APIResponse<List<JsonObject>> getRecentVulnerabilities(RecentSearchParams params) 
            throws IOException, InterruptedException {
        Map<String, String> queryParams = params != null ? params.toQueryParams() : new HashMap<>();
        return request("/api/v1/search/recent", queryParams, new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Retorna as 5 vulnerabilidades mais recentes
     */
    public APIResponse<List<JsonObject>> getTop5Recent(boolean includePt) throws IOException, InterruptedException {
        Map<String, String> params = new HashMap<>();
        params.put("include_pt", String.valueOf(includePt));
        return request("/api/v1/search/recent/5", params, new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Busca vulnerabilidades por ano
     */
    public APIResponse<List<JsonObject>> searchByYear(int year, PaginationParams params) 
            throws IOException, InterruptedException {
        Map<String, String> queryParams = params != null ? params.toQueryParams() : new HashMap<>();
        return request("/api/v1/search/year/" + year, queryParams, new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Busca vulnerabilidades por severidade
     */
    public APIResponse<List<JsonObject>> searchBySeverity(Severity severity, PaginationParams params) 
            throws IOException, InterruptedException {
        Map<String, String> queryParams = params != null ? params.toQueryParams() : new HashMap<>();
        return request("/api/v1/search/severity/" + severity.getValue(), queryParams, 
                new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Busca vulnerabilidades por vendor/fabricante
     */
    public APIResponse<List<JsonObject>> searchByVendor(String vendor, PaginationParams params) 
            throws IOException, InterruptedException {
        Map<String, String> queryParams = params != null ? params.toQueryParams() : new HashMap<>();
        return request("/api/v1/search/vendor/" + vendor, queryParams, 
                new TypeToken<APIResponse<List<JsonObject>>>() {});
    }

    /**
     * Retorna estatísticas gerais
     */
    public APIResponse<JsonObject> getStats() throws IOException, InterruptedException {
        return request("/api/v1/stats", null, new TypeToken<APIResponse<JsonObject>>() {});
    }

    /**
     * Retorna estatísticas por ano
     */
    public APIResponse<List<JsonObject>> getYearStats() throws IOException, InterruptedException {
        return request("/api/v1/stats/years", null, new TypeToken<APIResponse<List<JsonObject>>>() {});
    }
}
