// Package bnvd provides a Go client for the BNVD API
// (Banco Nacional de Vulnerabilidades Cibernéticas)
package bnvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client representa o cliente da API BNVD
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Headers    map[string]string
}

// Config contém a configuração do cliente
type Config struct {
	BaseURL string
	Timeout time.Duration
	Headers map[string]string
}

// Severity representa os níveis de severidade CVSS
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// PaginationParams parâmetros de paginação
type PaginationParams struct {
	Page    int
	PerPage int
}

// SearchParams parâmetros de busca
type SearchParams struct {
	PaginationParams
	Year      int
	Severity  Severity
	Vendor    string
	IncludePT bool
}

// RecentSearchParams parâmetros de busca recente
type RecentSearchParams struct {
	PaginationParams
	Days      int
	IncludePT bool
}

// CVEDescription descrição da CVE
type CVEDescription struct {
	Lang    string `json:"lang"`
	Value   string `json:"value"`
	ValuePT string `json:"value_pt,omitempty"`
}

// CVSSData dados CVSS
type CVSSData struct {
	Version      string  `json:"version,omitempty"`
	VectorString string  `json:"vectorString,omitempty"`
	BaseScore    float64 `json:"baseScore,omitempty"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}

// CVSSMetric métrica CVSS
type CVSSMetric struct {
	Source   string   `json:"source,omitempty"`
	Type     string   `json:"type,omitempty"`
	CVSSData CVSSData `json:"cvssData,omitempty"`
}

// CVEReference referência da CVE
type CVEReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// WeaknessDescription descrição de fraqueza
type WeaknessDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Weakness fraqueza (CWE)
type Weakness struct {
	Source      string                `json:"source,omitempty"`
	Type        string                `json:"type,omitempty"`
	Description []WeaknessDescription `json:"description,omitempty"`
}

// CVEMetrics métricas da CVE
type CVEMetrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31,omitempty"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30,omitempty"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2,omitempty"`
}

// CVEData dados da CVE
type CVEData struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier,omitempty"`
	Published        string           `json:"published,omitempty"`
	LastModified     string           `json:"lastModified,omitempty"`
	VulnStatus       string           `json:"vulnStatus,omitempty"`
	Descriptions     []CVEDescription `json:"descriptions,omitempty"`
	Metrics          *CVEMetrics      `json:"metrics,omitempty"`
	Weaknesses       []Weakness       `json:"weaknesses,omitempty"`
	References       []CVEReference   `json:"references,omitempty"`
}

// Vulnerability vulnerabilidade
type Vulnerability struct {
	CVE CVEData `json:"cve"`
}

// Pagination informações de paginação
type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// APIResponse resposta da API
type APIResponse struct {
	Status     string          `json:"status"`
	Data       json.RawMessage `json:"data,omitempty"`
	Message    string          `json:"message,omitempty"`
	Pagination *Pagination     `json:"pagination,omitempty"`
}

// StatsData estatísticas
type StatsData struct {
	TotalVulnerabilities int                `json:"total_vulnerabilities"`
	BySeverity           map[string]int     `json:"by_severity"`
	ByYear               map[string]int     `json:"by_year"`
	LastUpdated          string             `json:"last_updated"`
}

// YearStats estatísticas por ano
type YearStats struct {
	Year       int            `json:"year"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByMonth    map[string]int `json:"by_month"`
}

// NewClient cria um novo cliente BNVD
func NewClient(config Config) *Client {
	if config.BaseURL == "" {
		config.BaseURL = "https://bnvd.org/api/v1"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &Client{
		BaseURL: config.BaseURL,
		HTTPClient: &http.Client{
			Timeout: config.Timeout,
		},
		Headers: config.Headers,
	}
}

// buildURL constrói a URL com parâmetros
func (c *Client) buildURL(endpoint string, params map[string]string) string {
	baseURL, _ := url.Parse(c.BaseURL)
	baseURL.Path = endpoint

	if len(params) > 0 {
		q := baseURL.Query()
		for key, value := range params {
			if value != "" {
				q.Set(key, value)
			}
		}
		baseURL.RawQuery = q.Encode()
	}

	return baseURL.String()
}

// request faz uma requisição HTTP
func (c *Client) request(ctx context.Context, endpoint string, params map[string]string) (*APIResponse, error) {
	reqURL := c.buildURL(endpoint, params)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &apiResp, nil
}

// GetAPIInfo retorna informações sobre a API
func (c *Client) GetAPIInfo(ctx context.Context) (*APIResponse, error) {
	return c.request(ctx, "/api/v1/", nil)
}

// ListVulnerabilities lista vulnerabilidades
func (c *Client) ListVulnerabilities(ctx context.Context, params SearchParams) ([]Vulnerability, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}
	if params.Year > 0 {
		p["year"] = strconv.Itoa(params.Year)
	}
	if params.Severity != "" {
		p["severity"] = string(params.Severity)
	}
	if params.Vendor != "" {
		p["vendor"] = params.Vendor
	}
	if params.IncludePT {
		p["include_pt"] = "true"
	}

	resp, err := c.request(ctx, "/api/v1/vulnerabilities", p)
	if err != nil {
		return nil, nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, resp.Pagination, nil
}

// GetVulnerability busca uma vulnerabilidade específica
func (c *Client) GetVulnerability(ctx context.Context, cveID string, includePT bool) (*Vulnerability, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/vulnerabilities/%s", cveID), params)
	if err != nil {
		return nil, err
	}

	var vuln Vulnerability
	if err := json.Unmarshal(resp.Data, &vuln); err != nil {
		return nil, fmt.Errorf("error parsing vulnerability: %w", err)
	}

	return &vuln, nil
}

// GetRecentVulnerabilities busca vulnerabilidades recentes
func (c *Client) GetRecentVulnerabilities(ctx context.Context, params RecentSearchParams) ([]Vulnerability, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Days > 0 {
		p["days"] = strconv.Itoa(params.Days)
	}
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}
	if params.IncludePT {
		p["include_pt"] = "true"
	}

	resp, err := c.request(ctx, "/api/v1/search/recent", p)
	if err != nil {
		return nil, nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, resp.Pagination, nil
}

// GetTop5Recent retorna as 5 vulnerabilidades mais recentes
func (c *Client) GetTop5Recent(ctx context.Context, includePT bool) ([]Vulnerability, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, "/api/v1/search/recent/5", params)
	if err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, nil
}

// SearchByYear busca vulnerabilidades por ano
func (c *Client) SearchByYear(ctx context.Context, year int, params PaginationParams, includePT bool) ([]Vulnerability, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}
	if includePT {
		p["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/search/year/%d", year), p)
	if err != nil {
		return nil, nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, resp.Pagination, nil
}

// SearchBySeverity busca vulnerabilidades por severidade
func (c *Client) SearchBySeverity(ctx context.Context, severity Severity, params PaginationParams, includePT bool) ([]Vulnerability, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}
	if includePT {
		p["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/search/severity/%s", severity), p)
	if err != nil {
		return nil, nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, resp.Pagination, nil
}

// SearchByVendor busca vulnerabilidades por vendor
func (c *Client) SearchByVendor(ctx context.Context, vendor string, params PaginationParams, includePT bool) ([]Vulnerability, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}
	if includePT {
		p["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/search/vendor/%s", vendor), p)
	if err != nil {
		return nil, nil, err
	}

	var vulns []Vulnerability
	if err := json.Unmarshal(resp.Data, &vulns); err != nil {
		return nil, nil, fmt.Errorf("error parsing vulnerabilities: %w", err)
	}

	return vulns, resp.Pagination, nil
}

// GetStats retorna estatísticas gerais
func (c *Client) GetStats(ctx context.Context) (*StatsData, error) {
	resp, err := c.request(ctx, "/api/v1/stats", nil)
	if err != nil {
		return nil, err
	}

	var stats StatsData
	if err := json.Unmarshal(resp.Data, &stats); err != nil {
		return nil, fmt.Errorf("error parsing stats: %w", err)
	}

	return &stats, nil
}

// GetYearStats retorna estatísticas por ano
func (c *Client) GetYearStats(ctx context.Context) ([]YearStats, error) {
	resp, err := c.request(ctx, "/api/v1/stats/years", nil)
	if err != nil {
		return nil, err
	}

	var stats []YearStats
	if err := json.Unmarshal(resp.Data, &stats); err != nil {
		return nil, fmt.Errorf("error parsing year stats: %w", err)
	}

	return stats, nil
}

// ListNoticias lista todas as notícias
func (c *Client) ListNoticias(ctx context.Context, params PaginationParams) ([]json.RawMessage, *Pagination, error) {
	p := make(map[string]string)
	
	if params.Page > 0 {
		p["page"] = strconv.Itoa(params.Page)
	}
	if params.PerPage > 0 {
		p["per_page"] = strconv.Itoa(params.PerPage)
	}

	resp, err := c.request(ctx, "/api/v1/noticias", p)
	if err != nil {
		return nil, nil, err
	}

	var noticias []json.RawMessage
	if err := json.Unmarshal(resp.Data, &noticias); err != nil {
		return nil, nil, fmt.Errorf("error parsing noticias: %w", err)
	}

	return noticias, resp.Pagination, nil
}

// GetRecentNoticias retorna notícias recentes
func (c *Client) GetRecentNoticias(ctx context.Context, limit int) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/noticias/recentes/%d", limit), nil)
	if err != nil {
		return nil, err
	}

	var noticias []json.RawMessage
	if err := json.Unmarshal(resp.Data, &noticias); err != nil {
		return nil, fmt.Errorf("error parsing noticias: %w", err)
	}

	return noticias, nil
}

// GetNoticiaBySlug busca notícia por slug
func (c *Client) GetNoticiaBySlug(ctx context.Context, slug string) (json.RawMessage, error) {
	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/noticias/%s", slug), nil)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// GetMitreInfo retorna informações sobre o sistema MITRE ATT&CK
func (c *Client) GetMitreInfo(ctx context.Context) (json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre", nil)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListMitreMatrices lista todas as matrizes MITRE ATT&CK disponíveis
func (c *Client) ListMitreMatrices(ctx context.Context) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre/matrices", nil)
	if err != nil {
		return nil, err
	}

	var matrices []json.RawMessage
	if err := json.Unmarshal(resp.Data, &matrices); err != nil {
		return nil, fmt.Errorf("error parsing matrices: %w", err)
	}

	return matrices, nil
}

// GetMitreMatrix retorna uma matriz específica
func (c *Client) GetMitreMatrix(ctx context.Context, matrixName string, includePT bool) (json.RawMessage, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/mitre/matrix/%s", matrixName), params)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListMitreTechniques lista todas as técnicas MITRE ATT&CK
func (c *Client) ListMitreTechniques(ctx context.Context, params map[string]string) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre/techniques", params)
	if err != nil {
		return nil, err
	}

	var techniques []json.RawMessage
	if err := json.Unmarshal(resp.Data, &techniques); err != nil {
		return nil, fmt.Errorf("error parsing techniques: %w", err)
	}

	return techniques, nil
}

// GetMitreTechnique retorna detalhes de uma técnica específica
func (c *Client) GetMitreTechnique(ctx context.Context, techniqueID string, includePT bool) (json.RawMessage, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/mitre/technique/%s", techniqueID), params)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListMitreSubtechniques lista todas as subtécnicas MITRE ATT&CK
func (c *Client) ListMitreSubtechniques(ctx context.Context, params map[string]string) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre/subtechniques", params)
	if err != nil {
		return nil, err
	}

	var subtechniques []json.RawMessage
	if err := json.Unmarshal(resp.Data, &subtechniques); err != nil {
		return nil, fmt.Errorf("error parsing subtechniques: %w", err)
	}

	return subtechniques, nil
}

// ListMitreGroups lista todos os grupos de ameaças MITRE ATT&CK
func (c *Client) ListMitreGroups(ctx context.Context, params map[string]string) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre/groups", params)
	if err != nil {
		return nil, err
	}

	var groups []json.RawMessage
	if err := json.Unmarshal(resp.Data, &groups); err != nil {
		return nil, fmt.Errorf("error parsing groups: %w", err)
	}

	return groups, nil
}

// GetMitreGroup retorna detalhes de um grupo específico
func (c *Client) GetMitreGroup(ctx context.Context, groupID string, includePT bool) (json.RawMessage, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/mitre/group/%s", groupID), params)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// ListMitreMitigations lista todas as mitigações MITRE ATT&CK
func (c *Client) ListMitreMitigations(ctx context.Context, params map[string]string) ([]json.RawMessage, error) {
	resp, err := c.request(ctx, "/api/v1/mitre/mitigations", params)
	if err != nil {
		return nil, err
	}

	var mitigations []json.RawMessage
	if err := json.Unmarshal(resp.Data, &mitigations); err != nil {
		return nil, fmt.Errorf("error parsing mitigations: %w", err)
	}

	return mitigations, nil
}

// GetMitreMitigation retorna detalhes de uma mitigação específica
func (c *Client) GetMitreMitigation(ctx context.Context, mitigationID string, includePT bool) (json.RawMessage, error) {
	params := make(map[string]string)
	if includePT {
		params["include_pt"] = "true"
	}

	resp, err := c.request(ctx, fmt.Sprintf("/api/v1/mitre/mitigation/%s", mitigationID), params)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}
