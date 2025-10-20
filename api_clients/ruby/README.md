# BNVD API Client - Ruby

Cliente oficial em Ruby para a API do Banco Nacional de Vulnerabilidades Cibernéticas (BNVD).

## Instalação

Adicione ao seu Gemfile:

```ruby
gem 'bnvd_client'
```

Ou instale diretamente:

```bash
gem install bnvd_client
```

## Uso

```ruby
require 'bnvd_client'

# Configurar cliente (URL padrão: https://bnvd.org/api/v1)
client = BNVD::Client.new(BNVD::Config.new)

# Ou com configuração customizada
# config = BNVD::Config.new(
#   base_url: 'https://bnvd.org/api/v1',
#   timeout: 30
# )
# client = BNVD::Client.new(config)

# Listar vulnerabilidades
result = client.list_vulnerabilities(
  BNVD::SearchParams.new(
    page: 1,
    per_page: 20,
    include_pt: true
  )
)

if result.success?
  puts "Total: #{result.pagination['total']}"
  result.data.each do |vuln|
    puts vuln['cve']['id']
  end
end

# Buscar vulnerabilidade específica
vuln = client.get_vulnerability('CVE-2024-12345')

# Buscar por ano
vulns_2024 = client.search_by_year(2024)

# Buscar por severidade
critical = client.search_by_severity(BNVD::Severity::CRITICAL)

# Buscar vulnerabilidades recentes
recent = client.get_recent_vulnerabilities(
  BNVD::RecentSearchParams.new(days: 7)
)

# Obter estatísticas
stats = client.get_stats
puts "Total de vulnerabilidades: #{stats.data['total_vulnerabilities']}"
```

## Métodos Disponíveis

### Informações da API
- `get_api_info()` - Retorna informações sobre a API

### Vulnerabilidades
- `list_vulnerabilities(params)` - Lista todas as vulnerabilidades
- `get_vulnerability(cve_id, include_pt)` - Busca vulnerabilidade específica
- `get_recent_vulnerabilities(params)` - Vulnerabilidades recentes
- `get_top5_recent(include_pt)` - Top 5 mais recentes
- `search_by_year(year, params)` - Busca por ano
- `search_by_severity(severity, params)` - Busca por severidade
- `search_by_vendor(vendor, params)` - Busca por fabricante

### Estatísticas
- `get_stats()` - Estatísticas gerais
- `get_year_stats()` - Estatísticas por ano

### Notícias
- `list_noticias(params)` - Lista todas as notícias
- `get_recent_noticias(limit)` - Notícias recentes
- `get_noticia_by_slug(slug)` - Busca notícia por slug

### MITRE ATT&CK
- `get_mitre_info()` - Informações sobre o sistema MITRE
- `list_mitre_matrices()` - Lista matrizes disponíveis
- `get_mitre_matrix(name, include_pt)` - Retorna matriz específica
- `list_mitre_techniques(params)` - Lista técnicas
- `get_mitre_technique(id, include_pt)` - Detalhes de técnica
- `list_mitre_subtechniques(params)` - Lista subtécnicas
- `list_mitre_groups(params)` - Lista grupos de ameaças
- `get_mitre_group(id, include_pt)` - Detalhes de grupo
- `list_mitre_mitigations(params)` - Lista mitigações
- `get_mitre_mitigation(id, include_pt)` - Detalhes de mitigação

## Níveis de Severidade

```ruby
BNVD::Severity::LOW       # Baixa
BNVD::Severity::MEDIUM    # Média
BNVD::Severity::HIGH      # Alta
BNVD::Severity::CRITICAL  # Crítica
```

## Tratamento de Erros

```ruby
begin
  result = client.get_vulnerability('CVE-INVALID')
rescue => e
  puts "Erro: #{e.message}"
end
```

## Licença

MIT
