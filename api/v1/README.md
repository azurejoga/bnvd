# BNVD API v1 - Documentação

## Sobre a API

A BNVD API v1 é uma API REST que fornece acesso programático ao Banco Nacional de Vulnerabilidades Cibernéticas. Permite consultar vulnerabilidades de segurança, buscar por critérios específicos e obter estatísticas do banco de dados.

## Base URL

```
https://bnvd.org/api/v1
```

## Autenticação

Atualmente a API é pública e não requer autenticação. Todas as consultas são limitadas para garantir performance.

## Formatos de Resposta

Todas as respostas são em JSON com a seguinte estrutura:

### Resposta de Sucesso
```json
{
  "status": "success",
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "pages": 5,
    "has_next": true,
    "has_prev": false
  }
}
```

### Resposta de Erro
```json
{
  "status": "error",
  "message": "Descrição do erro",
  "code": 400
}
```

## Endpoints Disponíveis

### 1. Documentação da API
```
GET /api/v1/
```

Retorna informações sobre a API, endpoints disponíveis e parâmetros.

### 2. Listar Vulnerabilidades

```
GET /api/v1/vulnerabilities
```

Lista todas as vulnerabilidades com suporte a paginação e filtros.

**Parâmetros:**
- `page` (int): Número da página (padrão: 1)
- `per_page` (int): Resultados por página (padrão: 20, máximo: 100)
- `year` (int): Filtrar por ano específico
- `severity` (string): Filtrar por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL)
- `vendor` (string): Filtrar por vendor/fabricante
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/vulnerabilities?page=1&per_page=20&year=2024"
```

### 3. Buscar Vulnerabilidade Específica

```
GET /api/v1/vulnerabilities/<cve_id>
```

Busca uma vulnerabilidade específica pelo CVE ID.

**Parâmetros:**
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/vulnerabilities/CVE-2024-12345"
```

### 4. Vulnerabilidades Recentes

```
GET /api/v1/search/recent
```

Busca vulnerabilidades publicadas nos últimos dias.

**Parâmetros:**
- `days` (int): Número de dias (padrão: 7, máximo: 30)
- `page` (int): Número da página (padrão: 1)
- `per_page` (int): Resultados por página (padrão: 20, máximo: 100)
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/search/recent?days=7&page=1"
```

### 5. 5 Vulnerabilidades Mais Recentes

```
GET /api/v1/search/recent/5
```

Retorna as 5 vulnerabilidades mais recentes.

**Parâmetros:**
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

### 6. Buscar por Ano

```
GET /api/v1/search/year/<year>
```

Busca vulnerabilidades de um ano específico.

**Parâmetros:**
- `page` (int): Número da página (padrão: 1)
- `per_page` (int): Resultados por página (padrão: 20, máximo: 100)
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/search/year/2024"
```

### 7. Buscar por Severidade

```
GET /api/v1/search/severity/<severity>
```

Busca vulnerabilidades por severidade CVSS.

**Severidades aceitas:** LOW, MEDIUM, HIGH, CRITICAL

**Parâmetros:**
- `page` (int): Número da página (padrão: 1)
- `per_page` (int): Resultados por página (padrão: 20, máximo: 100)
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/search/severity/HIGH"
```

### 8. Buscar por Vendor

```
GET /api/v1/search/vendor/<vendor>
```

Busca vulnerabilidades por vendor/fabricante.

**Parâmetros:**
- `page` (int): Número da página (padrão: 1)
- `per_page` (int): Resultados por página (padrão: 20, máximo: 100)
- `include_pt` (boolean): Incluir traduções em português (padrão: true)

**Exemplo:**
```bash
curl "https://[seu-dominio]/api/v1/search/vendor/microsoft"
```

### 9. Estatísticas Gerais

```
GET /api/v1/stats
```

Retorna estatísticas gerais do banco de dados.

**Resposta:**
```json
{
  "status": "success",
  "data": {
    "total_vulnerabilities": 1500,
    "total_years": 25,
    "total_translations": 3000,
    "years_distribution": [...],
    "last_created": "2024-01-01T00:00:00",
    "last_updated": "2024-01-01T00:00:00",
    "database_status": "operational"
  }
}
```

### 10. Estatísticas por Ano

```
GET /api/v1/stats/years
```

Retorna estatísticas detalhadas por ano.

## Estrutura de Dados de Vulnerabilidade

```json
{
  "cve_id": "CVE-2024-12345",
  "year": 2024,
  "published_date": "2024-01-01T00:00:00",
  "last_modified": "2024-01-01T00:00:00",
  "status": "Published",
  "descriptions": [{
    "lang": "en",
    "value": "Description in English"
  }],
  "descriptions_pt": [{
    "lang": "pt",
    "value": "Descrição em português"
  }],
  "cvss_metrics": {
    "cvssMetricV31": [{
      "cvssData": {
        "baseScore": 7.5,
        "baseSeverity": "HIGH"
      }
    }]
  },
  "weaknesses": [...],
  "configurations": [...],
  "references": [...]
}
```

## Códigos de Status HTTP

- `200 OK`: Sucesso
- `400 Bad Request`: Parâmetros inválidos
- `404 Not Found`: Recurso não encontrado
- `500 Internal Server Error`: Erro interno do servidor

## Limitações

- Máximo de 100 resultados por página
- Máximo de 30 dias para busca de vulnerabilidades recentes
- API pública sem autenticação (limitações de rate podem ser aplicadas no futuro)

## Exemplos de Uso

### Buscar vulnerabilidades do Microsoft
```bash
curl "https://[seu-dominio]/api/v1/search/vendor/microsoft?per_page=10"
```

### Buscar vulnerabilidades críticas
```bash
curl "https://[seu-dominio]/api/v1/search/severity/CRITICAL"
```

### Obter estatísticas do banco
```bash
curl "https://[seu-dominio]/api/v1/stats"
```

### Buscar vulnerabilidades de 2024
```bash
curl "https://[seu-dominio]/api/v1/search/year/2024"
```

## Integração com Código

### Python
```python
import requests

def get_recent_vulnerabilities():
    response = requests.get('https://[seu-dominio]/api/v1/search/recent')
    if response.status_code == 200:
        data = response.json()
        return data['data']
    return None
```

### JavaScript
```javascript
async function getVulnerabilityById(cveId) {
    try {
        const response = await fetch(`https://[seu-dominio]/api/v1/vulnerabilities/${cveId}`);
        const data = await response.json();
        return data.status === 'success' ? data.data : null;
    } catch (error) {
        console.error('Erro ao buscar vulnerabilidade:', error);
        return null;
    }
}
```

## Contato

Para dúvidas sobre a API ou reportar problemas, entre em contato através da página "Sobre" do BNVD.