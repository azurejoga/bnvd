# BNVD API Client - JavaScript/TypeScript

Cliente oficial da API do **Banco Nacional de Vulnerabilidades Cibernéticas (BNVD)** para JavaScript e TypeScript.

## Instalação

```bash
npm install bnvd-api-client
```

## Uso Rápido

### TypeScript

```typescript
import { BNVDClient } from 'bnvd-api-client';

// Criar cliente (URL padrão: https://bnvd.org/api/v1)
const client = new BNVDClient();

// Ou com configuração customizada
// const client = new BNVDClient({
//   baseUrl: 'https://bnvd.org/api/v1',
//   timeout: 30000
// });

// Buscar vulnerabilidade específica
const vuln = await client.getVulnerability('CVE-2024-12345');
console.log(vuln.data);

// Listar vulnerabilidades recentes
const recent = await client.getRecentVulnerabilities({ days: 7 });
console.log(recent.data);
```

### JavaScript (Node.js)

```javascript
const { BNVDClient } = require('bnvd-api-client');

const client = new BNVDClient({
  baseUrl: 'https://bnvd.org/api/v1'
});

// Buscar vulnerabilidade específica
client.getVulnerability('CVE-2024-12345').then(response => {
  console.log(response.data);
});
```

### JavaScript (Browser)

```html
<script type="module">
  import { BNVDClient } from './bnvd-client.js';
  
  const client = new BNVDClient({
    baseUrl: 'https://bnvd.org/api/v1'
  });
  
  const data = await client.getTop5Recent();
  console.log(data);
</script>
```

## API Reference

### Configuração

```typescript
const client = new BNVDClient({
  baseUrl: 'https://bnvd.org/api/v1',   // URL base da API
  timeout: 30000,                        // Timeout em ms (padrão: 30000)
  headers: {                             // Headers customizados
    'Authorization': 'Bearer token'
  }
});
```

### Métodos Disponíveis

#### `getAPIInfo()`
Retorna informações sobre a API.

```typescript
const info = await client.getAPIInfo();
```

#### `listVulnerabilities(params?)`
Lista vulnerabilidades com filtros opcionais.

```typescript
const vulnerabilities = await client.listVulnerabilities({
  page: 1,
  per_page: 20,
  year: 2024,
  severity: 'CRITICAL',
  vendor: 'microsoft',
  include_pt: true
});
```

#### `getVulnerability(cveId, includePt?)`
Busca vulnerabilidade específica por CVE ID.

```typescript
const vuln = await client.getVulnerability('CVE-2024-12345', true);
```

#### `getRecentVulnerabilities(params?)`
Busca vulnerabilidades recentes.

```typescript
const recent = await client.getRecentVulnerabilities({
  days: 7,
  page: 1,
  per_page: 20,
  include_pt: true
});
```

#### `getTop5Recent(includePt?)`
Retorna as 5 vulnerabilidades mais recentes.

```typescript
const top5 = await client.getTop5Recent(true);
```

#### `searchByYear(year, params?)`
Busca vulnerabilidades por ano.

```typescript
const vulns2024 = await client.searchByYear(2024, {
  page: 1,
  per_page: 50,
  include_pt: true
});
```

#### `searchBySeverity(severity, params?)`
Busca vulnerabilidades por severidade.

```typescript
const critical = await client.searchBySeverity('CRITICAL', {
  page: 1,
  per_page: 20
});
```

#### `searchByVendor(vendor, params?)`
Busca vulnerabilidades por fabricante.

```typescript
const microsoft = await client.searchByVendor('microsoft', {
  page: 1,
  per_page: 20
});
```

#### `getStats()`
Retorna estatísticas gerais.

```typescript
const stats = await client.getStats();
```

#### `getYearStats()`
Retorna estatísticas por ano.

```typescript
const yearStats = await client.getYearStats();
```

## Tipos TypeScript

A biblioteca fornece tipos completos para TypeScript:

```typescript
import { 
  BNVDClient, 
  Vulnerability, 
  CVEData, 
  APIResponse,
  SearchParams,
  StatsData 
} from 'bnvd-api-client';
```

## Tratamento de Erros

```typescript
try {
  const vuln = await client.getVulnerability('CVE-2024-12345');
  if (vuln.status === 'success') {
    console.log(vuln.data);
  } else {
    console.error(vuln.message);
  }
} catch (error) {
  console.error('Erro na requisição:', error);
}
```

## Exemplos Práticos

### Buscar e exibir vulnerabilidades críticas recentes

```typescript
const client = new BNVDClient({ baseUrl: 'https://bnvd.org/api/v1' });

async function mostrarCriticasRecentes() {
  const response = await client.searchBySeverity('CRITICAL', {
    page: 1,
    per_page: 10,
    include_pt: true
  });

  if (response.status === 'success' && response.data) {
    response.data.forEach(vuln => {
      const desc = vuln.cve.descriptions?.find(d => d.lang === 'en');
      console.log(`${vuln.cve.id}: ${desc?.value_pt || desc?.value}`);
    });
  }
}
```

### Obter estatísticas e gerar relatório

```typescript
async function gerarRelatorio() {
  const stats = await client.getStats();
  const yearStats = await client.getYearStats();

  console.log('=== RELATÓRIO BNVD ===');
  console.log(`Total de vulnerabilidades: ${stats.data?.total_vulnerabilities}`);
  console.log(`\nPor severidade:`);
  console.log(`- Críticas: ${stats.data?.by_severity.CRITICAL}`);
  console.log(`- Altas: ${stats.data?.by_severity.HIGH}`);
  console.log(`- Médias: ${stats.data?.by_severity.MEDIUM}`);
  console.log(`- Baixas: ${stats.data?.by_severity.LOW}`);
}
```

### Integração com React

```typescript
import { BNVDClient } from 'bnvd-api-client';
import { useState, useEffect } from 'react';

const client = new BNVDClient({ baseUrl: 'https://bnvd.org/api/v1' });

function VulnerabilityList() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      const response = await client.getRecentVulnerabilities({ days: 7 });
      if (response.status === 'success') {
        setVulns(response.data || []);
      }
      setLoading(false);
    }
    fetchData();
  }, []);

  if (loading) return <div>Carregando...</div>;

  return (
    <ul>
      {vulns.map(vuln => (
        <li key={vuln.cve.id}>{vuln.cve.id}</li>
      ))}
    </ul>
  );
}
```

## Licença

MIT

### Notícias de Segurança Cibernética

```typescript
// Listar todas as notícias
const noticias = await client.listNoticias({ page: 1, per_page: 20 });

// Notícias recentes
const recent = await client.getRecentNoticias(5);

// Notícia específica
const noticia = await client.getNoticiaBySlug('slug-da-noticia');
```

### MITRE ATT&CK

```typescript
// Listar matrizes disponíveis
const matrices = await client.listMitreMatrices();

// Obter matriz específica com tradução
const enterprise = await client.getMitreMatrix('enterprise', true);

// Listar técnicas
const techniques = await client.listMitreTechniques({
  matrix: 'enterprise',
  tactic: 'initial-access'
});

// Detalhes de técnica
const technique = await client.getMitreTechnique('T1566');

// Listar grupos
const groups = await client.listMitreGroups({ matrix: 'enterprise' });

// Detalhes de grupo
const group = await client.getMitreGroup('G0016');

// Listar mitigações
const mitigations = await client.listMitreMitigations();

// Detalhes de mitigação
const mitigation = await client.getMitreMitigation('M1047');
```

## Suporte

Para problemas ou dúvidas, abra uma issue no [GitHub](https://github.com/azurejoga/bnvd/tree/main/api_clients/javascript).
