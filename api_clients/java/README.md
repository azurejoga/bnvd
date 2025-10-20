# BNVD API Client - Java

Cliente oficial em Java para a API do Banco Nacional de Vulnerabilidades Cibernéticas (BNVD).

## Requisitos

- Java 11 ou superior
- Maven 3.6+ (para build)

## Instalação

### Maven

Adicione ao seu `pom.xml`:

```xml
<dependency>
    <groupId>org.bnvd</groupId>
    <artifactId>bnvd-client</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'org.bnvd:bnvd-client:1.0.0'
```

## Uso

```java
import org.bnvd.client.BNVDClient;
import org.bnvd.client.BNVDClient.*;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;

public class Example {
    public static void main(String[] args) {
        try {
            // Configurar cliente (URL padrão: https://bnvd.org/api/v1)
            Config config = new Config();
            BNVDClient client = new BNVDClient(config);
            
            // Ou com configuração customizada
            // Config config = new Config(
            //     "https://bnvd.org/api/v1",
            //     Duration.ofSeconds(30),
            //     new HashMap<>()
            // );
            // BNVDClient client = new BNVDClient(config);

            // Listar vulnerabilidades
            SearchParams params = new SearchParams();
            params.setPage(1);
            params.setPerPage(20);
            params.setIncludePt(true);

            APIResponse<?> result = client.listVulnerabilities(params);

            if (result.isSuccess()) {
                System.out.println("Total: " + result.getPagination().get("total"));
            }

            // Buscar vulnerabilidade específica
            var vuln = client.getVulnerability("CVE-2024-12345", true);

            // Buscar por ano
            var vulns2024 = client.searchByYear(2024, null);

            // Buscar por severidade
            var critical = client.searchBySeverity(
                Severity.CRITICAL, 
                null
            );

            // Buscar vulnerabilidades recentes
            RecentSearchParams recentParams = new RecentSearchParams();
            recentParams.setDays(7);
            var recent = client.getRecentVulnerabilities(recentParams);

            // Obter estatísticas
            var stats = client.getStats();
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
```

## Métodos Disponíveis

### Informações da API
- `getAPIInfo()` - Retorna informações sobre a API

### Vulnerabilidades
- `listVulnerabilities(params)` - Lista todas as vulnerabilidades
- `getVulnerability(cveId, includePt)` - Busca vulnerabilidade específica
- `getRecentVulnerabilities(params)` - Vulnerabilidades recentes
- `getTop5Recent(includePt)` - Top 5 mais recentes
- `searchByYear(year, params)` - Busca por ano
- `searchBySeverity(severity, params)` - Busca por severidade
- `searchByVendor(vendor, params)` - Busca por fabricante

### Estatísticas
- `getStats()` - Estatísticas gerais
- `getYearStats()` - Estatísticas por ano

### Notícias
- `listNoticias(params)` - Lista todas as notícias
- `getRecentNoticias(limit)` - Notícias recentes
- `getNoticiaBySlug(slug)` - Busca notícia por slug

### MITRE ATT&CK
- `getMitreInfo()` - Informações sobre o sistema MITRE
- `listMitreMatrices()` - Lista matrizes disponíveis
- `getMitreMatrix(name, includePt)` - Retorna matriz específica
- `listMitreTechniques(params)` - Lista técnicas
- `getMitreTechnique(id, includePt)` - Detalhes de técnica
- `listMitreSubtechniques(params)` - Lista subtécnicas
- `listMitreGroups(params)` - Lista grupos de ameaças
- `getMitreGroup(id, includePt)` - Detalhes de grupo
- `listMitreMitigations(params)` - Lista mitigações
- `getMitreMitigation(id, includePt)` - Detalhes de mitigação

## Níveis de Severidade

```java
import org.bnvd.client.BNVDClient.Severity;

Severity.LOW       // Baixa
Severity.MEDIUM    // Média
Severity.HIGH      // Alta
Severity.CRITICAL  // Crítica
```

## Tratamento de Erros

```java
try {
    APIResponse<?> result = client.getVulnerability("CVE-INVALID", true);
    
    if (result.isError()) {
        System.err.println("Erro da API: " + result.getMessage());
    }
} catch (IOException e) {
    System.err.println("Erro de I/O: " + e.getMessage());
} catch (InterruptedException e) {
    System.err.println("Requisição interrompida: " + e.getMessage());
    Thread.currentThread().interrupt();
}
```

## Exemplos Avançados

### Busca com Múltiplos Filtros

```java
SearchParams params = new SearchParams();
params.setPage(1);
params.setPerPage(50);
params.setYear(2024);
params.setSeverity(Severity.CRITICAL.getValue());
params.setIncludePt(true);

APIResponse<?> result = client.listVulnerabilities(params);
```

### Paginação

```java
int page = 1;
int perPage = 20;
boolean hasMore = true;

while (hasMore) {
    SearchParams params = new SearchParams();
    params.setPage(page);
    params.setPerPage(perPage);
    
    APIResponse<?> result = client.listVulnerabilities(params);
    
    // Processar resultados
    if (result.getData() != null) {
        // ...
    }
    
    // Verificar se há mais páginas
    Map<String, Object> pagination = result.getPagination();
    int totalPages = ((Double) pagination.get("total_pages")).intValue();
    hasMore = page < totalPages;
    page++;
}
```

### Configuração Personalizada

```java
Map<String, String> customHeaders = new HashMap<>();
customHeaders.put("User-Agent", "MyApp/1.0");
customHeaders.put("Accept-Language", "pt-BR");

Config config = new Config(
    "https://bnvd.org",
    Duration.ofSeconds(60),
    customHeaders
);

BNVDClient client = new BNVDClient(config);
```

## Build do Projeto

```bash
# Compilar
mvn clean compile

# Executar testes
mvn test

# Criar JAR
mvn package

# Instalar localmente
mvn install
```

## Licença

MIT
