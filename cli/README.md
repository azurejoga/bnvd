# BNVD CLI - Interface de Linha de Comando

Interface de linha de comando para o Banco Nacional de Vulnerabilidades Cibernéticas (BNVD).

## Instalação

```bash
pip install -e .
```

Depois poderá usar:
```bash
bnvd-cli --help
bnvd --help
```

## Uso

### Buscar vulnerabilidades por termo
```bash
bnvd-cli buscar apache
bnvd-cli buscar openssl --limit 50
```

### Buscar CVE específico
```bash
bnvd-cli cve CVE-2024-12345
bnvd-cli cve 2024-12345  # O prefixo CVE- é opcional
```

### Vulnerabilidades recentes
```bash
bnvd-cli recentes                # Últimos 7 dias
bnvd-cli recentes --dias 30      # Últimos 30 dias
bnvd-cli recentes --dias 7 --limit 50
```

### Filtrar por severidade
```bash
bnvd-cli severidade CRITICAL
bnvd-cli severidade HIGH --limit 100
bnvd-cli severidade MEDIUM
```

Opções de severidade: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### Buscar por fabricante
```bash
bnvd-cli vendor Microsoft
bnvd-cli vendor Adobe
bnvd-cli vendor "Google Chrome"
```

### Ver estatísticas
```bash
bnvd-cli stats
```

### Exportar CVE
```bash
bnvd-cli export CVE-2024-12345              # Exporta para JSON
bnvd-cli export CVE-2024-12345 --formato txt
```

Formatos suportados: `json`, `txt`

## Variáveis de Ambiente

Pode-se configurar a URL base da API usando:

```bash
export BNVD_API_URL=https://bnvd.org/api/v1
bnvd-cli buscar apache
```

Se não definida, usa a URL padrão: `https://bnvd.org/api/v1`

## Exemplos Completos

```bash
# Encontrar todas as CVEs críticas dos últimos 7 dias
bnvd-cli recentes --dias 7 | grep -i critical

# Exportar CVE crítica para análise
bnvd-cli export CVE-2024-44487 --formato json > cve-details.json

# Buscar todas as vulnerabilidades da Microsoft
bnvd-cli vendor Microsoft --limit 100

# Analisar CVEs por severidade
bnvd-cli severidade CRITICAL --limit 20
```

## Saída em Cores

A CLI usa cores para facilitar a leitura:
- **Vermelho**: Crítico
- **Amarelo**: Alto
- **Ciano**: Médio
- **Verde**: Baixo
- **Azul**: Informações gerais

## Suporte

Para relatar bugs ou sugerir melhorias:
https://github.com/azurejoga/bnvd/issues
