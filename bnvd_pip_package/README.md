### README.md

````markdown
# BNVD Python Client

Cliente Python para a API do Banco Nacional de Vulnerabilidades Digitais (BNVD).

## Instalação

```bash
pip install bnvd
````

## Uso básico

```python
from bnvd.client import BNVDClient

client = BNVDClient()

# Buscar vulnerabilidade específica
detalhes = client.get_vulnerability("CVE-2025-12345")
print(detalhes)
```

## Funcionalidades

* Listar vulnerabilidades com filtros (ano, severidade, vendor)
* Buscar vulnerabilidade por CVE ID
* Buscar estatísticas do banco de dados

## Contribuição

Contribuições são bem-vindas! Abra uma issue ou pull request no GitHub.

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

