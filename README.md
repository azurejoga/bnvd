# BNVD – Banco Nacional de Vulnerabilidades Cibernéticas
**Acesse em:** [https://bnvd.org](https://bnvd.org)

---

## 🏛️ Sobre o Projeto

O **Brasil nunca contou com um banco de dados nacional dedicado à catalogação de vulnerabilidades cibernéticas**, como já ocorre nos Estados Unidos com o [NVD](https://nvd.nist.gov) e na União Europeia com iniciativas semelhantes.

O **BNVD** surge para preencher essa lacuna e **representa um marco na segurança cibernética brasileira**, promovendo maior transparência, soberania digital e capacidade de resposta a ameaças.

---

## ⚠️ Aviso Importante

Este repositório tem **finalidade exclusivamente de desenvolvimento**.  
O banco de dados e os registros de CVEs **não estão incluídos** neste repositório público.

---

## ⚙️ Como Iniciar o Desenvolvimento

### 1. Clone o repositório
```bash
git clone https://github.com/azurejoga/bnvd
cd bnvd
```

### 2. Crie e ative o ambiente virtual Python
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Configure o banco de dados PostgreSQL

Certifique-se de que o PostgreSQL está instalado e em execução localmente ou em um servidor remoto acessível.

### 4. Crie e edite o arquivo `.env`

Adicione as variáveis de ambiente globais:

```bash
DATABASE_URL=postgresql://usuario:senha@localhost:5432/bnvd
NVD_API_KEY=sua_chave_nvd_aqui
SESSION_SECRET=sua_chave_flask_aqui
```

### 5. Instale as dependências com Poetry

O projeto utiliza o **Poetry** para gerenciar dependências e ambientes virtuais.

#### Instale o Poetry (se ainda não tiver instalado)
```bash
pip install poetry
```

#### Instale as dependências do projeto
```bash
poetry install --no-root
```

### 6. Solicite sua chave de API da NVD
Acesse o site oficial e siga as instruções:  
👉 [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

### 7. Execute a aplicação
```bash
python main.py
```

---

## 📦 Wrappers / Clientes do BNVD

O **BNVD** pode ser utilizado em diversas linguagens de programação através de **envoltórios (wrappers)** e **clientes oficiais** ou **comunitários**.

> 🔗 Repositório principal dos clientes oficiais:  
> [https://github.com/azurejoga/bnvd/tree/master/api_clients](https://github.com/azurejoga/bnvd/tree/master/api_clients)

| 💻 Linguagem | 🔗 Repositório / Cliente | ⚙️ Status |
|--------------|--------------------------|------------|
| **Ruby** | [bnvd-ruby-client](https://github.com/azurejoga/bnvd/tree/master/api_clients/ruby) | ✅ Estável |
| **Crystal** | [bnvd-crystal-client](https://github.com/azurejoga/bnvd/tree/master/api_clients/crystal) | ✅ Estável |
| **Java** | [bnvd-java-client](https://github.com/azurejoga/bnvd/tree/master/api_clients/java) | ✅ Estável |
| **JavaScript / TypeScript** | [bnvd-js-client](https://github.com/azurejoga/bnvd/tree/master/api_clients/javascript) | ✅ Estável |
| **PHP** | [bnvd-php-client](https://github.com/gustavo-barrios2006/bnvd-php-client) | ✅ Estável |
| **Flutter** | *bnvd-flutter-client* | 🚧 Em desenvolvimento |
| **Rust** | *bnvd-rust-client* | 🚧 Em desenvolvimento |

---

## 🤝 Agradecimentos

Este projeto é resultado da dedicação de profissionais comprometidos com o fortalecimento da **cibersegurança no Brasil**.  
Agradecemos a todos que colaboram com sugestões, desenvolvimento, revisão e testes.

### 👥 Colaboradores (todos deficientes visuais)

- [@gabriel1003](https://github.com/gabriel1003)  
- [@augusto-marques-anacleto](https://github.com/augusto-marques-anacleto)  
- [@gustavo-barrios2006](https://github.com/gustavo-barrios2006)  
- [@jhonata192](https://github.com/jhonata192)

---

## 🧩 Licença

Este projeto é distribuído sob a licença **MIT**.  
Consulte o arquivo `LICENSE` para mais detalhes.
