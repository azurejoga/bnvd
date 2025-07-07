# BNVD – Banco Nacional de Vulnerabilidades Digitais  
**Acesse em:** [https://bnvd.org](https://bnvd.org)

---

##  Sobre o Projeto

O **Brasil nunca contou com um banco de dados nacional dedicado à catalogação de vulnerabilidades cibernéticas**, como já ocorre nos Estados Unidos com o [NVD](https://nvd.nist.gov) e na União Europeia com iniciativas semelhantes.

O **BNVD** surge para preencher essa lacuna e **representa um marco na segurança cibernética brasileira**, promovendo maior transparência, soberania digital e capacidade de resposta a ameaças.

---

## ⚠️ Aviso

Este repositório tem **finalidade exclusivamente de desenvolvimento**.  
O banco de dados e os registros de CVEs **não estão incluídos** neste repositório público.

---

##  Como iniciar o desenvolvimento

1. **Clone este repositório:**
   ```bash
   git clone https://github.com/azurejoga/bnvd
   cd bnvd
   ```

2. **Crie e ative um ambiente virtual Python:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. **Configure o banco de dados PostgreSQL.**

4. **Crie e edite o arquivo `.env`** com as variáveis globais:
   - `DATABASE_URL` – URL de conexão com o banco de dados PostgreSQL
   - `NVD_API_KEY` – Chave de acesso à API da NVD
   - `SESSION_SECRET` – Chave secreta do Flask

5. **Solicite sua chave de API do NVD:**  
   Acesse o site oficial e siga as instruções:  
   👉 [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

6. **Execute a aplicação:**
   ```bash
   python main.py
   ```

---

## 🙏 Agradecimentos

Este projeto é resultado da dedicação de profissionais preocupados com o fortalecimento da **cibersegurança no Brasil**.  
Agradecemos a todos que colaboram com sugestões, desenvolvimento, revisão e testes. em seguida, os colaboradores que tornaram isso real!. PS: todos eles são deficientes visuais!
* [@gabriel1003](https://github.com/gabriel1003)
* [augusto-marques-anacleto](https://github.com/augusto-marques-anacleto)
* [Gustavo Almeida Barrios](https://github.com/gustavo-barrios2006)
* [Jhonata Fernandes](https://github.com/jhonata192)
---
