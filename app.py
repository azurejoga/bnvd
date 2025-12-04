import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from dotenv import load_dotenv
import requests
from werkzeug.middleware.proxy_fix import ProxyFix
from nvd_api import NVDClient
from utils import (translate_severity, translate_cwe, translate_cvss_metrics, format_date, paginate_results,
                 extract_cvss_score, extract_severity, extract_vector_string, 
                 extract_cwe_info, extract_description, extract_references, clean_cpe_name)
from translator import DatabaseTranslator
from vulns import VulnerabilityDatabase
from seo import SEOManager, init_seo_routes
from security import security_manager

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__) # Renomeado para logger para consistência

# Criar aplicação Flask
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    import secrets
    app.secret_key = secrets.token_hex(32)
    logging.warning("SESSION_SECRET não configurado - usando chave gerada aleatoriamente para esta sessão")

# Configurar ProxyFix para HTTPS
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Inicializar cliente NVD com banco de dados
api_key = os.environ.get("NVD_API_KEY")
if not api_key:
    api_key = os.environ.get("NVD_API_KEY", "")
    if not api_key.strip():
        logging.warning("NVD_API_KEY não encontrada - usando modo desenvolvimento")
        api_key = "development-mode"

database_url = os.environ.get("DATABASE_URL")
if not database_url or database_url.strip() == "":
    # Construir DATABASE_URL a partir das variáveis individuais PostgreSQL
    pghost = os.environ.get("PGHOST", "").strip()
    pgport = os.environ.get("PGPORT", "").strip()
    pguser = os.environ.get("PGUSER", "").strip()
    pgpassword = os.environ.get("PGPASSWORD", "").strip()
    pgdatabase = os.environ.get("PGDATABASE", "").strip()

    if pghost and pgport and pguser and pgdatabase:
        database_url = f"postgresql://{pguser}:{pgpassword}@{pghost}:{pgport}/{pgdatabase}"
        logging.info("DATABASE_URL construída a partir das variáveis PostgreSQL individuais")
    else:
        logging.warning("Variáveis de banco de dados não encontradas - funcionando sem banco")
        database_url = None

# Inicializar cliente NVD (com ou sem banco)
nvd_client = NVDClient(api_key, database_url)

# Inicializar tradutor (com ou sem banco)
if database_url:
    translator = DatabaseTranslator(database_url)
    logging.info("Sistema de tradução com banco de dados inicializado")
else:
    # Criar um tradutor simples sem banco para desenvolvimento
    from translator import DatabaseTranslator

    class SimpleTranslator:
        def translate_text(self, text, target_lang='pt'):
            return text  # Retorna texto original sem tradução

        def force_translate_text(self, text, target_lang='pt'):
            return text  # Retorna texto original sem tradução

        def translate_cve_description(self, text):
            return text  # Retorna texto original sem tradução

    translator = SimpleTranslator()
    logging.warning("Sistema de tradução simples inicializado (sem banco)")

# Inicializar SEO Manager
seo_manager = SEOManager(app)

# Inicializar rotas de SEO
init_seo_routes(app, seo_manager)

# Registrar API v1
from api.v1 import api_v1
app.register_blueprint(api_v1)

# Inicializar sistema de notícias CISO Advisor
from advisor import init_advisor, get_recent_news, get_month_news, get_news_content
try:
    init_advisor()
    logging.info("Sistema de notícias CISO Advisor inicializado")
except Exception as e:
    logging.error(f"Erro ao inicializar sistema de notícias: {e}")

# Inicializar processador MITRE ATT&CK com tradutor dedicado
from mitre_translate import initialize_mitre_translator, mitre_translator
from mitre import initialize_mitre, mitre_processor

# Variável global para armazenar o processador
mitre_proc = None

try:
    # Criar tradutor dedicado para MITRE
    mt = initialize_mitre_translator(database_url)
    initialize_mitre(mt)
    
    # Importar novamente para pegar a instância inicializada
    from mitre import mitre_processor as mp
    mitre_proc = mp
    
    logging.info("Processador MITRE ATT&CK inicializado com tradutor dedicado")
except Exception as e:
    logging.error(f"Erro ao inicializar MITRE ATT&CK: {e}")
    mitre_proc = None

@app.route('/')
def index():
    """Página inicial do BNVD"""
    return render_template('index.html')

@app.route('/sw.js')
def service_worker():
    """Serve o service worker do PWA na raiz"""
    response = app.send_static_file('sw.js')
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def _search_database_with_sort(vendor, sort_by='published', sort_order='desc', page=1, per_page=20):
    """
    Busca vulnerabilidades no banco local com ordenação
    
    Args:
        vendor: Termo de busca por fabricante
        sort_by: 'published' ou 'modified' para campo de ordenação
        sort_order: 'asc' ou 'desc'
        page: Número da página
        per_page: Resultados por página
    
    Returns:
        Tupla (vulnerabilities, total_count) ou (None, 0) se falhar
    """
    try:
        if not database_url:
            return None, 0
        
        import psycopg2
        import psycopg2.extras
        
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Definir campo de ordenação
        order_field = 'last_modified' if sort_by == 'modified' else 'published_date'
        # 'desc' = DESC (mais recentes primeiro), 'asc' = ASC (mais antigos primeiro)
        order_direction = 'DESC' if sort_order == 'desc' else 'ASC'
        
        logging.debug(f"Ordenação: campo={order_field}, direção={order_direction}, sort_order={sort_order}")
        
        # Contar total
        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE descriptions::text ILIKE %s OR configurations::text ILIKE %s
        """, (f'%{vendor}%', f'%{vendor}%'))
        total_count = cursor.fetchone()['count']
        
        # Buscar dados com ordenação
        offset = (page - 1) * per_page
        query = f"""
            SELECT * FROM vulnerabilities 
            WHERE descriptions::text ILIKE %s OR configurations::text ILIKE %s 
            ORDER BY {order_field} {order_direction}
            LIMIT %s OFFSET %s
        """
        cursor.execute(query, (f'%{vendor}%', f'%{vendor}%', per_page, offset))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append(dict(row))
        
        cursor.close()
        conn.close()
        
        logging.info(f"Busca no banco: {total_count} CVEs encontradas para '{vendor}' (ordenação: {sort_by} {sort_order})")
        return vulnerabilities, total_count
        
    except Exception as e:
        logging.warning(f"Erro ao buscar no banco local: {e}")
        return None, 0

def _convert_db_to_api_format(db_vulns):
    """
    Converte vulnerabilidades do banco para formato da API NVD
    """
    if not db_vulns:
        return []
    
    import json
    from datetime import datetime
    
    api_vulns = []
    for db_vuln in db_vulns:
        try:
            # Parse dos campos JSON se necessário
            descriptions = db_vuln.get('descriptions')
            if isinstance(descriptions, str):
                descriptions = json.loads(descriptions)
            
            metrics = db_vuln.get('cvss_metrics')
            if isinstance(metrics, str):
                metrics = json.loads(metrics)
            
            configurations = db_vuln.get('configurations')
            if isinstance(configurations, str):
                configurations = json.loads(configurations)
            
            # Converter datas para strings ISO (o banco retorna datetime objects)
            published_date = db_vuln.get('published_date')
            if published_date and isinstance(published_date, datetime):
                published_date = published_date.isoformat()
            
            last_modified = db_vuln.get('last_modified')
            if last_modified and isinstance(last_modified, datetime):
                last_modified = last_modified.isoformat()
            
            # Formato da API NVD
            api_vuln = {
                'cve': {
                    'id': db_vuln.get('cve_id'),
                    'published': published_date,
                    'lastModified': last_modified,
                    'descriptions': descriptions or [],
                    'metrics': metrics or {},
                    'configurations': configurations or [],
                    'sourceIdentifier': db_vuln.get('source_identifier'),
                    'vulnStatus': db_vuln.get('vulnstatus')
                }
            }
            api_vulns.append(api_vuln)
        except Exception as e:
            logging.warning(f"Erro ao converter CVE do banco: {e}")
            continue
    
    return api_vulns

@app.route('/busca')
def busca():
    """Página de busca de vulnerabilidades"""
    # Sanitizar e validar todos os parâmetros da requisição
    secure_params = security_manager.secure_request_params(request.args)

    # Verificar tentativas de ataque nos parâmetros brutos
    for param_name, param_value in request.args.items():
        if security_manager.detect_sql_injection(str(param_value)):
            logging.warning(f"SQL injection detectado: {param_name}={param_value}")
            flash("Parâmetros de entrada inválidos detectados.", "error")
            return render_template('busca.html', error_message="Parâmetros de entrada inválidos")

        if security_manager.detect_xss(str(param_value)):
            logging.warning(f"XSS detectado: {param_name}={param_value}")
            flash("Parâmetros de entrada inválidos detectados.", "error")
            return render_template('busca.html', error_message="Parâmetros de entrada inválidos")

    # Obter parâmetros seguros
    cve_id = secure_params.get('cve_id', '')
    severidade = secure_params.get('severidade', '')
    vendor = secure_params.get('vendor', '')
    
    # Parâmetros de ordenação (mais recente primeiro por padrão)
    sort_by = request.args.get('ordenar', 'published')  # 'published' ou 'modified'
    sort_order = request.args.get('ordem', 'desc')  # 'asc' ou 'desc'
    
    # Validar parâmetros de ordenação
    if sort_by not in ['published', 'modified']:
        sort_by = 'published'
    if sort_order not in ['asc', 'desc']:
        sort_order = 'desc'

    # Paginação segura
    page = secure_params.get('page', 1)
    per_page = min(secure_params.get('per_page', 20), 20)  # Limitar a 20 para performance
    start_index = (page - 1) * per_page

    # Inicializar variáveis
    vulnerabilidades = []
    total_results = 0
    error_message = None

    # Verificar se há filtros de busca (removidos ano e keyword)
    has_filters = any([cve_id, severidade, vendor])

    try:
        vulnerabilidades = []
        total_results = 0
        source = "nenhuma"  # Para logging
        
        # PRIORIDADE 1: Se houver vendor OU severidade → Banco Local (ordenação e filtro exato)
        if (vendor or severidade) and database_url:
            logging.info(f"Buscando no banco local: vendor='{vendor}', severidade='{severidade}'")
            
            # Para severidade, precisamos de uma busca diferente
            if severidade and not vendor:
                # Busca apenas por severidade no banco
                try:
                    import psycopg2
                    import psycopg2.extras
                    
                    conn = psycopg2.connect(database_url)
                    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                    
                    order_field = 'last_modified' if sort_by == 'modified' else 'published_date'
                    order_direction = 'ASC' if sort_order == 'desc' else 'DESC'
                    
                    cursor.execute("""
                        SELECT COUNT(*) FROM vulnerabilities 
                        WHERE cvss_metrics::text ILIKE %s
                    """, (f'%{severidade}%',))
                    total_count = cursor.fetchone()['count']
                    
                    offset = (page - 1) * per_page
                    query = f"""
                        SELECT * FROM vulnerabilities 
                        WHERE cvss_metrics::text ILIKE %s 
                        ORDER BY {order_field} {order_direction}
                        LIMIT %s OFFSET %s
                    """
                    cursor.execute(query, (f'%{severidade}%', per_page, offset))
                    
                    db_vulns = [dict(row) for row in cursor.fetchall()]
                    cursor.close()
                    conn.close()
                    
                    if db_vulns and total_count > 0:
                        api_response = _convert_db_to_api_format(db_vulns)
                        vulnerabilidades = api_response
                        total_results = total_count
                        source = "banco_severidade"
                        logging.info(f"Banco encontrou {total_count} CVEs com severidade '{severidade}'")
                except Exception as e:
                    logging.warning(f"Erro ao buscar severidade no banco: {e}")
            else:
                # Busca por vendor (com ou sem severidade)
                db_vulns, db_total = _search_database_with_sort(vendor, sort_by, sort_order, page, per_page)
                
                if db_vulns and db_total > 0:
                    api_response = _convert_db_to_api_format(db_vulns)
                    vulnerabilidades = api_response
                    total_results = db_total
                    source = "banco_vendor"
                    logging.info(f"Banco encontrou {db_total} CVEs para '{vendor}' (com ordenação {sort_by} {sort_order})")
        
        # PRIORIDADE 2: Se só houver CVE ID → API NVD (busca exata)
        if not vulnerabilidades and cve_id:
            logging.info(f"Buscando CVE ID específico na API NVD: {cve_id}")
            search_params = {}
            search_params['cveId'] = cve_id
            search_params['resultsPerPage'] = 20
            search_params['startIndex'] = start_index

            response = nvd_client.search_cves(**search_params)

            if response and 'vulnerabilities' in response and len(response['vulnerabilities']) > 0:
                vulnerabilidades = response['vulnerabilities']
                total_results = response.get('totalResults', 0)
                source = "api_cve_id"
                logging.info(f"API NVD retornou CVE exato: {total_results} resultado")
            else:
                logging.info(f"CVE ID '{cve_id}' não encontrado na API NVD")
                
                # Fallback para banco se API não encontrou
                if database_url:
                    logging.info(f"Tentando encontrar CVE no banco local como fallback...")
                    try:
                        import psycopg2
                        import psycopg2.extras
                        
                        conn = psycopg2.connect(database_url)
                        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                        cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = %s LIMIT 1", (cve_id,))
                        row = cursor.fetchone()
                        cursor.close()
                        conn.close()
                        
                        if row:
                            db_vuln = dict(row)
                            vulnerabilidades = _convert_db_to_api_format([db_vuln])
                            total_results = 1
                            source = "banco_fallback_cve"
                            logging.info(f"CVE encontrado no banco como fallback")
                    except Exception as e:
                        logging.warning(f"Erro ao buscar CVE no banco: {e}")

        # Processar resultados
        if vulnerabilidades and len(vulnerabilidades) > 0:
            # Traduzir TODAS as descrições das vulnerabilidades encontradas (COMPLETAS)
            for vuln in vulnerabilidades:
                if 'cve' in vuln and 'descriptions' in vuln['cve']:
                    for desc in vuln['cve']['descriptions']:
                        if desc.get('lang') == 'en' and desc.get('value'):
                            try:
                                # Traduzir descrição COMPLETA usando tradução do banco
                                original_text = desc['value']
                                translated = translator.force_translate_text(original_text)
                                desc['value_pt'] = translated if translated else original_text
                                logging.debug(f"Traduzido CVE: '{original_text[:30]}...' -> '{translated[:30] if translated else 'FALHOU'}...'")
                            except Exception as e:
                                logging.warning(f"Erro na tradução: {e}")
                                desc['value_pt'] = desc['value']  # Fallback para original

            if total_results > 0:
                flash(f"Encontrados {total_results:,} resultados", "success")
            else:
                flash("Nenhum resultado encontrado para os critérios especificados.", "warning")
        else:
            vulnerabilidades = []
            total_results = 0
            error_message = "Nenhuma vulnerabilidade encontrada para os critérios especificados."
            flash("Nenhum resultado encontrado. Tente ajustar os filtros de busca ou tentar novamente.", "warning")

    except Exception as e:
        logging.error(f"Erro na busca: {str(e)}")
        error_message = f"Erro ao buscar vulnerabilidades: {str(e)}"
        flash("Erro interno na busca. Tente novamente.", "error")

    # Calcular informações de paginação
    total_pages = (total_results + per_page - 1) // per_page if total_results > 0 else 0

    return render_template('busca.html', 
                         vulnerabilidades=vulnerabilidades,
                         total_results=total_results,
                         page=page,
                         total_pages=total_pages,
                         per_page=per_page,
                         error_message=error_message,
                         # Preservar parâmetros de busca
                         cve_id=cve_id,
                         severidade=severidade,
                         vendor=vendor,
                         # Parâmetros de ordenação
                         ordenar=sort_by,
                         ordem=sort_order)

@app.route('/vulnerabilidade/<cve_id>')
def detalhes(cve_id):
    """Página de detalhes de uma vulnerabilidade específica"""
    try:
        # Buscar dados da vulnerabilidade (sistema automaticamente verifica banco e API)
        response = nvd_client.get_cve(cve_id)

        if response and 'vulnerabilities' in response and len(response['vulnerabilities']) > 0:
            vulnerabilidade = response['vulnerabilities'][0]

            # Traduzir descrições para português
            if 'cve' in vulnerabilidade and 'descriptions' in vulnerabilidade['cve']:
                for desc in vulnerabilidade['cve']['descriptions']:
                    if desc.get('lang') == 'en' and desc.get('value'):
                        try:
                            original_text = desc['value']
                            translated = translator.translate_text(original_text)
                            desc['value_pt'] = translated
                            logging.debug(f"Traduzido CVE {cve_id}: '{original_text[:30]}...' -> '{translated[:30]}...'")
                        except Exception as e:
                            logging.error(f"Erro na tradução dos detalhes para {cve_id}: {e}")
                            desc['value_pt'] = desc['value']  # Fallback para original

            # Traduzir tags das referências se existirem
            if 'cve' in vulnerabilidade:
                cve_data = vulnerabilidade['cve']

                if 'references' in cve_data and 'reference_data' in cve_data['references']:
                    for ref in cve_data['references']['reference_data']:
                        if 'tags' in ref and ref['tags']:
                            try:
                                translated_tags = []
                                for tag in ref['tags']:
                                    translated_tag = translator.translate_text(tag)
                                    translated_tags.append(translated_tag)
                                ref['tags_pt'] = translated_tags
                            except Exception as e:
                                logging.warning(f"Erro na tradução das tags: {e}")
                                ref['tags_pt'] = ref['tags']

            # Renderizar template com dados traduzidos
            return render_template('detalhes.html', vuln=vulnerabilidade)
        else:
            flash(f"Vulnerabilidade {cve_id} não encontrada.", "error")
            return redirect(url_for('busca'))

    except Exception as e:
        logging.error(f"Erro ao buscar CVE {cve_id}: {str(e)}")
        flash(f"Erro ao carregar vulnerabilidade: {str(e)}", "error")
        return redirect(url_for('busca'))


@app.route('/diretorio-de-certificacoes')
def diretorio_de_certificacoes():
    """Página do diretório de certificações"""
    return render_template('diretorio-de-certificacoes.html')


@app.route('/sobre')
def sobre():
    """Página sobre o projeto"""
    return render_template('sobre.html')

@app.route('/politica')
def politica():
    """Página de política de divulgação responsável"""
    return render_template('politica.html')

@app.route('/privacidade')
def privacidade():
    """Página de política de privacidade"""
    return render_template('privacidade.html')

@app.route('/treinamentos')
def treinamentos():
    """Página de treinamentos e certificações"""
    return render_template('treinamentos.html')

@app.route('/downloads')
def downloads():
    """Página de downloads dos aplicativos"""
    return render_template('downloads.html')

@app.route('/api-docs')
def api_docs():
    """Página de documentação da API"""
    return render_template('api-docs.html')

@app.route('/api/mitre/translate', methods=['POST'])
def translate_mitre_item():
    """API para traduzir itens MITRE sob demanda"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Texto não fornecido'}), 400
        
        text = data['text']
        item_id = data.get('item_id', '')
        item_type = data.get('item_type', '')
        tactics = data.get('tactics', [])  # Receber táticas para traduzir
        
        # Dividir texto em nome e descrição se necessário
        parts = text.split('|')
        name = parts[0] if len(parts) > 0 else ''
        description = parts[1] if len(parts) > 1 else ''
        
        # Traduzir usando o tradutor MITRE
        from mitre_translate import mitre_translator
        
        result = {
            'item_id': item_id,
            'item_type': item_type
        }
        
        if name and mitre_translator:
            result['name_pt'] = mitre_translator.translate_text(name)
        
        if description and mitre_translator:
            # Traduzir descrição completa
            result['description_pt'] = mitre_translator.translate_text(description)
        
        # Traduzir táticas
        if tactics and mitre_translator:
            tactics_pt = []
            for tactic in tactics:
                if tactic:
                    tactic_pt = mitre_translator.translate_text(tactic)
                    tactics_pt.append(tactic_pt)
            result['tactics_pt'] = tactics_pt
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erro ao traduzir item MITRE: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/mitre-attack')
def mitre_attack():
    """Página da matriz MITRE ATT&CK"""
    try:
        # Verificar se mitre_processor foi inicializado
        if not mitre_proc:
            logger.error("MITRE processor não inicializado")
            flash('Sistema MITRE ATT&CK não disponível no momento.', 'warning')
            return redirect(url_for('index'))

        # Obter tipo de matriz do parâmetro (padrão: enterprise)
        matrix_type = request.args.get('matrix', 'enterprise')

        # Validar tipo de matriz
        valid_matrices = ['enterprise', 'mobile', 'ics', 'pre-attack']
        if matrix_type not in valid_matrices:
            matrix_type = 'enterprise'

        # Obter dados da matriz (sempre com tradução)
        logger.info(f"Carregando matriz {matrix_type}...")
        matrix_data = mitre_proc.get_matrix_data(matrix_type, translate=True)

        # Log das estatísticas
        logger.info(f"Matriz {matrix_type}: {matrix_data.get('total_techniques')} técnicas, {matrix_data.get('total_subtechniques')} subtécnicas, {matrix_data.get('total_groups')} grupos, {matrix_data.get('total_mitigations')} mitigações")

        return render_template('mitre-attack.html', 
                             matrix_data=matrix_data,
                             current_matrix=matrix_type,
                             page_title=f'MITRE ATT&CK - {matrix_type.title()}')
    except Exception as e:
        logger.error(f"Erro ao carregar MITRE ATT&CK: {e}")
        flash('Erro ao carregar matriz MITRE ATT&CK.', 'error')
        return redirect(url_for('index'))



@app.route('/api/cves/recent')
def api_recent_cves():
    """API endpoint para CVEs recentes (últimos 7 dias) - sem autenticação (limitado)"""
    try:
        days = min(int(request.args.get('days', 7)), 7)  # Máximo 7 dias sem token
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 10)  # Limite menor sem token
        start_index = (page - 1) * per_page
        include_pt = request.args.get('include_pt', 'false').lower() == 'true'

        response = nvd_client.get_recent_cves(
            days=days,
            start_index=start_index,
            results_per_page=per_page
        )

        if response:
            # Adicionar traduções portuguesas se solicitado
            if include_pt and 'vulnerabilities' in response:
                for vuln in response['vulnerabilities']:
                    if 'cve' in vuln and 'descriptions' in vuln['cve']:
                        for desc in vuln['cve']['descriptions']:
                            if desc.get('lang') == 'en' and desc.get('value'):
                                try:
                                    translated = translator.translate_text(desc['value'])
                                    desc['value_pt'] = translated
                                except Exception as e:
                                    logging.warning(f"Erro na tradução da API: {e}")
                                    desc['value_pt'] = desc['value']

            # Adicionar aviso sobre limitações
            response['api_notice'] = 'API pública limitada a 10 resultados. Para acesso completo, use /api/token/<seu_token>/recent'
            return response
        else:
            return {'error': 'Nenhum resultado encontrado'}, 404

    except Exception as e:
        logging.error(f"Erro na API de CVEs recentes: {str(e)}")
        return {'error': str(e)}, 500

@app.route('/api/cves/kev')
def api_kev_cves():
    """API endpoint para CVEs no catálogo CISA KEV - sem autenticação (limitado)"""
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 10)  # Limite menor sem token
        start_index = (page - 1) * per_page
        include_pt = request.args.get('include_pt', 'false').lower() == 'true'

        response = nvd_client.get_kev_cves(
            start_index=start_index,
            results_per_page=per_page
        )

        if response:
            # Adicionar traduções portuguesas se solicitado
            if include_pt and 'vulnerabilities' in response:
                for vuln in response['vulnerabilities']:
                    if 'cve' in vuln and 'descriptions' in vuln['cve']:
                        for desc in vuln['cve']['descriptions']:
                            if desc.get('lang') == 'en' and desc.get('value'):
                                try:
                                    translated = translator.translate_text(desc['value'])
                                    desc['value_pt'] = translated
                                except Exception as e:
                                    logging.warning(f"Erro na tradução da API: {e}")
                                    desc['value_pt'] = desc['value']

            # Adicionar aviso sobre limitações
            response['api_notice'] = 'API pública limitada a 10 resultados. Para acesso completo, use /api/token/<seu_token>/kev'
            return response
        else:
            return {'error': 'Nenhum resultado encontrado'}, 404

    except Exception as e:
        logging.error(f"Erro na API de CVEs KEV: {str(e)}")
        return {'error': str(e)}, 500

@app.route('/recentes')
def recentes():
    """Página de vulnerabilidades recentes"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        start_index = (page - 1) * per_page

        response = nvd_client.get_recent_cves(
            days=7,
            start_index=start_index,
            results_per_page=per_page
        )

        vulnerabilidades = []
        total_results = 0

        if response and 'vulnerabilities' in response:
            vulnerabilidades = response['vulnerabilities']
            total_results = response.get('totalResults', 0)

            # Traduzir descrições
            for vuln in vulnerabilidades:
                if 'cve' in vuln and 'descriptions' in vuln['cve']:
                    for desc in vuln['cve']['descriptions']:
                        if desc.get('lang') == 'en' and desc.get('value'):
                            try:
                                translated = translator.translate_text(desc['value'])
                                desc['value_pt'] = translated
                            except Exception as e:
                                logging.warning(f"Erro na tradução: {e}")
                                desc['value_pt'] = desc['value']

        total_pages = (total_results + per_page - 1) // per_page if total_results > 0 else 0

        return render_template('recentes.html',
                             vulnerabilidades=vulnerabilidades,
                             total_results=total_results,
                             page=page,
                             total_pages=total_pages,
                             per_page=per_page)

    except Exception as e:
        logging.error(f"Erro ao carregar CVEs recentes: {str(e)}")
        flash(f"Erro ao carregar vulnerabilidades recentes: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/kev')
def kev():
    """Página de vulnerabilidades CISA KEV"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        start_index = (page - 1) * per_page

        response = nvd_client.get_kev_cves(
            start_index=start_index,
            results_per_page=per_page
        )

        vulnerabilidades = []
        total_results = 0

        if response and 'vulnerabilities' in response:
            vulnerabilidades = response['vulnerabilities']
            total_results = response.get('totalResults', 0)

            # Traduzir descrições
            for vuln in vulnerabilidades:
                if 'cve' in vuln and 'descriptions' in vuln['cve']:
                    for desc in vuln['cve']['descriptions']:
                        if desc.get('lang') == 'en' and desc.get('value'):
                            try:
                                translated = translator.translate_text(desc['value'])
                                desc['value_pt'] = translated
                            except Exception as e:
                                logging.warning(f"Erro na tradução: {e}")
                                desc['value_pt'] = desc['value']

        total_pages = (total_results + per_page - 1) // per_page if total_results > 0 else 0

        return render_template('kev.html',
                             vulnerabilidades=vulnerabilidades,
                             total_results=total_results,
                             page=page,
                             total_pages=total_pages,
                             per_page=per_page)

    except Exception as e:
        logging.error(f"Erro ao carregar CVEs KEV: {str(e)}")
        flash(f"Erro ao carregar vulnerabilidades KEV: {str(e)}", "error")
        return redirect(url_for('index'))

# Endpoint API para paginação AJAX
@app.route('/api/vulnerabilidades/<int:year>')
def api_vulnerabilidades_por_ano(year):
    """API endpoint para vulnerabilidades por ano com paginação"""
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 500)  # Máximo 500
        offset = (page - 1) * per_page
        include_pt = request.args.get('include_pt', 'false').lower() == 'true'

        # Buscar vulnerabilidades do ano específico
        db = VulnerabilityDatabase(database_url=os.environ.get('DATABASE_URL'))

        db._ensure_connection()

        try:
            import psycopg2.extras
            cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Contar total de vulnerabilidades do ano
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM vulnerabilities 
                WHERE year = %s
            """, (year,))
            total_count = cursor.fetchone()['total']

            # Buscar vulnerabilidades paginadas
            cursor.execute("""
                SELECT cve_id, year, published_date, last_modified, vulnStatus, cvss_metrics
                FROM vulnerabilities 
                WHERE year = %s
                ORDER BY published_date DESC
                LIMIT %s OFFSET %s
            """, (year, per_page, offset))

            vulnerabilities = []
            rows = cursor.fetchall()
            for row in rows:
                # cvss_metrics já é um dict quando vem do banco
                cvss_metrics = row['cvss_metrics'] if row['cvss_metrics'] else None

                vuln_data = {
                    'cve_id': row['cve_id'],
                    'year': row['year'],
                    'published_date': row['published_date'].isoformat() if row['published_date'] else None,
                    'last_modified': row['last_modified'].isoformat() if row['last_modified'] else None,
                    'vulnStatus': row['vulnstatus'],
                    'cvss_metrics': cvss_metrics
                }

                # Adicionar tradução do status se português solicitado
                if include_pt:
                    vuln_data['vulnStatus_pt'] = filter_translate_status(row['vulnstatus'])
                    if cvss_metrics and 'baseSeverity' in cvss_metrics:
                        vuln_data['cvss_metrics_pt'] = cvss_metrics.copy()
                        vuln_data['cvss_metrics_pt']['baseSeverity_pt'] = filter_translate_severity(cvss_metrics['baseSeverity'])

                vulnerabilities.append(vuln_data)

            cursor.close()

        except Exception as e:
            logging.error(f"Erro na consulta de vulnerabilidades do ano {year}: {e}")
            vulnerabilities = []
            total_count = 0
        finally:
            db.close()

        # Calcular informações de paginação
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 0

        return {
            'status': 'success',
            'data': {
                'vulnerabilities': vulnerabilities,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': total_count,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                },
                'year': year
            }
        }

    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades do ano {year}: {e}")
        return {
            'status': 'error',
            'message': str(e)
        }, 500

# Nova rota para as 5 vulnerabilidades mais recentes
@app.route('/5recentes')
def cinco_recentes():
    """Página das 5 vulnerabilidades mais recentes"""
    try:
        response = nvd_client.get_recent_cves(
            days=7,
            start_index=0,
            results_per_page=5
        )

        vulnerabilidades = []

        if response and 'vulnerabilities' in response:
            vulnerabilidades = response['vulnerabilities'][:5]  # Garantir apenas 5

            # Traduzir descrições
            for vuln in vulnerabilidades:
                if 'cve' in vuln and 'descriptions' in vuln['cve']:
                    for desc in vuln['cve']['descriptions']:
                        if desc.get('lang') == 'en' and desc.get('value'):
                            try:
                                translated = translator.translate_text(desc['value'])
                                desc['value_pt'] = translated
                            except Exception as e:
                                logging.warning(f"Erro na tradução: {e}")
                                desc['value_pt'] = desc['value']

        return render_template('5recentes.html', vulnerabilidades=vulnerabilidades)

    except Exception as e:
        logging.error(f"Erro ao carregar 5 CVEs recentes: {str(e)}")
        flash(f"Erro ao carregar 5 vulnerabilidades recentes: {str(e)}", "error")
        return redirect(url_for('index'))

# Filtros personalizados para templates
@app.template_filter('translate_severity')
def filter_translate_severity(severity):
    return translate_severity(severity)

@app.template_filter('translate_cwe')
def filter_translate_cwe(cwe_id):
    return translate_cwe(cwe_id)

@app.template_filter('translate_cvss_metrics')
def filter_translate_cvss_metrics(term):
    return translate_cvss_metrics(term)

@app.template_filter('format_date')
def filter_format_date(date_string):
    return format_date(date_string)

@app.template_filter('extract_cvss_score')
def filter_extract_cvss_score(metrics):
    return extract_cvss_score(metrics)

@app.template_filter('extract_severity')
def filter_extract_severity(metrics):
    return extract_severity(metrics)

@app.template_filter('extract_vector_string')
def filter_extract_vector_string(metrics):
    return extract_vector_string(metrics)

@app.template_filter('clean_cpe_name')
def filter_clean_cpe_name(cpe_name):
    return clean_cpe_name(cpe_name)

@app.template_filter('translate_status')
def filter_translate_status(status):
    """Traduz status de vulnerabilidade para português"""
    status_translations = {
        'Awaiting Analysis': 'Aguardando Análise',
        'Undergoing Analysis': 'Em Análise',
        'Analyzed': 'Analisado',
        'Modified': 'Modificado',
        'Deferred': 'Adiado',
        'Published': 'Publicado',
        'Rejected': 'Rejeitado',
        'Received': 'Recebido',
        'Reserved': 'Reservado'
    }
    return status_translations.get(status, status)

@app.route('/doacao')
def doacao():
    """Página de doações para o BNVD"""
    return render_template('doacao.html')

@app.route('/busca-por-ano')
def busca_por_ano():
    """Página de busca por ano com estatísticas"""
    try:
        # Buscar estatísticas do banco de dados
        db = VulnerabilityDatabase(database_url=os.environ.get('DATABASE_URL'))

        # Buscar vulnerabilidades por ano usando raw SQL
        db._ensure_connection()

        try:
            # Contar vulnerabilidades por ano
            import psycopg2.extras
            cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            cursor.execute("""
                SELECT year, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY year 
                ORDER BY year DESC
            """)
            years_data = []
            rows = cursor.fetchall()
            for row in rows:
                years_data.append({
                    'year': row['year'],
                    'count': row['count']
                })

            # Estatísticas gerais
            cursor.execute("SELECT COUNT(*) as total FROM vulnerabilities")
            result = cursor.fetchone()
            total_vulnerabilities = result['total'] if result else 0

            cursor.execute("SELECT COUNT(DISTINCT year) as total FROM vulnerabilities")
            result = cursor.fetchone()
            total_years = result['total'] if result else 0

            cursor.execute("SELECT COUNT(*) as total FROM translations")
            result = cursor.fetchone()
            total_translations = result['total'] if result else 0

            cursor.close()

        except Exception as e:
            logging.error(f"Erro na consulta SQL: {e}")
            years_data = []
            total_vulnerabilities = 0
            total_years = 0
            total_translations = 0
        finally:
            db.close()

        return render_template('busca-por-ano.html',
                             years_data=years_data,
                             total_vulnerabilities=total_vulnerabilities,
                             total_years=total_years,
                             total_translations=total_translations)

    except Exception as e:
        logging.error(f"Erro ao buscar dados por ano: {e}")
        flash('Erro ao carregar dados por ano', 'error')
        return redirect(url_for('index'))

@app.route('/vulnerabilidades/<int:year>')
def vulnerabilidades_por_ano(year):
    """Página listando vulnerabilidades de um ano específico com paginação"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 20  # Reduzir para paginação adequada
        offset = (page - 1) * per_page

        # Buscar vulnerabilidades do ano específico
        db = VulnerabilityDatabase(database_url=os.environ.get('DATABASE_URL'))

        db._ensure_connection()

        try:
            import psycopg2.extras
            cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Contar total de vulnerabilidades do ano
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM vulnerabilities 
                WHERE year = %s
            """, (year,))
            total_count = cursor.fetchone()['total']

            # Buscar vulnerabilidades paginadas
            cursor.execute("""
                SELECT cve_id, year, published_date, last_modified, vulnStatus, cvss_metrics
                FROM vulnerabilities 
                WHERE year = %s
                ORDER BY published_date DESC
                LIMIT %s OFFSET %s
            """, (year, per_page, offset))

            vulnerabilities = []
            rows = cursor.fetchall()
            for row in rows:
                # cvss_metrics já é um dict quando vem do banco
                cvss_metrics = row['cvss_metrics'] if row['cvss_metrics'] else None

                vulnerabilities.append({
                    'cve_id': row['cve_id'],
                    'year': row['year'],
                    'published_date': row['published_date'],
                    'last_modified': row['last_modified'],
                    'vulnStatus': row['vulnstatus'],
                    'cvss_metrics': cvss_metrics
                })

            cursor.close()

        except Exception as e:
            logging.error(f"Erro na consulta de vulnerabilidades do ano {year}: {e}")
            vulnerabilities = []
            total_count = 0
        finally:
            db.close()

        # Calcular informações de paginação
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 0

        return render_template('vulnerabilidades-por-ano.html',
                             year=year,
                             vulnerabilities=vulnerabilities,
                             page=page,
                             total_pages=total_pages,
                             per_page=per_page,
                             total_count=total_count)

    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades do ano {year}: {e}")
        flash(f'Erro ao carregar vulnerabilidades do ano {year}', 'error')
        return redirect(url_for('busca_por_ano'))

@app.route('/noticias')
def noticias():
    """Página com as 5 notícias mais recentes de segurança cibernética"""
    try:
        news = get_recent_news(5)
        return render_template('noticias.html', noticias=news)
    except Exception as e:
        logging.error(f"Erro ao carregar notícias: {e}")
        flash('Erro ao carregar notícias', 'error')
        return redirect(url_for('index'))

@app.route('/ver-todas-noticias')
def ver_todas_noticias():
    """Página com todas as notícias do mês com paginação"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 5

        all_news = get_month_news()
        total_news = len(all_news)

        # Calcular paginação
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        news = all_news[start_idx:end_idx]

        total_pages = (total_news + per_page - 1) // per_page if total_news > 0 else 0

        return render_template('ver-todas-noticias.html', 
                             noticias=news,
                             page=page,
                             total_pages=total_pages,
                             total_news=total_news)
    except Exception as e:
        logging.error(f"Erro ao carregar notícias: {e}")
        flash('Erro ao carregar notícias', 'error')
        return redirect(url_for('index'))

@app.route('/noticias/conteudo')
def noticias_conteudo():
    """Retorna o conteúdo completo de uma notícia"""
    try:
        link = request.args.get('link', '')
        if not link:
            return jsonify({'error': 'Link não fornecido'}), 400

        content = get_news_content(link)
        return jsonify({'content': content})
    except Exception as e:
        logging.error(f"Erro ao buscar conteúdo da notícia: {e}")
        return jsonify({'error': 'Erro ao carregar conteúdo'}), 500

@app.route('/noticia/<slug>')
def noticia_detalhes(slug):
    """Página individual de notícia com slug amigável"""
    try:
        # Buscar notícia pelo slug
        from advisor import advisor_monitor
        news_list = advisor_monitor.load_news()

        noticia = None
        for news in news_list:
            if news.get('slug') == slug:
                noticia = news
                break

        if not noticia:
            flash('Notícia não encontrada', 'error')
            return redirect(url_for('noticias'))

        # Renderizar template individual da notícia
        template_path = f'noticias/{slug}.html'

        # Verificar se o template existe
        import os
        full_template_path = os.path.join('templates', 'noticias', f'{slug}.html')
        if not os.path.exists(full_template_path):
            # Se o HTML não existe, gerar agora
            logging.info(f"Gerando HTML para notícia: {slug}")
            advisor_monitor.generate_news_html(noticia)

        # Renderizar template (HTML já está renderizado com os dados)
        return render_template(template_path)
    except Exception as e:
        logging.error(f"Erro ao carregar notícia {slug}: {e}")
        flash('Erro ao carregar notícia', 'error')
        return redirect(url_for('noticias'))

# ==================== ROTAS DE EXPORTAÇÃO ====================

from export import export_manager

@app.route('/export/vulnerability/<cve_id>/<format>')
def export_vulnerability(cve_id, format):
    """Exporta uma vulnerabilidade em diversos formatos"""
    try:
        # Validar formato
        if format not in export_manager.supported_formats:
            flash(f'Formato não suportado: {format}', 'error')
            return redirect(url_for('detalhes', cve_id=cve_id))

        # Buscar dados da vulnerabilidade
        response = nvd_client.get_cve(cve_id)

        if response and 'vulnerabilities' in response and len(response['vulnerabilities']) > 0:
            vulnerabilidade = response['vulnerabilities'][0]

            # Traduzir descrições para português (se disponível)
            if 'cve' in vulnerabilidade and 'descriptions' in vulnerabilidade['cve']:
                for desc in vulnerabilidade['cve']['descriptions']:
                    if desc.get('lang') == 'en' and desc.get('value'):
                        try:
                            original_text = desc['value']
                            translated = translator.translate_text(original_text)
                            desc['value_pt'] = translated
                        except Exception as e:
                            logging.error(f"Erro na tradução para exportação: {e}")
                            desc['value_pt'] = desc['value']

            # Exportar no formato especificado
            return export_manager.export_vulnerability(vulnerabilidade, format)
        else:
            flash(f'Vulnerabilidade {cve_id} não encontrada.', 'error')
            return redirect(url_for('busca'))

    except Exception as e:
        logging.error(f"Erro ao exportar CVE {cve_id} em formato {format}: {str(e)}")
        flash(f'Erro ao exportar vulnerabilidade: {str(e)}', 'error')
        return redirect(url_for('detalhes', cve_id=cve_id))

@app.route('/export/news/<slug>/<format>')
def export_news(slug, format):
    """Exporta uma notícia em diversos formatos"""
    try:
        # Validar formato
        if format not in export_manager.supported_formats:
            flash(f'Formato não suportado: {format}', 'error')
            return redirect(url_for('noticia_detalhes', slug=slug))

        # Buscar notícia pelo slug
        from advisor import advisor_monitor
        news_list = advisor_monitor.load_news()

        noticia = None
        for news in news_list:
            if news.get('slug') == slug:
                noticia = news
                break

        if not noticia:
            flash('Notícia não encontrada', 'error')
            return redirect(url_for('noticias'))

        # Exportar no formato especificado
        return export_manager.export_news(noticia, format)

    except Exception as e:
        logging.error(f"Erro ao exportar notícia {slug} em formato {format}: {str(e)}")
        flash(f'Erro ao exportar notícia: {str(e)}', 'error')
        return redirect(url_for('noticia_detalhes', slug=slug))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
