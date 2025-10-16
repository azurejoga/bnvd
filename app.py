import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from dotenv import load_dotenv
from nvd_api import NVDClient
from utils import (translate_severity, translate_cwe, translate_cvss_metrics, format_date, paginate_results,
                 extract_cvss_score, extract_severity, extract_vector_string, 
                 extract_cwe_info, extract_description, extract_references, clean_cpe_name)
from translator import DatabaseTranslator
from vulns import VulnerabilityDatabase
from seo import SEOManager, init_seo_routes
from security import security_manager
from werkzeug.middleware.proxy_fix import ProxyFix                                                                      

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

# Criar aplicação Flask
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fallback-secret-key-for-dev")
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
        # Construir parâmetros básicos da API
        search_params = {}
        search_params['resultsPerPage'] = 20
        search_params['startIndex'] = start_index
        
        # Aplicar filtros (já validados pelo sistema de segurança)
        if cve_id:
            search_params['cveId'] = cve_id  # Já vem validado e formatado
        
        if severidade:
            search_params['cvssV3Severity'] = severidade  # Já validado
        
        if vendor:
            search_params['keywordSearch'] = vendor  # Já sanitizado
            logging.debug(f"Busca por fabricante: {vendor}")
        
        # Buscar vulnerabilidades apenas se há filtros
        response = None
        if has_filters:
            logging.debug(f"Parâmetros da busca: {search_params}")
            response = nvd_client.search_cves(**search_params)
            
            # Log da resposta para debug
            if response:
                total_results = response.get('totalResults', 0)
                logging.info(f"API NVD retornou {total_results} resultados para os parâmetros: {search_params}")
            else:
                logging.warning("API NVD retornou resposta vazia ou nula")
        
        if response and 'vulnerabilities' in response and len(response['vulnerabilities']) > 0:
            vulnerabilidades = response['vulnerabilities']
            total_results = response.get('totalResults', 0)
            
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
                         vendor=vendor)

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

@app.route('/downloads')
def downloads():
    """Página de downloads dos aplicativos"""
    return render_template('downloads.html')

@app.route('/api-docs')
def api_docs():
    """Página de documentação da API"""
    return render_template('api-docs.html')





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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)