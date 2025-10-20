"""
BNVD API v1 - Banco Nacional de Vulnerabilidades Cibernéticas
API REST para acesso programático às vulnerabilidades de segurança
"""

import os
import json
import logging
from flask import Blueprint, request, jsonify, url_for
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import psycopg2
import psycopg2.extras
from vulns import VulnerabilityDatabase
from security import security_manager

# Criar blueprint para API v1
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

def get_portuguese_description(cve_id: str, original_description: str) -> Optional[str]:
    """Busca tradução portuguesa específica para a descrição de uma vulnerabilidade"""
    try:
        logging.debug(f"Buscando tradução para {cve_id}, texto: {original_description[:100]}...")
        
        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            logging.warning("DATABASE_URL não configurado")
            return None
        
        # Conectar diretamente ao banco para buscar traduções
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Buscar tradução específica da descrição
        cursor.execute("""
            SELECT translated_text 
            FROM translations 
            WHERE original_text = %s 
            AND lang_from = 'en' 
            AND lang_to = 'pt'
            LIMIT 1
        """, (original_description,))
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            logging.debug(f"Tradução encontrada para {cve_id}: {result[0][:100]}...")
            return result[0]
        else:
            logging.debug(f"Nenhuma tradução encontrada para {cve_id}")
            return None
        
    except Exception as e:
        logging.error(f"Erro ao buscar tradução para {cve_id}: {e}")
        return None

def get_database_connection():
    """Retorna conexão com banco de dados ou None se não disponível"""
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        logging.warning("DATABASE_URL não configurado - endpoints de banco de dados não disponíveis")
        return None
    
    try:
        db = VulnerabilityDatabase(database_url)
        db._ensure_connection()
        return db
    except Exception as e:
        logging.error(f"Erro ao conectar com banco: {e}")
        return None

def format_vulnerability_response(vuln_data: Dict, include_pt: bool = True) -> Dict:
    """Formata dados de vulnerabilidade para resposta da API"""
    formatted_data = {
        'cve_id': vuln_data.get('cve_id'),
        'year': vuln_data.get('year'),
        'published_date': vuln_data.get('published_date').isoformat() if vuln_data.get('published_date') and hasattr(vuln_data.get('published_date'), 'isoformat') else str(vuln_data.get('published_date')) if vuln_data.get('published_date') else None,
        'last_modified': vuln_data.get('last_modified').isoformat() if vuln_data.get('last_modified') and hasattr(vuln_data.get('last_modified'), 'isoformat') else str(vuln_data.get('last_modified')) if vuln_data.get('last_modified') else None,
        'status': vuln_data.get('vulnstatus'),
        'descriptions': vuln_data.get('descriptions'),
        'cvss_metrics': vuln_data.get('cvss_metrics'),
        'weaknesses': vuln_data.get('weaknesses'),
        'configurations': vuln_data.get('configurations'),
        'references': vuln_data.get('cve_cve_references'),
        'created_at': vuln_data.get('created_at').isoformat() if vuln_data.get('created_at') and hasattr(vuln_data.get('created_at'), 'isoformat') else str(vuln_data.get('created_at')) if vuln_data.get('created_at') else None,
        'updated_at': vuln_data.get('updated_at').isoformat() if vuln_data.get('updated_at') and hasattr(vuln_data.get('updated_at'), 'isoformat') else str(vuln_data.get('updated_at')) if vuln_data.get('updated_at') else None
    }
    
    # Adicionar tradução portuguesa se solicitada
    if include_pt:
        # Buscar tradução específica no banco para a descrição da vulnerabilidade
        descriptions_pt = None
        if vuln_data.get('descriptions'):
            try:
                descriptions_data = vuln_data.get('descriptions')
                if isinstance(descriptions_data, str):
                    descriptions_data = json.loads(descriptions_data)
                
                # Buscar descrição em inglês
                english_desc = None
                if isinstance(descriptions_data, list):
                    for desc in descriptions_data:
                        if desc.get('lang') == 'en':
                            english_desc = desc.get('value')
                            break
                
                if english_desc and vuln_data.get('cve_id'):
                    # Buscar tradução específica no banco
                    pt_translation = get_portuguese_description(vuln_data.get('cve_id'), english_desc)
                    if pt_translation:
                        descriptions_pt = [{'lang': 'pt', 'value': pt_translation}]
                    
            except Exception as e:
                logging.error(f"Erro ao processar tradução para {vuln_data.get('cve_id')}: {e}")
        
        formatted_data['descriptions_pt'] = descriptions_pt or vuln_data.get('descriptions_pt')
    
    return formatted_data

@api_v1.route('/')
def api_root():
    """Documentação da API v1"""
    return jsonify({
        'name': 'BNVD API v1',
        'description': 'Banco Nacional de Vulnerabilidades Cibernéticas - API REST',
        'version': '1.0.0',
        'base_url': 'https://bnvd.org/api/v1',
        'github': 'https://github.com/azurejoga/bnvd',
        'api_clients': 'https://github.com/azurejoga/bnvd/tree/main/api_clients',
        'endpoints': {
            'vulnerabilities': {
                'GET /vulnerabilities': 'Lista todas as vulnerabilidades (paginado)',
                'GET /vulnerabilities/<cve_id>': 'Busca vulnerabilidade específica por CVE ID',
                'parameters': ['page', 'per_page', 'year', 'severity', 'vendor', 'include_pt']
            },
            'search': {
                'GET /search/recent': 'Vulnerabilidades recentes (últimos N dias)',
                'GET /search/recent/5': 'As 5 vulnerabilidades mais recentes',
                'GET /search/year/<year>': 'Vulnerabilidades por ano',
                'GET /search/severity/<severity>': 'Vulnerabilidades por severidade (LOW, MEDIUM, HIGH, CRITICAL)',
                'GET /search/vendor/<vendor>': 'Vulnerabilidades por vendor/fabricante'
            },
            'statistics': {
                'GET /stats': 'Estatísticas gerais do banco de dados',
                'GET /stats/years': 'Estatísticas detalhadas por ano'
            },
            'noticias': {
                'GET /noticias': 'Lista todas as notícias de segurança cibernética (paginado)',
                'GET /noticias/recentes': 'Retorna as notícias mais recentes (padrão: 5)',
                'GET /noticias/<slug>': 'Retorna uma notícia específica pelo slug',
                'parameters': ['page', 'per_page', 'limit']
            },
            'mitre': {
                'GET /mitre': 'Informações sobre os endpoints MITRE ATT&CK',
                'GET /mitre/matrices': 'Lista todas as matrizes disponíveis (enterprise, mobile, ics, pre-attack)',
                'GET /mitre/matrix/<type>': 'Dados completos de uma matriz específica',
                'GET /mitre/techniques': 'Lista todas as técnicas',
                'GET /mitre/technique/<id>': 'Detalhes de uma técnica específica',
                'GET /mitre/subtechniques': 'Lista todas as subtécnicas',
                'GET /mitre/groups': 'Lista todos os grupos de ameaças',
                'GET /mitre/group/<id>': 'Detalhes de um grupo específico',
                'GET /mitre/mitigations': 'Lista todas as mitigações',
                'GET /mitre/mitigation/<id>': 'Detalhes de uma mitigação específica',
                'parameters': ['matrix', 'tactic', 'platform', 'translate']
            }
        },
        'parameters': {
            'page': 'Número da página (padrão: 1)',
            'per_page': 'Resultados por página (padrão: 20, máximo: 100)',
            'limit': 'Número de resultados (usado em endpoints específicos)',
            'format': 'Formato de resposta (json)',
            'include_pt': 'Incluir traduções em português (true/false)',
            'translate': 'Traduzir conteúdo MITRE para português (true/false)',
            'matrix': 'Tipo de matriz MITRE (enterprise, mobile, ics, pre-attack)',
            'tactic': 'Filtrar técnicas por tática',
            'platform': 'Filtrar por plataforma'
        },
        'response_format': {
            'success': {
                'status': 'success',
                'data': '...',
                'pagination': {
                    'page': 1,
                    'per_page': 20,
                    'total': 100,
                    'pages': 5
                }
            },
            'error': {
                'status': 'error',
                'message': 'Descrição do erro',
                'code': 400
            }
        },
        'examples': {
            'vulnerabilities': {
                'list': '/api/v1/vulnerabilities?page=1&per_page=20&include_pt=true',
                'specific': '/api/v1/vulnerabilities/CVE-2024-12345',
                'by_year': '/api/v1/search/year/2024',
                'by_severity': '/api/v1/search/severity/CRITICAL',
                'recent': '/api/v1/search/recent?days=7'
            },
            'noticias': {
                'list': '/api/v1/noticias?page=1&per_page=20',
                'recent': '/api/v1/noticias/recentes?limit=5',
                'specific': '/api/v1/noticias/slug-da-noticia'
            },
            'mitre': {
                'matrices': '/api/v1/mitre/matrices',
                'enterprise': '/api/v1/mitre/matrix/enterprise?translate=true',
                'techniques': '/api/v1/mitre/techniques?matrix=enterprise&tactic=initial-access',
                'specific_technique': '/api/v1/mitre/technique/T1566',
                'groups': '/api/v1/mitre/groups?matrix=enterprise',
                'mitigations': '/api/v1/mitre/mitigations?matrix=enterprise'
            }
        }
    })

@api_v1.route('/vulnerabilities')
def list_vulnerabilities():
    """Lista todas as vulnerabilidades com paginação e filtros"""
    try:
        # Parâmetros de paginação
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Filtros
        year = request.args.get('year')
        severity = request.args.get('severity')
        vendor = request.args.get('vendor')
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Construir query base
        where_conditions = ["1=1"]
        params = []
        
        # Aplicar filtros
        if year:
            where_conditions.append("year = %s")
            params.append(int(year))
        
        if severity:
            where_conditions.append("cvss_metrics::text ILIKE %s")
            params.append(f'%{severity}%')
        
        if vendor:
            where_conditions.append("(descriptions::text ILIKE %s OR configurations::text ILIKE %s)")
            params.extend([f'%{vendor}%', f'%{vendor}%'])
        
        where_clause = " WHERE " + " AND ".join(where_conditions)
        
        # Contar total de resultados
        count_query = f"SELECT COUNT(*) FROM vulnerabilities{where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['count']
        
        # Buscar dados paginados
        data_query = f"SELECT * FROM vulnerabilities{where_clause} ORDER BY published_date DESC LIMIT %s OFFSET %s"
        offset = (page - 1) * per_page
        cursor.execute(data_query, params + [per_page, offset])
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row), include_pt)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        # Calcular paginação
        total_pages = (total_count + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            },
            'filters_applied': {
                'year': year,
                'severity': severity,
                'vendor': vendor,
                'include_pt': include_pt
            }
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar vulnerabilidades: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/vulnerabilities/<cve_id>')
def get_vulnerability(cve_id):
    """Busca vulnerabilidade específica por CVE ID"""
    try:
        # Validar CVE ID
        if not security_manager.validate_cve_id(cve_id):
            return jsonify({
                'status': 'error',
                'message': f'CVE ID inválido: {cve_id}',
                'code': 400
            }), 400
        
        # Validar parâmetros de query
        for param_name, param_value in request.args.items():
            if security_manager.detect_sql_injection(str(param_value)):
                logging.warning(f"SQL injection detectado na API: {param_name}={param_value}")
                return jsonify({
                    'status': 'error',
                    'message': 'Parâmetros de entrada inválidos',
                    'code': 400
                }), 400
            
            if security_manager.detect_xss(str(param_value)):
                logging.warning(f"XSS detectado na API: {param_name}={param_value}")
                return jsonify({
                    'status': 'error',
                    'message': 'Parâmetros de entrada inválidos',
                    'code': 400
                }), 400
        
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = %s", (cve_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({
                'status': 'error',
                'message': f'Vulnerabilidade {cve_id} não encontrada',
                'code': 404
            }), 404
        
        vuln_data = format_vulnerability_response(dict(row), include_pt)
        
        cursor.close()
        db.close()
        
        return jsonify({
            'status': 'success',
            'data': vuln_data
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidade {cve_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/search/recent')
def search_recent():
    """Vulnerabilidades recentes (últimos 7 dias)"""
    try:
        days = min(int(request.args.get('days', 7)), 30)  # Máximo 30 dias
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Data limite
        date_limit = datetime.now() - timedelta(days=days)
        
        # Contar total
        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE published_date >= %s
        """, (date_limit,))
        total_count = cursor.fetchone()['count']
        
        # Buscar dados
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE published_date >= %s 
            ORDER BY published_date DESC 
            LIMIT %s OFFSET %s
        """, (date_limit, per_page, offset))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row))
            if not include_pt:
                vuln_data.pop('descriptions_pt', None)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        total_pages = (total_count + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': total_pages
            },
            'search_params': {
                'days': days,
                'date_limit': date_limit.isoformat()
            }
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades recentes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/search/recent/5')
def search_recent_5():
    """As 5 vulnerabilidades mais recentes"""
    try:
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            ORDER BY published_date DESC 
            LIMIT 5
        """)
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row))
            if not include_pt:
                vuln_data.pop('descriptions_pt', None)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'count': len(vulnerabilities)
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar 5 vulnerabilidades recentes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/search/year/<int:year>')
def search_by_year(year):
    """Vulnerabilidades por ano específico"""
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Contar total
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE year = %s", (year,))
        total_count = cursor.fetchone()['count']
        
        # Buscar dados
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE year = %s 
            ORDER BY published_date DESC 
            LIMIT %s OFFSET %s
        """, (year, per_page, offset))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row))
            if not include_pt:
                vuln_data.pop('descriptions_pt', None)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        total_pages = (total_count + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': total_pages
            },
            'year': year
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades do ano {year}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/search/severity/<severity>')
def search_by_severity(severity):
    """Vulnerabilidades por severidade CVSS"""
    try:
        # Validar severidade
        valid_severity = security_manager.validate_severity(severity)
        if not valid_severity:
            return jsonify({
                'status': 'error',
                'message': f'Severidade inválida: {severity}. Use: LOW, MEDIUM, HIGH, CRITICAL',
                'code': 400
            }), 400
        
        # Validar parâmetros de query
        for param_name, param_value in request.args.items():
            if security_manager.detect_sql_injection(str(param_value)):
                logging.warning(f"SQL injection detectado na API: {param_name}={param_value}")
                return jsonify({
                    'status': 'error',
                    'message': 'Parâmetros de entrada inválidos',
                    'code': 400
                }), 400
        
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Contar total
        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE cvss_metrics::text ILIKE %s
        """, (f'%{severity}%',))
        total_count = cursor.fetchone()['count']
        
        # Buscar dados
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE cvss_metrics::text ILIKE %s 
            ORDER BY published_date DESC 
            LIMIT %s OFFSET %s
        """, (f'%{severity}%', per_page, offset))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row))
            if not include_pt:
                vuln_data.pop('descriptions_pt', None)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        total_pages = (total_count + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': total_pages
            },
            'severity': severity
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades por severidade {severity}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/search/vendor/<vendor>')
def search_by_vendor(vendor):
    """Vulnerabilidades por vendor/fabricante"""
    try:
        # Validar vendor (busca de texto)
        clean_vendor = security_manager.validate_search_query(vendor)
        if not clean_vendor:
            return jsonify({
                'status': 'error',
                'message': f'Termo de busca inválido: {vendor}',
                'code': 400
            }), 400
        
        # Validar parâmetros de query
        for param_name, param_value in request.args.items():
            if security_manager.detect_sql_injection(str(param_value)):
                logging.warning(f"SQL injection detectado na API: {param_name}={param_value}")
                return jsonify({
                    'status': 'error',
                    'message': 'Parâmetros de entrada inválidos',
                    'code': 400
                }), 400
        
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        include_pt = request.args.get('include_pt', 'true').lower() == 'true'
        
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Contar total
        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE descriptions::text ILIKE %s OR configurations::text ILIKE %s
        """, (f'%{vendor}%', f'%{vendor}%'))
        total_count = cursor.fetchone()['count']
        
        # Buscar dados
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE descriptions::text ILIKE %s OR configurations::text ILIKE %s 
            ORDER BY published_date DESC 
            LIMIT %s OFFSET %s
        """, (f'%{vendor}%', f'%{vendor}%', per_page, offset))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln_data = format_vulnerability_response(dict(row))
            if not include_pt:
                vuln_data.pop('descriptions_pt', None)
            vulnerabilities.append(vuln_data)
        
        cursor.close()
        db.close()
        
        total_pages = (total_count + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': total_pages
            },
            'vendor': vendor
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar vulnerabilidades por vendor {vendor}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/stats')
def get_statistics():
    """Estatísticas gerais do banco de dados"""
    try:
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Estatísticas gerais
        cursor.execute("SELECT COUNT(*) as total_vulnerabilities FROM vulnerabilities")
        total_vulns = cursor.fetchone()['total_vulnerabilities']
        
        cursor.execute("SELECT COUNT(DISTINCT year) as total_years FROM vulnerabilities")
        total_years = cursor.fetchone()['total_years']
        
        cursor.execute("SELECT COUNT(*) as total_translations FROM translations")
        total_translations = cursor.fetchone()['total_translations']
        
        # Vulnerabilidades por ano
        cursor.execute("""
            SELECT year, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY year 
            ORDER BY year DESC
        """)
        years_stats = [{'year': row['year'], 'count': row['count']} for row in cursor.fetchall()]
        
        # Últimas atualizações
        cursor.execute("""
            SELECT MAX(created_at) as last_created, MAX(updated_at) as last_updated 
            FROM vulnerabilities
        """)
        last_updates = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_vulnerabilities': total_vulns,
                'total_years': total_years,
                'total_translations': total_translations,
                'years_distribution': years_stats,
                'last_created': last_updates['last_created'].isoformat() if last_updates['last_created'] else None,
                'last_updated': last_updates['last_updated'].isoformat() if last_updates['last_updated'] else None,
                'database_status': 'operational'
            }
        })
        
    except Exception as e:
        logging.error(f"Erro ao obter estatísticas: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/stats/years')
def get_years_statistics():
    """Estatísticas detalhadas por ano"""
    try:
        # Conectar ao banco
        db = get_database_connection()
        if not db:
            return jsonify({
                'status': 'error',
                'message': 'Banco de dados não disponível. Este endpoint requer configuração de DATABASE_URL.',
                'code': 503
            }), 503
            
        cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute("""
            SELECT 
                year,
                COUNT(*) as total_count,
                COUNT(CASE WHEN cvss_metrics IS NOT NULL THEN 1 END) as with_cvss,
                COUNT(CASE WHEN descriptions_pt IS NOT NULL THEN 1 END) as with_translations,
                MIN(published_date) as first_published,
                MAX(published_date) as last_published
            FROM vulnerabilities 
            GROUP BY year 
            ORDER BY year DESC
        """)
        
        years_data = []
        for row in cursor.fetchall():
            years_data.append({
                'year': row['year'],
                'total_vulnerabilities': row['total_count'],
                'with_cvss_metrics': row['with_cvss'],
                'with_translations': row['with_translations'],
                'first_published': row['first_published'].isoformat() if row['first_published'] else None,
                'last_published': row['last_published'].isoformat() if row['last_published'] else None
            })
        
        cursor.close()
        db.close()
        
        return jsonify({
            'status': 'success',
            'data': years_data
        })
        
    except Exception as e:
        logging.error(f"Erro ao obter estatísticas por ano: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

# ==================== ENDPOINTS DE NOTÍCIAS ====================

@api_v1.route('/noticias')
def list_noticias():
    """Lista todas as notícias"""
    try:
        from advisor import get_all_news
        
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        all_news = get_all_news()
        
        if not all_news:
            return jsonify({
                'status': 'success',
                'data': [],
                'total': 0,
                'message': 'Nenhuma notícia disponível'
            })
        
        # Paginação
        total = len(all_news)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_news = all_news[start:end]
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'status': 'success',
            'data': paginated_news,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar notícias: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/noticias/recentes')
def noticias_recentes():
    """Retorna as 5 notícias mais recentes"""
    try:
        from advisor import get_recent_news
        
        limit = min(int(request.args.get('limit', 5)), 20)
        recent_news = get_recent_news(limit)
        
        return jsonify({
            'status': 'success',
            'data': recent_news,
            'count': len(recent_news)
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar notícias recentes: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/noticias/<slug>')
def get_noticia(slug):
    """Retorna uma notícia específica pelo slug"""
    try:
        from advisor import get_news_by_slug
        
        news = get_news_by_slug(slug)
        
        if not news:
            return jsonify({
                'status': 'error',
                'message': f'Notícia não encontrada: {slug}',
                'code': 404
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': news
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar notícia {slug}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

# ==================== ENDPOINTS DE MITRE ATT&CK ====================

@api_v1.route('/mitre')
def mitre_info():
    """Informações sobre os endpoints MITRE ATT&CK"""
    return jsonify({
        'status': 'success',
        'name': 'MITRE ATT&CK API',
        'description': 'API para acesso aos dados do MITRE ATT&CK',
        'endpoints': {
            'GET /mitre/matrices': 'Lista todas as matrizes disponíveis',
            'GET /mitre/matrix/<type>': 'Dados completos de uma matriz (enterprise, mobile, ics, pre-attack)',
            'GET /mitre/techniques': 'Lista todas as técnicas',
            'GET /mitre/technique/<id>': 'Detalhes de uma técnica específica',
            'GET /mitre/subtechniques': 'Lista todas as subtécnicas',
            'GET /mitre/groups': 'Lista todos os grupos de ameaças',
            'GET /mitre/group/<id>': 'Detalhes de um grupo específico',
            'GET /mitre/mitigations': 'Lista todas as mitigações',
            'GET /mitre/mitigation/<id>': 'Detalhes de uma mitigação específica'
        },
        'filters': {
            'matrix': 'Filtrar por matriz (enterprise, mobile, ics, pre-attack)',
            'tactic': 'Filtrar técnicas por tática',
            'platform': 'Filtrar por plataforma'
        }
    })

@api_v1.route('/mitre/matrices')
def list_mitre_matrices():
    """Lista todas as matrizes MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        summary = mitre_processor.get_all_matrices_summary(translate=False)
        
        return jsonify({
            'status': 'success',
            'data': summary
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar matrizes MITRE: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/matrix/<matrix_type>')
def get_mitre_matrix(matrix_type):
    """Retorna dados completos de uma matriz MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        valid_matrices = ['enterprise', 'mobile', 'ics', 'pre-attack']
        if matrix_type not in valid_matrices:
            return jsonify({
                'status': 'error',
                'message': f'Matriz inválida. Opções: {", ".join(valid_matrices)}',
                'code': 400
            }), 400
        
        translate = request.args.get('translate', 'false').lower() == 'true'
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        
        return jsonify({
            'status': 'success',
            'data': matrix_data
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar matriz {matrix_type}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/techniques')
def list_mitre_techniques():
    """Lista todas as técnicas MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        tactic = request.args.get('tactic')
        platform = request.args.get('platform')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        techniques = matrix_data.get('techniques', [])
        
        # Filtrar por tática se especificada
        if tactic:
            techniques = [t for t in techniques if tactic in t.get('tactics', [])]
        
        # Filtrar por plataforma se especificada
        if platform:
            techniques = [t for t in techniques if platform.lower() in [p.lower() for p in t.get('platforms', [])]]
        
        return jsonify({
            'status': 'success',
            'data': techniques,
            'count': len(techniques),
            'filters': {
                'matrix': matrix_type,
                'tactic': tactic,
                'platform': platform
            }
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar técnicas MITRE: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/technique/<technique_id>')
def get_mitre_technique(technique_id):
    """Retorna detalhes de uma técnica específica"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        techniques = matrix_data.get('techniques', []) + matrix_data.get('subtechniques', [])
        
        # Buscar técnica pelo ID
        technique = next((t for t in techniques if t.get('id') == technique_id.upper()), None)
        
        if not technique:
            return jsonify({
                'status': 'error',
                'message': f'Técnica {technique_id} não encontrada',
                'code': 404
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': technique
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar técnica {technique_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/subtechniques')
def list_mitre_subtechniques():
    """Lista todas as subtécnicas MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        subtechniques = matrix_data.get('subtechniques', [])
        
        return jsonify({
            'status': 'success',
            'data': subtechniques,
            'count': len(subtechniques)
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar subtécnicas MITRE: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/groups')
def list_mitre_groups():
    """Lista todos os grupos de ameaças MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        groups = matrix_data.get('groups', [])
        
        return jsonify({
            'status': 'success',
            'data': groups,
            'count': len(groups)
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar grupos MITRE: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/group/<group_id>')
def get_mitre_group(group_id):
    """Retorna detalhes de um grupo específico"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        groups = matrix_data.get('groups', [])
        
        # Buscar grupo pelo ID
        group = next((g for g in groups if g.get('id') == group_id.upper()), None)
        
        if not group:
            return jsonify({
                'status': 'error',
                'message': f'Grupo {group_id} não encontrado',
                'code': 404
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': group
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar grupo {group_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/mitigations')
def list_mitre_mitigations():
    """Lista todas as mitigações MITRE ATT&CK"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        mitigations = matrix_data.get('mitigations', [])
        
        return jsonify({
            'status': 'success',
            'data': mitigations,
            'count': len(mitigations)
        })
        
    except Exception as e:
        logging.error(f"Erro ao listar mitigações MITRE: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

@api_v1.route('/mitre/mitigation/<mitigation_id>')
def get_mitre_mitigation(mitigation_id):
    """Retorna detalhes de uma mitigação específica"""
    try:
        from mitre import mitre_processor
        
        if not mitre_processor:
            return jsonify({
                'status': 'error',
                'message': 'Sistema MITRE ATT&CK não disponível',
                'code': 503
            }), 503
        
        matrix_type = request.args.get('matrix', 'enterprise')
        translate = request.args.get('translate', 'false').lower() == 'true'
        
        matrix_data = mitre_processor.get_matrix_data(matrix_type, translate=translate)
        mitigations = matrix_data.get('mitigations', [])
        
        # Buscar mitigação pelo ID
        mitigation = next((m for m in mitigations if m.get('id') == mitigation_id.upper()), None)
        
        if not mitigation:
            return jsonify({
                'status': 'error',
                'message': f'Mitigação {mitigation_id} não encontrada',
                'code': 404
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': mitigation
        })
        
    except Exception as e:
        logging.error(f"Erro ao buscar mitigação {mitigation_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'code': 500
        }), 500

# Error handlers para o blueprint
@api_v1.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint não encontrado',
        'code': 404
    }), 404

@api_v1.errorhandler(400)
def bad_request(error):
    return jsonify({
        'status': 'error',
        'message': 'Requisição inválida',
        'code': 400
    }), 400

@api_v1.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Erro interno do servidor',
        'code': 500
    }), 500