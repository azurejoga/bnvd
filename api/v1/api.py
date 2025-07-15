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
    """Retorna conexão com banco de dados"""
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        raise Exception("DATABASE_URL não configurado")
    
    try:
        db = VulnerabilityDatabase(database_url)
        db._ensure_connection()
        return db
    except Exception as e:
        logging.error(f"Erro ao conectar com banco: {e}")
        raise

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
        'base_url': 'https://3bb1226b-7326-450c-9718-7460474e3bb4-00-hlsekyfc3ju1.kirk.replit.dev/api/v1',
        'endpoints': {
            'vulnerabilities': {
                'GET /vulnerabilities': 'Lista todas as vulnerabilidades (paginado)',
                'GET /vulnerabilities/<cve_id>': 'Busca vulnerabilidade específica por CVE ID',
                'parameters': ['page', 'per_page', 'year', 'severity', 'vendor']
            },
            'search': {
                'GET /search/recent': 'Vulnerabilidades recentes (últimos 7 dias)',
                'GET /search/recent/5': 'As 5 vulnerabilidades mais recentes',
                'GET /search/year/<year>': 'Vulnerabilidades por ano',
                'GET /search/severity/<severity>': 'Vulnerabilidades por severidade',
                'GET /search/vendor/<vendor>': 'Vulnerabilidades por vendor/fabricante'
            },
            'statistics': {
                'GET /stats': 'Estatísticas gerais do banco de dados',
                'GET /stats/years': 'Estatísticas por ano'
            }
        },
        'parameters': {
            'page': 'Número da página (padrão: 1)',
            'per_page': 'Resultados por página (padrão: 20, máximo: 100)',
            'format': 'Formato de resposta (json)',
            'include_pt': 'Incluir traduções em português (true/false)'
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