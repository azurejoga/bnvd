"""
Sistema de banco de dados para vulnerabilidades do BNVD
Gerencia conexões, consultas, inserções e atualizações de CVEs organizados por ano
"""

import os
import psycopg2
import psycopg2.extras
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

class VulnerabilityDatabase:
    """Classe para gerenciar o banco de dados de vulnerabilidades"""
    
    def __init__(self, database_url: str):
        if not database_url:
            raise ValueError("DATABASE_URL não encontrada nas variáveis de ambiente")
        
        self.database_url = database_url
        self.connection = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Estabelece conexão com o banco de dados"""
        try:
            self.connection = psycopg2.connect(
                self.database_url,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            self.connection.autocommit = True
            logging.info("Conexão com banco de dados estabelecida")
        except Exception as e:
            logging.error(f"Erro ao conectar com banco de dados: {e}")
            raise
    
    def _ensure_connection(self):
        """Garante que a conexão está ativa"""
        try:
            if self.connection is None or self.connection.closed:
                self._connect()
            else:
                # Testa a conexão
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
        except:
            # Reconecta se houver problema
            self._connect()
    
    def _create_tables(self):
        """Cria tabelas necessárias se não existirem"""
        if not self.connection:
            raise Exception("Conexão com banco não estabelecida")
            
        try:
            cursor = self.connection.cursor()
            
            # Tabela principal de vulnerabilidades
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) UNIQUE NOT NULL,
                    year INTEGER NOT NULL,
                    published_date TIMESTAMP,
                    last_modified TIMESTAMP,
                    vulnStatus VARCHAR(50),
                    descriptions JSONB,
                    descriptions_pt JSONB,
                    cvss_metrics JSONB,
                    weaknesses JSONB,
                    configurations JSONB,
                    cve_cve_references JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Índices para otimização
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id 
                ON vulnerabilities(cve_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_year 
                ON vulnerabilities(year)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_last_modified 
                ON vulnerabilities(last_modified)
            """)
            
            # Tabela para traduções específicas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS translations (
                    id SERIAL PRIMARY KEY,
                    original_text TEXT NOT NULL,
                    translated_text TEXT NOT NULL,
                    lang_from VARCHAR(5) DEFAULT 'en',
                    lang_to VARCHAR(5) DEFAULT 'pt',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(original_text, lang_from, lang_to)
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_translations_original 
                ON translations(original_text)
            """)
            
            cursor.close()
            logging.info("Tabelas do banco de dados criadas/verificadas com sucesso")
                
        except Exception as e:
            logging.error(f"Erro ao criar tabelas: {e}")
            raise
    
    def get_vulnerability_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Busca vulnerabilidade por CVE ID no banco
        
        Args:
            cve_id: ID da vulnerabilidade (ex: CVE-2025-26326)
            
        Returns:
            Dicionário com dados da vulnerabilidade ou None se não encontrada
        """
        if not cve_id:
            return None
            
        try:
            self._ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT * FROM vulnerabilities 
                WHERE cve_id = %s
            """, (cve_id,))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return dict(result)
            return None
            
        except Exception as e:
            logging.error(f"Erro ao buscar CVE {cve_id}: {e}")
            return None
    
    def insert_or_update_vulnerability(self, cve_data: Dict[str, Any]) -> bool:
        """
        Insere ou atualiza vulnerabilidade no banco
        
        Args:
            cve_data: Dados da vulnerabilidade vindos da API NVD
            
        Returns:
            True se operação foi bem-sucedida, False caso contrário
        """
        try:
            self._ensure_connection()
            
            # Extrai dados básicos - ajusta para estrutura da API NVD
            # Se cve_data já é o objeto CVE direto
            if 'id' in cve_data:
                cve_obj = cve_data
            # Se cve_data é a resposta completa da API
            elif 'vulnerabilities' in cve_data and cve_data['vulnerabilities']:
                cve_obj = cve_data['vulnerabilities'][0]['cve']
            else:
                logging.error("Estrutura de dados CVE inválida")
                return False
                
            cve_id = cve_obj.get('id', '')
            if not cve_id:
                logging.error("CVE ID não encontrado nos dados")
                return False
                
            # Extrai ano do CVE ID automaticamente (formato CVE-YYYY-NNNNN)
            year = self._extract_year_from_cve_id(cve_id)
            
            published_date = self._parse_date(cve_obj.get('published'))
            last_modified = self._parse_date(cve_obj.get('lastModified'))
            
            logging.debug(f"Inserindo CVE {cve_id}: year={year}, published={published_date}, modified={last_modified}")
            
            # Dados para inserção
            cursor = self.connection.cursor()
            
            cursor.execute("""
                INSERT INTO vulnerabilities (
                    cve_id, year, published_date, last_modified, vulnStatus,
                    descriptions, cvss_metrics, weaknesses, configurations, 
                    cve_cve_references, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (cve_id) DO UPDATE SET
                    last_modified = EXCLUDED.last_modified,
                    vulnStatus = EXCLUDED.vulnStatus,
                    descriptions = EXCLUDED.descriptions,
                    cvss_metrics = EXCLUDED.cvss_metrics,
                    weaknesses = EXCLUDED.weaknesses,
                    configurations = EXCLUDED.configurations,
                    cve_cve_references = EXCLUDED.cve_cve_references,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                cve_id,
                year,
                published_date,
                last_modified,
                cve_obj.get('vulnStatus', ''),
                json.dumps(cve_obj.get('descriptions', [])),
                json.dumps(cve_obj.get('metrics', {})),
                json.dumps(cve_obj.get('weaknesses', [])),
                json.dumps(cve_obj.get('configurations', [])),
                json.dumps(cve_obj.get('references', []))
            ))
            
            cursor.close()
            return True
            
        except Exception as e:
            logging.error(f"Erro ao inserir/atualizar CVE: {e}")
            return False
    
    def save_translation(self, original_text: str, translated_text: str, 
                        lang_from: str = 'en', lang_to: str = 'pt') -> bool:
        """
        Salva tradução no banco de dados
        
        Args:
            original_text: Texto original
            translated_text: Texto traduzido
            lang_from: Idioma de origem
            lang_to: Idioma de destino
            
        Returns:
            True se salvo com sucesso, False caso contrário
        """
        if not original_text or not translated_text:
            return False
            
        try:
            self._ensure_connection()
            cursor = self.connection.cursor()
            
            cursor.execute("""
                INSERT INTO translations (original_text, translated_text, lang_from, lang_to)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (original_text, lang_from, lang_to) 
                DO UPDATE SET 
                    translated_text = EXCLUDED.translated_text,
                    created_at = CURRENT_TIMESTAMP
            """, (original_text, translated_text, lang_from, lang_to))
            
            cursor.close()
            return True
            
        except Exception as e:
            logging.error(f"Erro ao salvar tradução: {e}")
            return False
    
    def get_translation(self, original_text: str, lang_from: str = 'en', 
                       lang_to: str = 'pt') -> Optional[str]:
        """
        Busca tradução no banco de dados
        
        Args:
            original_text: Texto original
            lang_from: Idioma de origem
            lang_to: Idioma de destino
            
        Returns:
            Texto traduzido ou None se não encontrado
        """
        if not original_text:
            return None
            
        try:
            self._ensure_connection()
            cursor = self.connection.cursor()
            
            cursor.execute("""
                SELECT translated_text FROM translations 
                WHERE original_text = %s AND lang_from = %s AND lang_to = %s
            """, (original_text, lang_from, lang_to))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return result[0]  # Usar índice em vez de chave
            return None
            
        except Exception as e:
            logging.error(f"Erro ao buscar tradução: {e}")
            return None
    
    def _extract_year_from_cve_id(self, cve_id: str) -> int:
        """Extrai o ano do CVE-ID (ex: CVE-2025-26326 -> 2025)"""
        try:
            if cve_id and 'CVE-' in cve_id:
                parts = cve_id.split('-')
                if len(parts) >= 2:
                    year = int(parts[1])
                    # Validar que o ano está em um range razoável (1999-2030)
                    if 1999 <= year <= 2030:
                        return year
            return 2000  # Default fallback
        except (ValueError, IndexError):
            return 2000  # Default fallback
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Converte string de data ISO para datetime"""
        if not date_str:
            return None
            
        try:
            # Remove timezone info se presente
            if date_str.endswith('Z'):
                date_str = date_str[:-1]
            elif '+' in date_str:
                date_str = date_str.split('+')[0]
            elif date_str.count('-') > 2:  # Detecta timezone negativo
                parts = date_str.split('-')
                if len(parts) > 3:
                    date_str = '-'.join(parts[:3]) + 'T' + parts[3].split('T')[1] if 'T' in parts[3] else '-'.join(parts[:3])
            
            # Tenta diferentes formatos
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S', 
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
                    
            return None
        except Exception:
            return None
    
    def close(self):
        """Fecha conexão com banco de dados"""
        try:
            if self.connection and not self.connection.closed:
                self.connection.close()
                logging.info("Conexão com banco de dados fechada")
        except Exception as e:
            logging.error(f"Erro ao fechar conexão: {e}")
    
    def __del__(self):
        """Destructor para garantir fechamento da conexão"""
        self.close()