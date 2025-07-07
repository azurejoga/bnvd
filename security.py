"""
Sistema de segurança para o BNVD
Proteção contra SQL injection, XSS e outras vulnerabilidades
"""

import re
import html
import logging
from typing import Optional, Any, Dict, List
from markupsafe import escape

class SecurityManager:
    """Gerenciador de segurança para validação e sanitização de entrada"""
    
    # Padrões de CVE válidos
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
    
    # Padrões suspeitos de SQL injection
    SQL_INJECTION_PATTERNS = [
        r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+',
        r'union\s+select',
        r'insert\s+into',
        r'delete\s+from',
        r'drop\s+table',
        r'update\s+set',
        r'create\s+table',
        r'alter\s+table',
        r'exec\s*\(',
        r'execute\s*\(',
        r'sp_\w+',
        r'xp_\w+',
        r'--\s*$',
        r'/\*.*\*/',
        r';\s*(drop|delete|insert|update|create|alter)',
        r'(\'|\")(\s*;\s*)*(drop|delete|insert|update|create|alter)',
        r'(\bor\b|\band\b)\s+(\'|\")?\w*(\'|\")?\s*=\s*(\'|\")?\w*(\'|\")?'
    ]
    
    # Padrões suspeitos de XSS
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<form[^>]*>',
        r'<meta[^>]*>',
        r'<link[^>]*>',
        r'<style[^>]*>.*?</style>',
        r'<base[^>]*>',
        r'vbscript:',
        r'data:text/html',
        r'expression\s*\(',
        r'url\s*\(',
        r'@import'
    ]
    
    def __init__(self):
        """Inicializa o gerenciador de segurança"""
        self.sql_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.XSS_PATTERNS]
    
    def validate_cve_id(self, cve_id: str) -> bool:
        """
        Valida se o CVE ID está no formato correto
        
        Args:
            cve_id: ID da vulnerabilidade
            
        Returns:
            True se válido, False caso contrário
        """
        if not cve_id or not isinstance(cve_id, str):
            return False
        
        return bool(self.CVE_PATTERN.match(cve_id.upper()))
    
    def sanitize_input(self, text: str, max_length: int = 1000) -> str:
        """
        Sanitiza entrada do usuário para prevenir XSS
        
        Args:
            text: Texto a ser sanitizado
            max_length: Tamanho máximo permitido
            
        Returns:
            Texto sanitizado
        """
        if not text or not isinstance(text, str):
            return ""
        
        # Truncar se muito longo
        if len(text) > max_length:
            text = text[:max_length]
        
        # Escapar HTML para prevenir XSS
        text = html.escape(text, quote=True)
        
        # Remover caracteres de controle
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        return text.strip()
    
    def detect_sql_injection(self, text: str) -> bool:
        """
        Detecta possíveis tentativas de SQL injection
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            True se suspeito, False caso contrário
        """
        if not text or not isinstance(text, str):
            return False
        
        text_lower = text.lower()
        
        # Verificar padrões suspeitos
        for regex in self.sql_regex:
            if regex.search(text_lower):
                logging.warning(f"Possível SQL injection detectado: {text}")
                return True
        
        return False
    
    def detect_xss(self, text: str) -> bool:
        """
        Detecta possíveis tentativas de XSS
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            True se suspeito, False caso contrário
        """
        if not text or not isinstance(text, str):
            return False
        
        # Verificar padrões suspeitos
        for regex in self.xss_regex:
            if regex.search(text):
                logging.warning(f"Possível XSS detectado: {text}")
                return True
        
        return False
    
    def validate_year(self, year: Any) -> Optional[int]:
        """
        Valida e converte ano para inteiro
        
        Args:
            year: Ano a ser validado
            
        Returns:
            Ano válido ou None
        """
        if not year:
            return None
        
        try:
            year_int = int(year)
            if 1999 <= year_int <= 2030:  # Range razoável para CVEs
                return year_int
        except (ValueError, TypeError):
            pass
        
        return None
    
    def validate_page_number(self, page: Any) -> int:
        """
        Valida número da página
        
        Args:
            page: Número da página
            
        Returns:
            Número da página válido (mínimo 1)
        """
        try:
            page_int = int(page)
            return max(1, page_int)
        except (ValueError, TypeError):
            return 1
    
    def validate_per_page(self, per_page: Any, max_limit: int = 100) -> int:
        """
        Valida número de resultados por página
        
        Args:
            per_page: Número de resultados por página
            max_limit: Limite máximo permitido
            
        Returns:
            Número válido de resultados por página
        """
        try:
            per_page_int = int(per_page)
            return min(max(1, per_page_int), max_limit)
        except (ValueError, TypeError):
            return 20
    
    def validate_severity(self, severity: str) -> Optional[str]:
        """
        Valida severidade CVSS
        
        Args:
            severity: Severidade a ser validada
            
        Returns:
            Severidade válida ou None
        """
        if not severity or not isinstance(severity, str):
            return None
        
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        severity_upper = severity.upper()
        
        if severity_upper in valid_severities:
            return severity_upper
        
        return None
    
    def validate_search_query(self, query: str, max_length: int = 200) -> Optional[str]:
        """
        Valida query de busca
        
        Args:
            query: Query de busca
            max_length: Tamanho máximo
            
        Returns:
            Query sanitizada ou None se suspeita
        """
        if not query or not isinstance(query, str):
            return None
        
        # Detectar ataques
        if self.detect_sql_injection(query) or self.detect_xss(query):
            return None
        
        # Sanitizar
        sanitized = self.sanitize_input(query, max_length)
        
        # Verificar se não está vazia após sanitização
        if not sanitized:
            return None
        
        return sanitized
    
    def secure_request_params(self, request_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitiza todos os parâmetros de uma requisição
        
        Args:
            request_args: Dicionário com parâmetros da requisição
            
        Returns:
            Dicionário com parâmetros sanitizados
        """
        secure_params = {}
        
        for key, value in request_args.items():
            if not isinstance(key, str) or not value:
                continue
            
            # Sanitizar key
            safe_key = self.sanitize_input(key, 50)
            if not safe_key:
                continue
            
            # Processar diferentes tipos de valores
            if key.lower() == 'cve_id':
                if self.validate_cve_id(str(value)):
                    secure_params[safe_key] = str(value).upper()
            elif key.lower() == 'year':
                valid_year = self.validate_year(value)
                if valid_year:
                    secure_params[safe_key] = valid_year
            elif key.lower() == 'page':
                secure_params[safe_key] = self.validate_page_number(value)
            elif key.lower() == 'per_page':
                secure_params[safe_key] = self.validate_per_page(value)
            elif key.lower() == 'severity':
                valid_severity = self.validate_severity(str(value))
                if valid_severity:
                    secure_params[safe_key] = valid_severity
            elif key.lower() in ['search', 'keyword', 'query', 'vendor']:
                safe_value = self.validate_search_query(str(value))
                if safe_value:
                    secure_params[safe_key] = safe_value
            elif key.lower() == 'include_pt':
                secure_params[safe_key] = str(value).lower() == 'true'
            else:
                # Para outros parâmetros, aplicar sanitização básica
                safe_value = self.sanitize_input(str(value), 100)
                if safe_value:
                    secure_params[safe_key] = safe_value
        
        return secure_params

# Instância global do gerenciador de segurança
security_manager = SecurityManager()