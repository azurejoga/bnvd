"""
Sistema de tradução integrado com banco de dados para o BNVD
"""

import os
import logging
import time
import requests
from typing import Optional
from vulns import VulnerabilityDatabase

class DatabaseTranslator:
    """Tradutor que armazena traduções no banco de dados"""
    
    def __init__(self, database_url: str):
        self.db = VulnerabilityDatabase(database_url)
        self.last_request_time = 0
        self.min_request_interval = 1.0  # 1 segundo entre requisições
        
    def _rate_limit(self):
        """Implementa rate limiting básico"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _is_likely_portuguese(self, text: str) -> bool:
        """Verifica se o texto já está provavelmente em português"""
        if not text or len(text) < 10:
            return False
        
        # Palavras comuns em português (mais específicas)
        portuguese_words = [
            'vulnerabilidade', 'segurança', 'aplicação', 'execução', 'configuração', 
            'autenticação', 'autorização', 'através', 'é possível', 'permite que',
            'possibilita', 'invasores', 'atacantes', 'explorar', 'comprometer',
            'usuários', 'servidores', 'aplicações', 'sistemas', 'códigos',
            'senhas', 'chaves', 'certificados', 'protocolos', 'dados',
            'informações', 'arquivos', 'conexões', 'privilégios',
            'injeção', 'execução', 'remotamente', 'localmente'
        ]
        
        # Palavras que indicam claramente inglês
        english_words = [
            'vulnerability', 'security', 'application', 'execution', 'authentication',
            'authorization', 'allows', 'enables', 'attacker', 'exploit',
            'remote', 'local', 'injection', 'cross-site', 'scripting',
            'privilege', 'escalation', 'bypass', 'disclosure', 'injection',
            'buffer', 'overflow', 'arbitrary', 'execute', 'command'
        ]
        
        text_lower = text.lower()
        portuguese_count = sum(1 for word in portuguese_words if word in text_lower)
        english_count = sum(1 for word in english_words if word in text_lower)
        
        # Se tem mais palavras em inglês do que em português, não está em português
        # Ou se tem muitas palavras claramente em inglês, não está em português
        if english_count > portuguese_count or english_count >= 5:
            return False
        
        # Se tem pelo menos 3 palavras portuguesas específicas, provavelmente está em português
        return portuguese_count >= 3
    
    def _translate_via_google(self, text: str, target_lang: str = 'pt') -> Optional[str]:
        """Traduz usando Google Translate (free tier)"""
        try:
            self._rate_limit()
            
            # URL da API gratuita do Google Translate
            url = "https://translate.googleapis.com/translate_a/single"
            params = {
                'client': 'gtx',
                'sl': 'en',
                'tl': target_lang,
                'dt': 't',
                'q': text
            }
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result and len(result) > 0 and result[0]:
                    translated_parts = []
                    for part in result[0]:
                        if part[0]:
                            translated_parts.append(part[0])
                    
                    translated_text = ''.join(translated_parts)
                    if translated_text and translated_text.strip():
                        return translated_text.strip()
            
            return None
            
        except Exception as e:
            logging.warning(f"Erro na tradução via Google: {e}")
            return None
    
    def translate_text(self, text: str, target_lang: str = 'pt') -> str:
        """
        Traduz texto para português usando cache do banco primeiro
        
        Args:
            text: Texto a ser traduzido
            target_lang: Idioma de destino
            
        Returns:
            Texto traduzido ou original se falhar
        """
        if not text or not text.strip():
            return text
        
        text = text.strip()
        
        # Verificar se já está em português
        if self._is_likely_portuguese(text):
            logging.debug("Texto já parece estar em português, pulando tradução")
            return text
        
        # Buscar tradução no banco
        cached_translation = self.db.get_translation(text, 'en', target_lang)
        if cached_translation:
            logging.debug("Tradução encontrada no banco de dados")
            return cached_translation
        
        # Se não tem no banco, traduzir
        logging.debug("Traduzindo texto via Google Translate")
        translated = self._translate_via_google(text, target_lang)
        
        if translated and translated != text:
            # Salvar tradução no banco
            self.db.save_translation(text, translated, 'en', target_lang)
            return translated
        else:
            # Se falhou, salvar o original para evitar tentar traduzir novamente
            self.db.save_translation(text, text, 'en', target_lang)
            return text
    
    def force_translate_text(self, text: str, target_lang: str = 'pt') -> str:
        """
        Força tradução sem usar cache (para garantir tradução)
        
        Args:
            text: Texto a ser traduzido
            target_lang: Idioma de destino
            
        Returns:
            Texto traduzido ou original se falhar
        """
        if not text or not text.strip():
            return text
        
        text = text.strip()
        
        # Verificar se já está em português
        if self._is_likely_portuguese(text):
            return text
        
        # Traduzir sem usar cache
        translated = self._translate_via_google(text, target_lang)
        
        if translated and translated != text:
            # Salvar/atualizar tradução no banco
            self.db.save_translation(text, translated, 'en', target_lang)
            return translated
        else:
            return text
    
    def translate_cve_description(self, description: str) -> str:
        """
        Traduz descrição de CVE com tratamento especial
        
        Args:
            description: Descrição da vulnerabilidade
            
        Returns:
            Descrição traduzida
        """
        if not description:
            return description
        
        # Para descrições de CVE, sempre tentar traduzir
        return self.translate_text(description, 'pt')
    
    def close(self):
        """Fecha conexão com banco"""
        if self.db:
            self.db.close()
    
    def __del__(self):
        """Destructor para garantir fechamento da conexão"""
        self.close()

# Instância global do tradutor (será inicializada no app.py)
translator = None