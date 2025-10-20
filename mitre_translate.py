
"""
Sistema de tradução dedicado para MITRE ATT&CK usando banco de dados e cache JSON
"""

import os
import json
import logging
import time
import requests
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MITRETranslator:
    """Tradutor especializado para conteúdo MITRE ATT&CK"""
    
    def __init__(self, database_url: str = None, cache_file: str = 'mitre-cache.json'):
        self.database_url = database_url
        self.cache_file = cache_file
        self.last_request_time = 0
        self.min_request_interval = 1.0  # 1 segundo entre requisições
        self.cache = {}  # Cache em memória
        
        # Carregar cache do arquivo JSON
        self._load_json_cache()
        
        # Conectar ao banco se disponível
        if database_url:
            try:
                from vulns import VulnerabilityDatabase
                self.db = VulnerabilityDatabase(database_url)
                logger.info("MITRE Translator conectado ao banco de dados")
            except Exception as e:
                logger.warning(f"Erro ao conectar ao banco: {e}. Usando apenas cache em memória")
                self.db = None
        else:
            self.db = None
            logger.info("MITRE Translator usando cache JSON e memória")
    
    def _load_json_cache(self):
        """Carrega cache de traduções do arquivo JSON"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                logger.info(f"Cache JSON carregado: {len(self.cache)} traduções")
            else:
                self.cache = {}
                logger.info("Arquivo de cache JSON não encontrado, criando novo")
        except Exception as e:
            logger.warning(f"Erro ao carregar cache JSON: {e}. Iniciando com cache vazio")
            self.cache = {}
    
    def _save_json_cache(self):
        """Salva cache de traduções no arquivo JSON"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
            logger.debug(f"Cache JSON salvo: {len(self.cache)} traduções")
        except Exception as e:
            logger.warning(f"Erro ao salvar cache JSON: {e}")
    
    def _rate_limit(self):
        """Implementa rate limiting básico"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _translate_via_google(self, text: str, target_lang: str = 'pt') -> Optional[str]:
        """Traduz usando Google Translate (free tier)"""
        try:
            self._rate_limit()
            
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
            logger.warning(f"Erro na tradução via Google: {e}")
            return None
    
    def translate_text(self, text: str, target_lang: str = 'pt') -> str:
        """
        Traduz texto para português usando cache JSON, banco de dados e Google Translate
        
        Args:
            text: Texto a ser traduzido
            target_lang: Idioma de destino
            
        Returns:
            Texto traduzido ou original se falhar
        """
        if not text or not text.strip():
            return text
        
        text = text.strip()
        cache_key = f"{text[:100]}_{target_lang}"
        
        # 1. Verificar cache em memória/JSON primeiro (mais rápido)
        if cache_key in self.cache:
            logger.debug(f"Tradução encontrada no cache JSON para: {text[:50]}...")
            return self.cache[cache_key]
        
        # 2. Buscar no banco de dados se disponível
        if self.db:
            try:
                cached_translation = self.db.get_translation(text, 'en', target_lang)
                if cached_translation:
                    logger.debug(f"Tradução encontrada no banco para: {text[:50]}...")
                    # Adicionar ao cache JSON para próximas consultas
                    self.cache[cache_key] = cached_translation
                    self._save_json_cache()
                    return cached_translation
            except Exception as e:
                logger.warning(f"Erro ao buscar tradução no banco: {e}")
        
        # 3. Traduzir via Google Translate
        logger.info(f"Traduzindo via Google: {text[:50]}...")
        translated = self._translate_via_google(text, target_lang)
        
        if translated and translated != text:
            # Salvar no cache JSON
            self.cache[cache_key] = translated
            self._save_json_cache()
            
            # Salvar no banco se disponível
            if self.db:
                try:
                    self.db.save_translation(text, translated, 'en', target_lang)
                except Exception as e:
                    logger.warning(f"Erro ao salvar tradução no banco: {e}")
            
            return translated
        else:
            # Se falhou, salvar o original para evitar tentar novamente
            self.cache[cache_key] = text
            self._save_json_cache()
            if self.db:
                try:
                    self.db.save_translation(text, text, 'en', target_lang)
                except Exception as e:
                    pass
            return text
    
    def translate_mitre_object(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traduz um objeto MITRE completo (técnica, grupo, mitigação, etc)
        
        Args:
            obj: Objeto MITRE com campos name e description
            
        Returns:
            Objeto com campos traduzidos (_pt)
        """
        translated_obj = obj.copy()
        
        # Traduzir nome
        if 'name' in obj and obj['name']:
            translated_obj['name_pt'] = self.translate_text(obj['name'])
        
        # Traduzir descrição completa
        if 'description' in obj and obj['description']:
            translated_obj['description_pt'] = self.translate_text(obj['description'])
        
        return translated_obj
    
    def close(self):
        """Fecha conexão com banco e salva cache JSON"""
        # Salvar cache JSON final antes de fechar
        self._save_json_cache()
        if self.db:
            self.db.close()
    
    def __del__(self):
        """Destructor para garantir fechamento da conexão"""
        self.close()

# Instância global do tradutor MITRE
mitre_translator = None

def initialize_mitre_translator(database_url: str = None):
    """Inicializa o tradutor MITRE"""
    global mitre_translator
    mitre_translator = MITRETranslator(database_url)
    logger.info("MITRE Translator inicializado")
    return mitre_translator
