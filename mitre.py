"""
BNVD - Sistema de Visualização MITRE ATT&CK
Processa JSONs do MITRE ATT&CK e traduz para português
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any
from mitre_translate import MITRETranslator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MITREProcessor:
    def __init__(self, translator_instance: MITRETranslator = None):
        self.enterprise_data = None
        self.mobile_data = None
        self.ics_data = None
        self.pre_attack_data = None
        self.translator = translator_instance
        
    def load_json_file(self, filepath: str) -> Optional[Dict]:
        """Carrega arquivo JSON do MITRE ATT&CK"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logger.warning(f"Arquivo não encontrado: {filepath}")
                return None
        except Exception as e:
            logger.error(f"Erro ao carregar {filepath}: {e}")
            return None
    
    def load_all_matrices(self):
        """Carrega todas as matrizes MITRE ATT&CK"""
        logger.info("Carregando matrizes MITRE ATT&CK...")
        
        self.enterprise_data = self.load_json_file('enterprise_attack.json')
        self.mobile_data = self.load_json_file('mobile_attack.json')
        self.ics_data = self.load_json_file('ics_attack.json')
        self.pre_attack_data = self.load_json_file('pre_attack_attack.json')
        
        logger.info("Matrizes carregadas com sucesso")
    
    def translate_text(self, text: str) -> str:
        """Traduz texto para português usando o translator"""
        if not text:
            return ""
        
        # Se não há tradutor disponível, retornar texto original
        if not self.translator:
            return text
        
        try:
            return self.translator.translate_text(text)
        except Exception as e:
            logger.error(f"Erro na tradução: {e}")
            return text
    
    def extract_techniques(self, data: Dict, translate: bool = True) -> List[Dict]:
        """Extrai técnicas do JSON"""
        techniques = []
        
        if not data or 'objects' not in data:
            return techniques
        
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated', False):
                technique = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'tactics': [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])],
                    'platforms': obj.get('x_mitre_platforms', []),
                    'url': obj.get('external_references', [{}])[0].get('url', ''),
                    'type': obj.get('type', ''),
                    'is_subtechnique': obj.get('x_mitre_is_subtechnique', False)
                }
                techniques.append(technique)
        
        return techniques
    
    def extract_tactics(self, data: Dict, translate: bool = True) -> List[Dict]:
        """Extrai táticas do JSON"""
        tactics = []
        
        if not data or 'objects' not in data:
            return tactics
        
        for obj in data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'shortname': obj.get('x_mitre_shortname', ''),
                    'url': obj.get('external_references', [{}])[0].get('url', '')
                }
                tactics.append(tactic)
        
        return tactics
    
    def extract_groups(self, data: Dict, translate: bool = True) -> List[Dict]:
        """Extrai grupos de ameaças do JSON"""
        groups = []
        
        if not data or 'objects' not in data:
            return groups
        
        for obj in data['objects']:
            if obj.get('type') == 'intrusion-set' and not obj.get('revoked', False):
                group = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'aliases': obj.get('aliases', []),
                    'url': obj.get('external_references', [{}])[0].get('url', '')
                }
                groups.append(group)
        
        return groups
    
    def extract_mitigations(self, data: Dict, translate: bool = True) -> List[Dict]:
        """Extrai mitigações do JSON"""
        mitigations = []
        
        if not data or 'objects' not in data:
            return mitigations
        
        for obj in data['objects']:
            if obj.get('type') == 'course-of-action' and not obj.get('revoked', False):
                mitigation = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'url': obj.get('external_references', [{}])[0].get('url', '')
                }
                mitigations.append(mitigation)
        
        return mitigations
    
    def get_matrix_data(self, matrix_type: str = 'enterprise', translate: bool = True) -> Dict:
        """Retorna dados estruturados de uma matriz específica"""
        data_map = {
            'enterprise': self.enterprise_data,
            'mobile': self.mobile_data,
            'ics': self.ics_data,
            'pre-attack': self.pre_attack_data
        }
        
        data = data_map.get(matrix_type)
        
        if not data:
            logger.warning(f"Matriz {matrix_type} não encontrada")
            return {}
        
        logger.info(f"Processando matriz {matrix_type}...")
        
        # Extrair dados com tradução opcional
        tactics = self.extract_tactics(data, translate)
        techniques = self.extract_techniques(data, translate)
        groups = self.extract_groups(data, translate)
        mitigations = self.extract_mitigations(data, translate)
        
        # Organizar técnicas por tática
        techniques_by_tactic = {}
        for technique in techniques:
            for tactic in technique.get('tactics', []):
                if tactic not in techniques_by_tactic:
                    techniques_by_tactic[tactic] = []
                techniques_by_tactic[tactic].append(technique)
        
        # Separar técnicas e subtécnicas
        main_techniques = [t for t in techniques if not t.get('is_subtechnique')]
        subtechniques = [t for t in techniques if t.get('is_subtechnique')]
        
        matrix_info = {
            'type': matrix_type,
            'name': f'MITRE ATT&CK - {matrix_type.title()}',
            'name_pt': f'MITRE ATT&CK - {matrix_type.title()}',  # Não traduzir nome da matriz
            'tactics': tactics,
            'techniques': main_techniques,
            'subtechniques': subtechniques,
            'techniques_by_tactic': techniques_by_tactic,
            'groups': groups,
            'mitigations': mitigations,
            'total_tactics': len(tactics),
            'total_techniques': len(main_techniques),
            'total_subtechniques': len(subtechniques),
            'total_groups': len(groups),
            'total_mitigations': len(mitigations)
        }
        
        logger.info(f"Matriz {matrix_type} processada: {len(main_techniques)} técnicas, {len(subtechniques)} subtécnicas, {len(groups)} grupos")
        
        return matrix_info
    
    def get_all_matrices_summary(self, translate: bool = True) -> Dict:
        """Retorna resumo de todas as matrizes"""
        return {
            'enterprise': self.get_matrix_summary('enterprise', translate),
            'mobile': self.get_matrix_summary('mobile', translate),
            'ics': self.get_matrix_summary('ics', translate),
            'pre_attack': self.get_matrix_summary('pre-attack', translate)
        }
    
    def get_matrix_summary(self, matrix_type: str, translate: bool = True) -> Dict:
        """Retorna resumo de uma matriz"""
        matrix_data = self.get_matrix_data(matrix_type, translate=False)  # Sem traduzir para resumo
        
        return {
            'name': matrix_data.get('name', ''),
            'total_tactics': matrix_data.get('total_tactics', 0),
            'total_techniques': matrix_data.get('total_techniques', 0),
            'total_subtechniques': matrix_data.get('total_subtechniques', 0),
            'total_groups': matrix_data.get('total_groups', 0),
            'total_mitigations': matrix_data.get('total_mitigations', 0)
        }

# Instância global do processador MITRE (será inicializado em app.py com o tradutor)
mitre_processor = None

def initialize_mitre(translator_instance: MITRETranslator = None):
    """Inicializa o processador MITRE com o tradutor"""
    global mitre_processor
    mitre_processor = MITREProcessor(translator_instance)
    mitre_processor.load_all_matrices()
    logger.info("Processador MITRE inicializado")
    return mitre_processor
