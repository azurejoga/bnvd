#!/usr/bin/env python3
"""
BNVD CLI - Interface de linha de comando para o Banco Nacional de Vulnerabilidades Ciberneticas

Uso:
    bnvd-cli buscar <termo>              Busca vulnerabilidades por termo
    bnvd-cli cve <cve_id>                Busca CVE especifico
    bnvd-cli recentes [--dias N]         Lista vulnerabilidades recentes
    bnvd-cli severidade <nivel>          Filtra por severidade (LOW, MEDIUM, HIGH, CRITICAL)
    bnvd-cli vendor <fabricante>         Busca por fabricante
    bnvd-cli stats                       Mostra estatisticas do banco
    bnvd-cli export <cve_id> [--formato] Exporta CVE para arquivo

Exemplos:
    bnvd-cli buscar apache
    bnvd-cli cve CVE-2024-12345
    bnvd-cli recentes --dias 7
    bnvd-cli severidade CRITICAL
    bnvd-cli vendor Microsoft
    bnvd-cli export CVE-2024-12345 --formato json
"""

import argparse
import json
import sys
import os
from datetime import datetime
from typing import Optional, Dict, Any, List

try:
    import requests
except ImportError:
    print("Erro: O modulo 'requests' e necessario. Instale com: pip install requests")
    sys.exit(1)

BNVD_API_URL = os.environ.get('BNVD_API_URL', 'https://bnvd.org/api/v1')
VERSION = '1.0.0'

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def colorize(text: str, color: str) -> str:
    """Aplica cor ao texto se terminal suportar"""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text

def severity_color(severity: str) -> str:
    """Retorna cor baseada na severidade"""
    colors = {
        'CRITICAL': Colors.RED,
        'HIGH': Colors.YELLOW,
        'MEDIUM': Colors.CYAN,
        'LOW': Colors.GREEN
    }
    return colors.get(severity.upper(), Colors.WHITE)

class BNVDClient:
    """Cliente para a API BNVD"""
    
    def __init__(self, api_url: str = BNVD_API_URL):
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'BNVD-CLI/{VERSION}',
            'Accept': 'application/json'
        })
    
    def _request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Faz requisicao a API"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            print(colorize("Erro: Timeout na conexao com a API BNVD", Colors.RED))
            return None
        except requests.exceptions.ConnectionError:
            print(colorize("Erro: Falha na conexao com a API BNVD", Colors.RED))
            return None
        except requests.exceptions.HTTPError as e:
            print(colorize(f"Erro HTTP: {e}", Colors.RED))
            return None
        except json.JSONDecodeError:
            print(colorize("Erro: Resposta invalida da API", Colors.RED))
            return None
    
    def get_vulnerability(self, cve_id: str) -> Optional[Dict]:
        """Busca vulnerabilidade especifica por CVE ID"""
        return self._request(f'/vulnerabilities/{cve_id}', {'include_pt': 'true'})
    
    def search_vulnerabilities(self, **kwargs) -> Optional[Dict]:
        """Busca vulnerabilidades com filtros"""
        params = {'include_pt': 'true', 'per_page': kwargs.get('limit', 20)}
        
        if kwargs.get('vendor'):
            params['vendor'] = kwargs['vendor']
        if kwargs.get('severity'):
            params['severity'] = kwargs['severity']
        if kwargs.get('year'):
            params['year'] = kwargs['year']
        if kwargs.get('page'):
            params['page'] = kwargs['page']
        
        return self._request('/vulnerabilities', params)
    
    def get_recent(self, days: int = 7, limit: int = 10) -> Optional[Dict]:
        """Busca vulnerabilidades recentes"""
        return self._request('/search/recent', {'days': days, 'limit': limit})
    
    def get_by_severity(self, severity: str, limit: int = 20) -> Optional[Dict]:
        """Busca vulnerabilidades por severidade"""
        return self._request(f'/search/severity/{severity}', {'per_page': limit})
    
    def get_by_vendor(self, vendor: str, limit: int = 20) -> Optional[Dict]:
        """Busca vulnerabilidades por vendor"""
        return self._request(f'/search/vendor/{vendor}', {'per_page': limit})
    
    def get_stats(self) -> Optional[Dict]:
        """Retorna estatisticas do banco"""
        return self._request('/stats')

def format_vulnerability(vuln: Dict, detailed: bool = False) -> str:
    """Formata vulnerabilidade para exibicao"""
    lines = []
    
    cve_id = vuln.get('cve_id', 'N/A')
    lines.append(colorize(f"\n{'='*60}", Colors.BLUE))
    lines.append(colorize(f"  {cve_id}", Colors.BOLD + Colors.WHITE))
    lines.append(colorize(f"{'='*60}", Colors.BLUE))
    
    cvss_metrics = vuln.get('cvss_metrics', {})
    if isinstance(cvss_metrics, str):
        try:
            cvss_metrics = json.loads(cvss_metrics)
        except:
            cvss_metrics = {}
    
    score = None
    severity = None
    
    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if version in cvss_metrics:
            metrics = cvss_metrics[version]
            if isinstance(metrics, list) and len(metrics) > 0:
                cvss_data = metrics[0].get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                break
    
    if score and severity:
        sev_color = severity_color(severity)
        lines.append(f"  Score CVSS: {colorize(f'{score}/10.0', Colors.BOLD)} ({colorize(severity, sev_color)})")
    
    published = vuln.get('published_date')
    if published:
        if isinstance(published, str):
            lines.append(f"  Publicado: {published[:10]}")
    
    last_modified = vuln.get('last_modified')
    if last_modified:
        if isinstance(last_modified, str):
            lines.append(f"  Atualizado: {last_modified[:10]}")
    
    descriptions = vuln.get('descriptions', [])
    descriptions_pt = vuln.get('descriptions_pt', [])
    
    if isinstance(descriptions, str):
        try:
            descriptions = json.loads(descriptions)
        except:
            descriptions = []
    
    if descriptions_pt and len(descriptions_pt) > 0:
        desc_text = descriptions_pt[0].get('value', '')
        if desc_text:
            lines.append(colorize("\n  Descricao (PT):", Colors.GREEN))
            wrapped = _wrap_text(desc_text, 56, "    ")
            lines.append(wrapped)
    elif descriptions:
        for desc in descriptions:
            if desc.get('lang') == 'en':
                desc_text = desc.get('value', '')
                if desc_text:
                    lines.append(colorize("\n  Descricao (EN):", Colors.YELLOW))
                    wrapped = _wrap_text(desc_text, 56, "    ")
                    lines.append(wrapped)
                break
    
    if detailed:
        weaknesses = vuln.get('weaknesses', [])
        if isinstance(weaknesses, str):
            try:
                weaknesses = json.loads(weaknesses)
            except:
                weaknesses = []
        
        if weaknesses:
            lines.append(colorize("\n  CWE (Tipos de Fraqueza):", Colors.MAGENTA))
            for weakness in weaknesses[:3]:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        lines.append(f"    - {desc.get('value', 'N/A')}")
        
        lines.append(colorize(f"\n  Link BNVD:", Colors.CYAN))
        lines.append(f"    https://bnvd.org/vulnerabilidade/{cve_id}")
        
        lines.append(colorize(f"\n  Analisar com IA:", Colors.GREEN))
        lines.append(f"    https://chat.openai.com/?q=Analise%20{cve_id}")
    
    return '\n'.join(lines)

def _wrap_text(text: str, width: int, prefix: str = "") -> str:
    """Quebra texto em linhas"""
    words = text.split()
    lines = []
    current_line = prefix
    
    for word in words:
        if len(current_line) + len(word) + 1 <= width + len(prefix):
            if current_line == prefix:
                current_line += word
            else:
                current_line += ' ' + word
        else:
            if current_line != prefix:
                lines.append(current_line)
            current_line = prefix + word
    
    if current_line != prefix:
        lines.append(current_line)
    
    return '\n'.join(lines)

def cmd_buscar(args):
    """Busca vulnerabilidades por termo"""
    client = BNVDClient()
    
    print(colorize(f"\nBuscando vulnerabilidades com termo: {args.termo}", Colors.CYAN))
    
    result = client.search_vulnerabilities(vendor=args.termo, limit=args.limit)
    
    if not result:
        print(colorize("Nenhum resultado encontrado ou erro na busca.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    vulnerabilities = result.get('data', [])
    
    if not vulnerabilities:
        print(colorize("Nenhuma vulnerabilidade encontrada.", Colors.YELLOW))
        return 0
    
    pagination = result.get('pagination', {})
    total = pagination.get('total', len(vulnerabilities))
    
    print(colorize(f"\nEncontradas {total} vulnerabilidades:", Colors.GREEN))
    
    for vuln in vulnerabilities:
        print(format_vulnerability(vuln))
    
    return 0

def cmd_cve(args):
    """Busca CVE especifico"""
    client = BNVDClient()
    cve_id = args.cve_id.upper()
    
    if not cve_id.startswith('CVE-'):
        cve_id = f'CVE-{cve_id}'
    
    print(colorize(f"\nBuscando {cve_id}...", Colors.CYAN))
    
    result = client.get_vulnerability(cve_id)
    
    if not result:
        print(colorize(f"Vulnerabilidade {cve_id} nao encontrada.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    vuln = result.get('data')
    if vuln:
        print(format_vulnerability(vuln, detailed=True))
    else:
        print(colorize(f"Vulnerabilidade {cve_id} nao encontrada.", Colors.YELLOW))
        return 1
    
    return 0

def cmd_recentes(args):
    """Lista vulnerabilidades recentes"""
    client = BNVDClient()
    
    print(colorize(f"\nBuscando vulnerabilidades dos ultimos {args.dias} dias...", Colors.CYAN))
    
    result = client.get_recent(days=args.dias, limit=args.limit)
    
    if not result:
        print(colorize("Erro ao buscar vulnerabilidades recentes.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    vulnerabilities = result.get('data', [])
    
    if not vulnerabilities:
        print(colorize("Nenhuma vulnerabilidade recente encontrada.", Colors.YELLOW))
        return 0
    
    print(colorize(f"\n{len(vulnerabilities)} vulnerabilidades recentes:", Colors.GREEN))
    
    for vuln in vulnerabilities:
        print(format_vulnerability(vuln))
    
    return 0

def cmd_severidade(args):
    """Filtra por severidade"""
    client = BNVDClient()
    severity = args.nivel.upper()
    
    valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if severity not in valid_severities:
        print(colorize(f"Severidade invalida. Use: {', '.join(valid_severities)}", Colors.RED))
        return 1
    
    print(colorize(f"\nBuscando vulnerabilidades com severidade {severity}...", Colors.CYAN))
    
    result = client.get_by_severity(severity, limit=args.limit)
    
    if not result:
        print(colorize("Erro ao buscar vulnerabilidades.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    vulnerabilities = result.get('data', [])
    
    if not vulnerabilities:
        print(colorize(f"Nenhuma vulnerabilidade {severity} encontrada.", Colors.YELLOW))
        return 0
    
    sev_color = severity_color(severity)
    print(colorize(f"\n{len(vulnerabilities)} vulnerabilidades {colorize(severity, sev_color)}:", Colors.GREEN))
    
    for vuln in vulnerabilities:
        print(format_vulnerability(vuln))
    
    return 0

def cmd_vendor(args):
    """Busca por fabricante"""
    client = BNVDClient()
    
    print(colorize(f"\nBuscando vulnerabilidades do fabricante: {args.fabricante}", Colors.CYAN))
    
    result = client.get_by_vendor(args.fabricante, limit=args.limit)
    
    if not result:
        print(colorize("Erro ao buscar vulnerabilidades.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    vulnerabilities = result.get('data', [])
    
    if not vulnerabilities:
        print(colorize(f"Nenhuma vulnerabilidade encontrada para {args.fabricante}.", Colors.YELLOW))
        return 0
    
    print(colorize(f"\n{len(vulnerabilities)} vulnerabilidades de {args.fabricante}:", Colors.GREEN))
    
    for vuln in vulnerabilities:
        print(format_vulnerability(vuln))
    
    return 0

def cmd_stats(args):
    """Mostra estatisticas do banco"""
    client = BNVDClient()
    
    print(colorize("\nBuscando estatisticas do BNVD...", Colors.CYAN))
    
    result = client.get_stats()
    
    if not result:
        print(colorize("Erro ao buscar estatisticas.", Colors.YELLOW))
        return 1
    
    if result.get('status') == 'error':
        print(colorize(f"Erro: {result.get('message')}", Colors.RED))
        return 1
    
    stats = result.get('data', {})
    
    print(colorize("\n" + "="*50, Colors.BLUE))
    print(colorize("  ESTATISTICAS DO BNVD", Colors.BOLD + Colors.WHITE))
    print(colorize("="*50, Colors.BLUE))
    
    print(f"\n  Total de Vulnerabilidades: {colorize(str(stats.get('total_vulnerabilities', 'N/A')), Colors.GREEN)}")
    print(f"  Total de Traducoes: {colorize(str(stats.get('total_translations', 'N/A')), Colors.GREEN)}")
    
    by_severity = stats.get('by_severity', {})
    if by_severity:
        print(colorize("\n  Por Severidade:", Colors.CYAN))
        for sev, count in by_severity.items():
            sev_color = severity_color(sev)
            print(f"    {colorize(sev, sev_color)}: {count}")
    
    by_year = stats.get('by_year', {})
    if by_year:
        print(colorize("\n  Por Ano (ultimos 5):", Colors.CYAN))
        sorted_years = sorted(by_year.items(), key=lambda x: x[0], reverse=True)[:5]
        for year, count in sorted_years:
            print(f"    {year}: {count}")
    
    return 0

def cmd_export(args):
    """Exporta CVE para arquivo"""
    client = BNVDClient()
    cve_id = args.cve_id.upper()
    
    if not cve_id.startswith('CVE-'):
        cve_id = f'CVE-{cve_id}'
    
    print(colorize(f"\nExportando {cve_id}...", Colors.CYAN))
    
    result = client.get_vulnerability(cve_id)
    
    if not result or result.get('status') == 'error':
        print(colorize(f"Vulnerabilidade {cve_id} nao encontrada.", Colors.YELLOW))
        return 1
    
    vuln = result.get('data')
    if not vuln:
        print(colorize(f"Dados nao disponiveis para {cve_id}.", Colors.YELLOW))
        return 1
    
    formato = args.formato.lower()
    filename = f"{cve_id}.{formato}"
    
    if formato == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(vuln, f, indent=2, ensure_ascii=False, default=str)
    elif formato == 'txt':
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(format_vulnerability(vuln, detailed=True))
    else:
        print(colorize(f"Formato '{formato}' nao suportado. Use: json, txt", Colors.RED))
        return 1
    
    print(colorize(f"Exportado para: {filename}", Colors.GREEN))
    return 0

def main():
    """Funcao principal"""
    global BNVD_API_URL
    
    parser = argparse.ArgumentParser(
        prog='bnvd-cli',
        description='BNVD CLI - Interface de linha de comando para o Banco Nacional de Vulnerabilidades Ciberneticas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos:
  bnvd-cli buscar apache           # Busca vulnerabilidades com "apache"
  bnvd-cli cve CVE-2024-12345      # Detalhes de um CVE especifico
  bnvd-cli recentes --dias 7       # Vulnerabilidades dos ultimos 7 dias
  bnvd-cli severidade CRITICAL     # Somente vulnerabilidades criticas
  bnvd-cli vendor Microsoft        # Vulnerabilidades da Microsoft
  bnvd-cli stats                   # Estatisticas do banco
  bnvd-cli export CVE-2024-12345   # Exporta CVE para arquivo

Mais informacoes: https://bnvd.org
        '''
    )
    
    parser.add_argument('--version', action='version', version=f'BNVD CLI v{VERSION}')
    parser.add_argument('--api-url', default=BNVD_API_URL, help='URL base da API BNVD')
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponiveis')
    
    buscar_parser = subparsers.add_parser('buscar', help='Busca vulnerabilidades por termo')
    buscar_parser.add_argument('termo', help='Termo de busca')
    buscar_parser.add_argument('--limit', type=int, default=20, help='Limite de resultados')
    buscar_parser.set_defaults(func=cmd_buscar)
    
    cve_parser = subparsers.add_parser('cve', help='Busca CVE especifico')
    cve_parser.add_argument('cve_id', help='ID do CVE (ex: CVE-2024-12345)')
    cve_parser.set_defaults(func=cmd_cve)
    
    recentes_parser = subparsers.add_parser('recentes', help='Lista vulnerabilidades recentes')
    recentes_parser.add_argument('--dias', type=int, default=7, help='Numero de dias (padrao: 7)')
    recentes_parser.add_argument('--limit', type=int, default=10, help='Limite de resultados')
    recentes_parser.set_defaults(func=cmd_recentes)
    
    severidade_parser = subparsers.add_parser('severidade', help='Filtra por severidade')
    severidade_parser.add_argument('nivel', help='Nivel de severidade (LOW, MEDIUM, HIGH, CRITICAL)')
    severidade_parser.add_argument('--limit', type=int, default=20, help='Limite de resultados')
    severidade_parser.set_defaults(func=cmd_severidade)
    
    vendor_parser = subparsers.add_parser('vendor', help='Busca por fabricante')
    vendor_parser.add_argument('fabricante', help='Nome do fabricante')
    vendor_parser.add_argument('--limit', type=int, default=20, help='Limite de resultados')
    vendor_parser.set_defaults(func=cmd_vendor)
    
    stats_parser = subparsers.add_parser('stats', help='Mostra estatisticas do banco')
    stats_parser.set_defaults(func=cmd_stats)
    
    export_parser = subparsers.add_parser('export', help='Exporta CVE para arquivo')
    export_parser.add_argument('cve_id', help='ID do CVE')
    export_parser.add_argument('--formato', default='json', help='Formato de exportacao (json, txt)')
    export_parser.set_defaults(func=cmd_export)
    
    args = parser.parse_args()
    
    if args.api_url:
        BNVD_API_URL = args.api_url
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)

if __name__ == '__main__':
    sys.exit(main())
