"""
Sistema de SEO para o Banco Nacional de Vulnerabilidades Cibernéticas (BNVD)
Implementa todas as práticas de SEO recomendadas para otimização de busca
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin
from flask import request, url_for


class SEOManager:
    """Gerenciador de SEO para o BNVD"""
    
    def __init__(self, app=None):
        self.app = app
        self.base_url = "https://bnvd.org"  # URL base do site
        self.site_name = "Banco Nacional de Vulnerabilidades Cibernéticas (BNVD)"
        self.site_description = "A fonte confiável de vulnerabilidades de segurança cibernética no Brasil"
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa o SEO manager com a aplicação Flask"""
        self.app = app
        
        # Registra template globals
        app.jinja_env.globals['seo_meta_tags'] = self.generate_meta_tags
        app.jinja_env.globals['seo_structured_data'] = self.generate_structured_data
        app.jinja_env.globals['seo_breadcrumb'] = self.generate_breadcrumb
    
    def generate_meta_tags(self, page_data: Dict) -> Dict[str, str]:
        """
        Gera meta tags otimizadas para SEO
        
        Args:
            page_data: Dicionário com dados da página atual
        
        Returns:
            Dicionário com todas as meta tags necessárias
        """
        # Lista extensa de palavras-chave para SEO
        default_keywords = [
            'vulnerabilidades', 'segurança cibernética', 'CVE', 'Brasil', 'BNVD',
            'vulnerabilidade de segurança', 'banco de dados', 'NVD', 'National Vulnerability Database',
            'security vulnerabilities', 'cybersecurity', 'cyber security', 'infosec',
            'information security', 'vulnerabilidades de software', 'falhas de segurança',
            'exploits', 'zero day', 'patches', 'atualizações de segurança', 'correções',
            'CVSS', 'Common Vulnerability Scoring System', 'CWE', 'Common Weakness Enumeration',
            'penetration testing', 'pentest', 'teste de penetração', 'ethical hacking',
            'hacking ético', 'vulnerability assessment', 'avaliação de vulnerabilidades',
            'security advisory', 'aviso de segurança', 'security bulletin', 'boletim de segurança',
            'threat intelligence', 'inteligência de ameaças', 'cyber threats', 'ameaças cibernéticas',
            'malware', 'ransomware', 'trojan', 'virus', 'worm', 'backdoor', 'rootkit',
            'SQL injection', 'XSS', 'cross-site scripting', 'CSRF', 'buffer overflow',
            'code injection', 'privilege escalation', 'escalação de privilégios',
            'denial of service', 'DDoS', 'distributed denial of service', 'negação de serviço',
            'authentication bypass', 'authorization bypass', 'session hijacking',
            'man in the middle', 'MITM', 'phishing', 'social engineering',
            'engenharia social', 'security testing', 'testes de segurança',
            'vulnerability scanning', 'varredura de vulnerabilidades', 'security audit',
            'auditoria de segurança', 'compliance', 'conformidade', 'GDPR', 'LGPD',
            'ISO 27001', 'NIST', 'OWASP', 'security framework', 'framework de segurança',
            'incident response', 'resposta a incidentes', 'forensics', 'forense digital',
            'threat hunting', 'caça às ameaças', 'security monitoring', 'monitoramento',
            'SIEM', 'SOC', 'Security Operations Center', 'Centro de Operações de Segurança',
            'vulnerability management', 'gestão de vulnerabilidades', 'patch management',
            'gestão de patches', 'risk assessment', 'avaliação de riscos',
            'security posture', 'postura de segurança', 'defense in depth',
            'defesa em profundidade', 'zero trust', 'confiança zero',
            'network security', 'segurança de rede', 'firewall', 'IDS', 'IPS',
            'endpoint security', 'segurança de endpoints', 'antivirus', 'EDR',
            'cloud security', 'segurança na nuvem', 'AWS security', 'Azure security',
            'GCP security', 'container security', 'Kubernetes security',
            'DevSecOps', 'security by design', 'segurança por design',
            'secure coding', 'programação segura', 'code review', 'revisão de código',
            'static analysis', 'análise estática', 'dynamic analysis', 'análise dinâmica',
            'application security', 'segurança de aplicações', 'web security',
            'segurança web', 'mobile security', 'segurança móvel',
            'IoT security', 'Internet of Things security', 'segurança IoT',
            'industrial security', 'segurança industrial', 'SCADA security',
            'OT security', 'operational technology', 'tecnologia operacional'
        ]
        
        # Meta tags básicas
        title = page_data.get('title', self.site_name)
        description = page_data.get('description', self.site_description)
        keywords = page_data.get('keywords', ', '.join(default_keywords))
        author = page_data.get('author', 'Juan Mathews Rebello Santos')
        canonical_url = page_data.get('canonical_url', request.url)
        
        # Se for uma página de CVE, otimizar para o ID
        if 'cve_id' in page_data:
            cve_id = page_data['cve_id']
            title = f"{cve_id} - Vulnerabilidade de Segurança | {self.site_name}"
            description = f"Detalhes completos da vulnerabilidade {cve_id}. {page_data.get('cve_description', 'Informações detalhadas sobre esta vulnerabilidade de segurança.')}"
            keywords = f"{cve_id}, vulnerabilidade, segurança, CVE, {keywords}"
        
        # Limitar tamanhos para otimização
        title = title[:60] + "..." if len(title) > 60 else title
        description = description[:160] + "..." if len(description) > 160 else description
        
        meta_tags = {
            'title': title,
            'description': description,
            'keywords': keywords,
            'author': author,
            'copyright': f'© {datetime.now().year} {self.site_name}',
            'robots': page_data.get('robots', 'index, follow'),
            'canonical_url': canonical_url,
            'viewport': 'width=device-width, initial-scale=1.0',
            'charset': 'utf-8',
            'language': 'pt-BR',
            'geo_region': 'BR',
            'geo_country': 'Brasil',
            'theme_color': '#0d6efd',
            'msapplication_TileColor': '#0d6efd',
            'apple_mobile_web_app_capable': 'yes',
            'apple_mobile_web_app_status_bar_style': 'default',
            'apple_mobile_web_app_title': 'BNVD'
        }
        
        # Open Graph (Facebook)
        meta_tags.update({
            'og_type': page_data.get('og_type', 'website'),
            'og_url': canonical_url,
            'og_title': title,
            'og_description': description,
            'og_image': page_data.get('og_image', f"{self.base_url}/static/images/bnvd-logo.png"),
            'og_image_width': '1200',
            'og_image_height': '630',
            'og_site_name': self.site_name,
            'og_locale': 'pt_BR'
        })
        
        # Twitter Cards
        meta_tags.update({
            'twitter_card': 'summary_large_image',
            'twitter_url': canonical_url,
            'twitter_title': title,
            'twitter_description': description,
            'twitter_image': page_data.get('twitter_image', f"{self.base_url}/static/images/bnvd-logo.png"),
            'twitter_creator': '@bnvd_brasil',
            'twitter_site': '@bnvd_brasil'
        })
        
        return meta_tags
    
    def generate_structured_data(self, page_data: Dict) -> str:
        """
        Gera dados estruturados JSON-LD para melhor indexação
        
        Args:
            page_data: Dados da página atual
            
        Returns:
            String JSON-LD com dados estruturados
        """
        base_schema = {
            "@context": "https://schema.org",
            "@type": "WebSite",
            "name": self.site_name,
            "description": self.site_description,
            "url": self.base_url,
            "potentialAction": {
                "@type": "SearchAction",
                "target": f"{self.base_url}/busca?q={{search_term_string}}",
                "query-input": "required name=search_term_string"
            },
            "publisher": {
                "@type": "Organization",
                "name": self.site_name,
                "url": self.base_url,
                "logo": {
                    "@type": "ImageObject",
                    "url": f"{self.base_url}/static/images/bnvd-logo.png"
                }
            }
        }
        
        # Schema específico para páginas de CVE
        if 'cve_id' in page_data:
            vulnerability_schema = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": f"Vulnerabilidade {page_data['cve_id']}",
                "description": page_data.get('cve_description', ''),
                "datePublished": page_data.get('published_date', datetime.now().isoformat()),
                "dateModified": page_data.get('modified_date', datetime.now().isoformat()),
                "author": {
                    "@type": "Organization",
                    "name": "National Vulnerability Database (NVD)"
                },
                "publisher": {
                    "@type": "Organization",
                    "name": self.site_name,
                    "logo": {
                        "@type": "ImageObject",
                        "url": f"{self.base_url}/static/images/bnvd-logo.png"
                    }
                },
                "mainEntityOfPage": {
                    "@type": "WebPage",
                    "@id": page_data.get('canonical_url', request.url)
                },
                "about": {
                    "@type": "Thing",
                    "name": f"Vulnerabilidade de Segurança {page_data['cve_id']}",
                    "description": page_data.get('cve_description', '')
                }
            }
            return json.dumps([base_schema, vulnerability_schema], ensure_ascii=False, indent=2)
        
        return json.dumps(base_schema, ensure_ascii=False, indent=2)
    
    def generate_breadcrumb(self, breadcrumb_items: List[Dict[str, str]]) -> str:
        """
        Gera breadcrumb estruturado para SEO
        
        Args:
            breadcrumb_items: Lista de itens do breadcrumb
            
        Returns:
            JSON-LD do breadcrumb
        """
        if not breadcrumb_items:
            return ""
        
        breadcrumb_schema = {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": []
        }
        
        for i, item in enumerate(breadcrumb_items):
            breadcrumb_schema["itemListElement"].append({
                "@type": "ListItem",
                "position": i + 1,
                "name": item.get('name', ''),
                "item": item.get('url', '')
            })
        
        return json.dumps(breadcrumb_schema, ensure_ascii=False, indent=2)
    
    def generate_sitemap_xml(self, cve_files: Optional[List[str]] = None) -> str:
        """
        Gera sitemap XML dinâmico incluindo todas as páginas e CVEs do banco de dados
        
        Args:
            cve_files: Lista de arquivos CVE em cache (legacy, agora usa banco)
            
        Returns:
            XML do sitemap
        """
        from datetime import datetime
        import os
        
        # URLs principais do site
        main_urls = [
            {'loc': self.base_url, 'priority': '1.0', 'changefreq': 'daily'},
            {'loc': f"{self.base_url}/busca", 'priority': '0.9', 'changefreq': 'weekly'},
            {'loc': f"{self.base_url}/recentes", 'priority': '0.8', 'changefreq': 'daily'},
            {'loc': f"{self.base_url}/sobre", 'priority': '0.7', 'changefreq': 'monthly'},
            {'loc': f"{self.base_url}/politica", 'priority': '0.6', 'changefreq': 'monthly'},
            {'loc': f"{self.base_url}/busca-por-ano", 'priority': '0.8', 'changefreq': 'weekly'},
            {'loc': f"{self.base_url}/5recentes", 'priority': '0.9', 'changefreq': 'daily'},
            {'loc': f"{self.base_url}/noticias", 'priority': '0.9', 'changefreq': 'hourly'},
            {'loc': f"{self.base_url}/ver-todas-noticias", 'priority': '0.8', 'changefreq': 'daily'},
            {'loc': f"{self.base_url}/downloads", 'priority': '0.7', 'changefreq': 'monthly'},
            {'loc': f"{self.base_url}/privacidade", 'priority': '0.6', 'changefreq': 'monthly'},
        ]
        
        # Buscar CVEs do banco de dados
        cve_urls = []
        try:
            from vulns import VulnerabilityDatabase
            
            database_url = os.environ.get('DATABASE_URL')
            if database_url:
                db = VulnerabilityDatabase(database_url)
                db._ensure_connection()
                
                # Usar cursor real dict para compatibilidade
                import psycopg2.extras
                cursor = db.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                cursor.execute("SELECT cve_id, last_modified FROM vulnerabilities ORDER BY last_modified DESC")
                vulnerabilities = cursor.fetchall()
                
                for vuln in vulnerabilities:
                    cve_id = vuln['cve_id']
                    last_modified = vuln['last_modified']
                    
                    # Converter data para formato adequado
                    lastmod_date = last_modified.strftime('%Y-%m-%d') if last_modified else datetime.now().strftime('%Y-%m-%d')
                    
                    cve_urls.append({
                        'loc': f"{self.base_url}/vulnerabilidade/{cve_id}",
                        'priority': '0.8',
                        'changefreq': 'monthly',
                        'lastmod': lastmod_date
                    })
                
                cursor.close()
                db.close()
        except Exception as e:
            print(f"Erro ao buscar CVEs do banco para sitemap: {e}")
            # Fallback para arquivos se necessário
            if cve_files:
                for cve_file in cve_files:
                    if cve_file.endswith('.html'):
                        cve_id = cve_file.replace('.html', '')
                        cve_urls.append({
                            'loc': f"{self.base_url}/vulnerabilidade/{cve_id}",
                            'priority': '0.8',
                            'changefreq': 'monthly',
                            'lastmod': datetime.now().strftime('%Y-%m-%d')
                        })
        
        # Buscar URLs de notícias
        news_urls = []
        try:
            import json
            news_file = 'noticias_ciso.json'
            if os.path.exists(news_file):
                with open(news_file, 'r', encoding='utf-8') as f:
                    news_data = json.load(f)
                    for news in news_data:
                        slug = news.get('slug', '')
                        pub_date = news.get('pub_date', '')
                        
                        # Converter data de publicação
                        try:
                            from datetime import datetime, timedelta
                            date_obj = datetime.strptime(pub_date.split('+')[0].strip(), '%a, %d %b %Y %H:%M:%S')
                            lastmod = (date_obj - timedelta(hours=3)).strftime('%Y-%m-%d')
                        except:
                            lastmod = datetime.now().strftime('%Y-%m-%d')
                        
                        if slug:
                            news_urls.append({
                                'loc': f"{self.base_url}/noticia/{slug}",
                                'priority': '0.7',
                                'changefreq': 'weekly',
                                'lastmod': lastmod
                            })
        except Exception as e:
            print(f"Erro ao buscar notícias para sitemap: {e}")
        
        # Gerar XML
        xml_content = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_content.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
        
        # Adicionar URLs principais
        for url in main_urls:
            xml_content.append('  <url>')
            xml_content.append(f'    <loc>{url["loc"]}</loc>')
            xml_content.append(f'    <priority>{url["priority"]}</priority>')
            xml_content.append(f'    <changefreq>{url["changefreq"]}</changefreq>')
            xml_content.append(f'    <lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod>')
            xml_content.append('  </url>')
        
        # Adicionar URLs de notícias
        for url in news_urls:
            xml_content.append('  <url>')
            xml_content.append(f'    <loc>{url["loc"]}</loc>')
            xml_content.append(f'    <priority>{url["priority"]}</priority>')
            xml_content.append(f'    <changefreq>{url["changefreq"]}</changefreq>')
            xml_content.append(f'    <lastmod>{url["lastmod"]}</lastmod>')
            xml_content.append('  </url>')
        
        # Adicionar URLs de CVEs
        for url in cve_urls:
            xml_content.append('  <url>')
            xml_content.append(f'    <loc>{url["loc"]}</loc>')
            xml_content.append(f'    <priority>{url["priority"]}</priority>')
            xml_content.append(f'    <changefreq>{url["changefreq"]}</changefreq>')
            xml_content.append(f'    <lastmod>{url["lastmod"]}</lastmod>')
            xml_content.append('  </url>')
        
        xml_content.append('</urlset>')
        
        return '\n'.join(xml_content)
    
    def generate_robots_txt(self) -> str:
        """
        Gera robots.txt otimizado
        
        Returns:
            Conteúdo do robots.txt
        """
        robots_content = [
            "User-agent: *",
            "Allow: /",
            "",
            "# Disallow admin and cache management",
            "Disallow: /admin/",
            "Disallow: /cache/",
            "",
            "# Allow all CVE pages",
            "Allow: /vulnerabilidade/",
            "",
            f"Sitemap: {self.base_url}/sitemap.xml",
            "",
            "# Crawl delay",
            "Crawl-delay: 1"
        ]
        
        return '\n'.join(robots_content)
    
    def get_cve_meta_data(self, cve_data: Dict, cve_id: str) -> Dict:
        """
        Extrai dados de meta tags específicos para uma página de CVE
        
        Args:
            cve_data: Dados da vulnerabilidade
            cve_id: ID da vulnerabilidade
            
        Returns:
            Dicionário com dados otimizados para SEO
        """
        # Extrair descrição
        description = "Informações não disponíveis"
        if cve_data and 'descriptions' in cve_data:
            for desc in cve_data['descriptions']:
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
        
        # Extrair data de publicação
        published_date = None
        if cve_data and 'published' in cve_data:
            published_date = cve_data['published']
        
        # Extrair data de modificação
        modified_date = None
        if cve_data and 'lastModified' in cve_data:
            modified_date = cve_data['lastModified']
        
        # Extrair severidade
        severity = "Unknown"
        if cve_data and 'metrics' in cve_data:
            metrics = cve_data['metrics']
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', severity)
            elif 'cvssMetricV3' in metrics and metrics['cvssMetricV3']:
                severity = metrics['cvssMetricV3'][0].get('cvssData', {}).get('baseSeverity', severity)
        
        return {
            'title': f"{cve_id} - Vulnerabilidade de Segurança",
            'description': f"Vulnerabilidade {cve_id} com severidade {severity}. {description[:100]}...",
            'keywords': f"{cve_id}, vulnerabilidade, segurança, CVE, {severity.lower()}, cibernética",
            'cve_id': cve_id,
            'cve_description': description,
            'published_date': published_date,
            'modified_date': modified_date,
            'og_type': 'article',
            'canonical_url': f"{self.base_url}/vulnerabilidade/{cve_id}",
            'robots': 'index, follow'
        }

    def generate_security_txt(self) -> str:
        """
        Gera arquivo security.txt para divulgação responsável de vulnerabilidades
        
        Returns:
            Conteúdo do security.txt
        """
        return """# Política de Divulgação Responsável de Vulnerabilidades
# BNVD - Banco Nacional de Vulnerabilidades Cibernéticas

Contact: contato@bnvd.org
Contact: https://github.com/azurejoga/
Preferred-Languages: pt, en
Canonical: https://bnvd.replit.app/.well-known/security.txt

# Escopo
# Este site é mantido para fins educacionais e de pesquisa
# Vulnerabilidades devem ser reportadas de forma responsável

Policy: https://bnvd.replit.app/politica
Acknowledgments: https://bnvd.replit.app/sobre

# Prazo para resposta: 72 horas
# Divulgação coordenada após correção
"""

    def generate_manifest_json(self) -> str:
        """
        Gera manifest.json para PWA
        
        Returns:
            JSON do manifest
        """
        import json
        
        manifest = {
            "name": "Banco Nacional de Vulnerabilidades Cibernéticas",
            "short_name": "BNVD",
            "description": "Banco nacional brasileiro de vulnerabilidades de segurança cibernética",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#ffffff",
            "theme_color": "#0d6efd",
            "orientation": "portrait-primary",
            "scope": "/",
            "lang": "pt-BR",
            "categories": ["security", "database", "reference"],
            "icons": [
                {
                    "src": "/static/icons/icon-192.png",
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable"
                },
                {
                    "src": "/static/icons/icon-512.png", 
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any maskable"
                }
            ],
            "shortcuts": [
                {
                    "name": "Busca Rápida",
                    "short_name": "Buscar",
                    "description": "Buscar vulnerabilidades CVE",
                    "url": "/busca",
                    "icons": [{"src": "/static/icons/search-icon.png", "sizes": "96x96"}]
                },
                {
                    "name": "Vulnerabilidades Recentes",
                    "short_name": "Recentes", 
                    "description": "Ver vulnerabilidades dos últimos 7 dias",
                    "url": "/recentes",
                    "icons": [{"src": "/static/icons/recent-icon.png", "sizes": "96x96"}]
                }
            ]
        }
        
        return json.dumps(manifest, indent=2, ensure_ascii=False)

    def generate_humans_txt(self) -> str:
        """
        Gera arquivo humans.txt com informações sobre a equipe
        
        Returns:
            Conteúdo do humans.txt
        """
        return """/* TEAM */

Desenvolvedor: Juan Mathews Rebello Santos
GitHub: https://github.com/azurejoga/
LinkedIn: https://linkedin.com/in/juan-mathews-rebello-santos-/
Localização: Brasil

/* THANKS */

National Vulnerability Database (NVD) - NIST
Bootstrap Team
Font Awesome
Replit Platform

/* SITE */

Última atualização: 2025/07/02
Linguagem: Português (Brasil)
Framework: Flask (Python)
Ferramentas: Bootstrap 5, Font Awesome 6
Código: https://github.com/azurejoga/
Padrões: HTML5, CSS3, ES6+
Componentes: responsive, PWA-ready, SEO-optimized
"""

    def generate_feed_rss(self, recent_cves: Optional[List] = None) -> str:
        """
        Gera feed RSS para vulnerabilidades recentes
        
        Args:
            recent_cves: Lista de CVEs recentes
            
        Returns:
            XML do feed RSS
        """
        from datetime import datetime
        import html
        
        rss_items = []
        
        if recent_cves:
            for cve in recent_cves[:20]:  # Limitar a 20 itens
                # Extrair informações básicas
                cve_id = cve.get('id', 'N/A')
                description = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição disponível')[:200] + '...'
                published = cve.get('published', datetime.now().isoformat())
                
                # Escapar HTML
                description_escaped = html.escape(description)
                
                rss_items.append(f'''
        <item>
            <title>CVE-{cve_id}</title>
            <description>{description_escaped}</description>
            <link>https://bnvd.replit.app/cve/{cve_id}</link>
            <guid>https://bnvd.replit.app/cve/{cve_id}</guid>
            <pubDate>{published}</pubDate>
            <category>Vulnerabilidade</category>
        </item>''')
        
        rss_feed = f'''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <channel>
        <title>BNVD - Vulnerabilidades Recentes</title>
        <link>https://bnvd.replit.app</link>
        <description>Feed de vulnerabilidades de segurança cibernética recentes do Banco Nacional de Vulnerabilidades</description>
        <language>pt-BR</language>
        <copyright>© 2025 BNVD - Todos os direitos reservados</copyright>
        <managingEditor>contato@bnvd.org (BNVD Team)</managingEditor>
        <webMaster>contato@bnvd.org (BNVD Team)</webMaster>
        <lastBuildDate>{datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}</lastBuildDate>
        <atom:link href="https://bnvd.replit.app/feed.rss" rel="self" type="application/rss+xml"/>
        <image>
            <url>https://bnvd.replit.app/static/icons/icon-192.png</url>
            <title>BNVD</title>
            <link>https://bnvd.replit.app</link>
        </image>{''.join(rss_items)}
    </channel>
</rss>'''
        
        return rss_feed

    def generate_feed_atom(self, recent_cves: Optional[List] = None) -> str:
        """
        Gera feed Atom para vulnerabilidades recentes
        
        Args:
            recent_cves: Lista de CVEs recentes
            
        Returns:
            XML do feed Atom
        """
        from datetime import datetime
        import html
        
        atom_entries = []
        
        if recent_cves:
            for cve in recent_cves[:20]:
                cve_id = cve.get('id', 'N/A')
                description = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição disponível')
                published = cve.get('published', datetime.now().isoformat())
                
                description_escaped = html.escape(description)
                
                atom_entries.append(f'''
    <entry>
        <title>CVE-{cve_id}</title>
        <link href="https://bnvd.replit.app/cve/{cve_id}"/>
        <id>https://bnvd.replit.app/cve/{cve_id}</id>
        <updated>{published}</updated>
        <summary>{description_escaped}</summary>
        <category term="vulnerabilidade"/>
        <author>
            <name>BNVD</name>
            <email>contato@bnvd.org</email>
        </author>
    </entry>''')
        
        atom_feed = f'''<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
    <title>BNVD - Vulnerabilidades Recentes</title>
    <link href="https://bnvd.replit.app"/>
    <link href="https://bnvd.replit.app/feed.atom" rel="self"/>
    <id>https://bnvd.replit.app/feed.atom</id>
    <updated>{datetime.now().isoformat()}</updated>
    <subtitle>Feed de vulnerabilidades de segurança cibernética recentes</subtitle>
    <author>
        <name>BNVD</name>
        <email>contato@bnvd.org</email>
    </author>{''.join(atom_entries)}
</feed>'''
        
        return atom_feed


def init_seo_routes(app, seo_manager: SEOManager):
    """
    Inicializa rotas relacionadas ao SEO
    
    Args:
        app: Aplicação Flask
        seo_manager: Instância do SEOManager
    """
    
    @app.route('/sitemap.xml')
    def sitemap():
        """Gera sitemap dinâmico"""
        from flask import Response
        import os
        
        # Listar arquivos CVE em cache
        cve_files = []
        cache_dir = 'cves'
        
        if os.path.exists(cache_dir):
            cve_files = [f for f in os.listdir(cache_dir) if f.endswith('.html')]
        
        xml_content = seo_manager.generate_sitemap_xml(cve_files)
        
        return Response(
            xml_content,
            mimetype='application/xml',
            headers={'Content-Type': 'application/xml; charset=utf-8'}
        )
    
    @app.route('/robots.txt')
    def robots():
        """Gera robots.txt"""
        from flask import Response
        
        robots_content = seo_manager.generate_robots_txt()
        
        return Response(
            robots_content,
            mimetype='text/plain',
            headers={'Content-Type': 'text/plain; charset=utf-8'}
        )
    
    @app.route('/.well-known/security.txt')
    def security_txt():
        """Gera security.txt para divulgação responsável"""
        from flask import Response
        
        security_content = seo_manager.generate_security_txt()
        
        return Response(
            security_content,
            mimetype='text/plain',
            headers={'Content-Type': 'text/plain; charset=utf-8'}
        )
    
    @app.route('/manifest.json')
    def manifest():
        """Gera manifest.json para PWA"""
        from flask import Response
        
        manifest_content = seo_manager.generate_manifest_json()
        
        return Response(
            manifest_content,
            mimetype='application/json',
            headers={'Content-Type': 'application/json; charset=utf-8'}
        )
    
    @app.route('/humans.txt')
    def humans():
        """Gera humans.txt"""
        from flask import Response
        
        humans_content = seo_manager.generate_humans_txt()
        
        return Response(
            humans_content,
            mimetype='text/plain',
            headers={'Content-Type': 'text/plain; charset=utf-8'}
        )
    
    @app.route('/feed.rss')
    def feed_rss():
        """Gera feed RSS de vulnerabilidades recentes"""
        from flask import Response
        from nvd_api import NVDClient
        import os
        
        # Buscar CVEs recentes para o feed
        recent_cves = []
        try:
            nvd_client = NVDClient(os.environ.get('NVD_API_KEY', ''))
            result = nvd_client.get_recent_cves(days=7, results_per_page=20)
            if result and 'vulnerabilities' in result:
                recent_cves = [vuln['cve'] for vuln in result['vulnerabilities']]
        except Exception as e:
            print(f"Erro ao buscar CVEs para RSS: {e}")
        
        rss_content = seo_manager.generate_feed_rss(recent_cves)
        
        return Response(
            rss_content,
            mimetype='application/rss+xml',
            headers={'Content-Type': 'application/rss+xml; charset=utf-8'}
        )
    
    @app.route('/feed.atom')
    def feed_atom():
        """Gera feed Atom de vulnerabilidades recentes"""
        from flask import Response
        from nvd_api import NVDClient
        import os
        
        # Buscar CVEs recentes para o feed
        recent_cves = []
        try:
            nvd_client = NVDClient(os.environ.get('NVD_API_KEY', ''))
            result = nvd_client.get_recent_cves(days=7, results_per_page=20)
            if result and 'vulnerabilities' in result:
                recent_cves = [vuln['cve'] for vuln in result['vulnerabilities']]
        except Exception as e:
            print(f"Erro ao buscar CVEs para Atom: {e}")
        
        atom_content = seo_manager.generate_feed_atom(recent_cves)
        
        return Response(
            atom_content,
            mimetype='application/atom+xml',
            headers={'Content-Type': 'application/atom+xml; charset=utf-8'}
        )