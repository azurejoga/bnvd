"""
BNVD - Sistema de Notícias de Segurança Cibernética
Monitora feed RSS do CISO Advisor e extrai notícias automaticamente
"""

import os
import json
import logging
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from lxml import etree
from apscheduler.schedulers.background import BackgroundScheduler
from typing import List, Dict, Optional
import re
import unicodedata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FEED_URL = "https://www.cisoadvisor.com.br/feed/"
NEWS_FILE = "noticias_ciso.json"
UPDATE_INTERVAL = 3600  # 1 hora em segundos
NEWS_HTML_DIR = "templates/noticias"  # Diretório para HTMLs de notícias

class CISOAdvisorMonitor:
    def __init__(self):
        self.news_file = NEWS_FILE
        self.feed_url = FEED_URL
        self.scheduler = None

    def load_news(self) -> List[Dict]:
        """Carrega notícias do arquivo JSON"""
        if os.path.exists(self.news_file):
            try:
                with open(self.news_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erro ao carregar notícias: {e}")
                return []
        return []

    def save_news(self, news: List[Dict]):
        """Salva notícias no arquivo JSON"""
        try:
            with open(self.news_file, 'w', encoding='utf-8') as f:
                json.dump(news, f, ensure_ascii=False, indent=2)
            logger.info(f"Notícias salvas: {len(news)} itens")
        except Exception as e:
            logger.error(f"Erro ao salvar notícias: {e}")

    def fetch_rss_feed(self) -> Optional[str]:
        """Busca o feed RSS do CISO Advisor"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.feed_url, headers=headers, timeout=30)
            response.raise_for_status()
            logger.info("Feed RSS obtido com sucesso")
            return response.text
        except Exception as e:
            logger.error(f"Erro ao buscar feed RSS: {e}")
            return None

    def parse_rss_feed(self, rss_content: str) -> List[Dict]:
        """Parseia o feed RSS e extrai informações das notícias"""
        items = []
        try:
            root = etree.fromstring(rss_content.encode('utf-8'))

            for item in root.xpath('.//item'):
                title = item.find('title')
                link = item.find('link')
                description = item.find('description')
                pub_date = item.find('pubDate')
                category = item.find('category')

                news_item = {
                    'title': title.text if title is not None else 'Sem título',
                    'link': link.text if link is not None else '',
                    'description': self.clean_html(description.text if description is not None else ''),
                    'pub_date': pub_date.text if pub_date is not None else '',
                    'category': category.text if category is not None else 'Sem categoria',
                    'fetched_at': datetime.now().isoformat()
                }

                items.append(news_item)

            logger.info(f"Parsed {len(items)} notícias do feed RSS")
        except Exception as e:
            logger.error(f"Erro ao parsear RSS: {e}")

        return items

    def clean_html(self, html_text: str) -> str:
        """Remove tags HTML e limpa o texto"""
        if not html_text:
            return ""
        soup = BeautifulSoup(html_text, 'html.parser')
        text = soup.get_text()
        # Remove espaços extras
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def create_slug(self, title: str) -> str:
        """Cria slug amigável a partir do título"""
        # Normalizar caracteres unicode (remover acentos)
        nfkd = unicodedata.normalize('NFKD', title)
        slug = ''.join([c for c in nfkd if not unicodedata.combining(c)])

        # Converter para minúsculas
        slug = slug.lower()

        # Remover caracteres especiais, manter apenas letras, números e espaços
        slug = re.sub(r'[^a-z0-9\s-]', '', slug)

        # Substituir espaços e múltiplos hífens por um único hífen
        slug = re.sub(r'[\s-]+', '-', slug)

        # Remover hífens do início e fim
        slug = slug.strip('-')

        # Limitar tamanho
        if len(slug) > 100:
            slug = slug[:100].rsplit('-', 1)[0]

        return slug

    def _url_for_mock(self, endpoint, **kwargs):
        """Mock para url_for para uso em templates estáticos."""
        # Em uma aplicação Flask real, você usaria `from flask import url_for`
        # Aqui, simulamos para que o template funcione.
        # Para a rota de índice, assumimos que é '/'.
        if endpoint == 'index':
            return '/'
        # Para a rota de notícias, assumimos que é '/noticias'.
        if endpoint == 'noticias':
            return '/noticias'
        # Para detalhes de notícias, formatamos com o slug.
        if endpoint == 'noticia_detalhes' and 'slug' in kwargs:
            return f"/noticia/{kwargs['slug']}"
        return '#' # Fallback

    def generate_news_html(self, news_item: Dict) -> str:
        """Gera HTML individual para uma notícia"""
        slug = news_item.get('slug', '')
        title = news_item.get('title', 'Sem título')
        pub_date_formatted = news_item.get('pub_date_formatted', '')
        original_link = news_item.get('link', '#')
        category = news_item.get('category', '')

        # Criar diretório se não existir
        os.makedirs(NEWS_HTML_DIR, exist_ok=True)

        # Preparar conteúdo HTML
        content = news_item.get('content', '')
        if content and content != 'Conteúdo não disponível':
            # Converter texto em parágrafos HTML
            paragraphs = content.split('\n\n')
            content_html = '\n'.join([f'<p>{p.strip()}</p>' for p in paragraphs if p.strip()])
        else:
            content_html = '<p class="alert alert-warning">Conteúdo completo não disponível.</p>'

        # Badge de categoria (se houver)
        category_badge = f'<p class="mt-2"><span class="badge bg-info"><i class="fas fa-tag me-1"></i>{category}</span></p>' if category else ''

        # Template HTML para notícia individual (HTML estático renderizado)
        html_content = f"""{{% extends "base.html" %}}

{{% block title %}}{title} - BNVD{{% endblock %}}
{{% block description %}}{news_item.get('description', title)[:160]}{{% endblock %}}
{{% block keywords %}}segurança cibernética, {title}, notícias cyber, BNVD, vulnerabilidades{{% endblock %}}

{{% block og_type %}}article{{% endblock %}}
{{% block og_title %}}{title}{{% endblock %}}
{{% block og_description %}}{news_item.get('description', title)[:160]}{{% endblock %}}

{{% block structured_data %}}
<script type="application/ld+json">
{{
    "@context": "https://schema.org",
    "@type": "NewsArticle",
    "headline": "{title}",
    "datePublished": "{news_item.get('pub_date', '')}",
    "dateModified": "{news_item.get('pub_date', '')}",
    "author": {{
        "@type": "Organization",
        "name": "CISO Advisor",
        "url": "{original_link}"
    }},
    "publisher": {{
        "@type": "Organization",
        "name": "Banco Nacional de Vulnerabilidades Cibernéticas (BNVD)",
        "url": "{{{{ url_for('index', _external=True) }}}}"
    }},
    "description": "{news_item.get('description', title)[:160]}",
    "mainEntityOfPage": {{
        "@type": "WebPage",
        "@id": "{{{{ url_for('noticia_detalhes', slug='{slug}', _external=True) }}}}"
    }}
}}
</script>
{{% endblock %}}

{{% block content %}}
<div class="container py-5">
    <article class="news-article">
        <!-- Breadcrumb -->
        <nav aria-label="breadcrumb" class="mb-4">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="{{{{ url_for('index') }}}}">Início</a></li>
                <li class="breadcrumb-item"><a href="{{{{ url_for('noticias') }}}}">Notícias</a></li>
                <li class="breadcrumb-item active" aria-current="page">{title}</li>
            </ol>
        </nav>

        <!-- Título -->
        <h1 class="display-5 fw-bold text-primary mb-4">{title}</h1>

        <!-- Metadados -->
        <div class="news-meta mb-4 pb-3 border-bottom">
            <p class="text-muted mb-2">
                <i class="fas fa-calendar-alt me-2"></i>
                <strong>Publicado em:</strong> {pub_date_formatted}
            </p>
            <p class="text-muted mb-2">
                <i class="fas fa-globe me-2"></i>
                <strong>Publicado por:</strong> <a href="{{{{ url_for('index') }}}}" class="text-decoration-none">BNVD.org</a>
            </p>
            <p class="text-muted mb-0">
                <i class="fas fa-external-link-alt me-2"></i>
                <strong>Fonte original:</strong> <a href="{original_link}" target="_blank" rel="noopener noreferrer">CISO Advisor</a>
            </p>
            {category_badge}
        </div>

        <!-- Conteúdo -->
        <div class="news-content mb-4">
            {content_html}
        </div>

        <!-- Botões de Ação -->
        <div class="d-flex gap-3 mb-4 pb-4 border-bottom flex-wrap">
            <button onclick="compartilharNoticia()" class="btn btn-primary">
                <i class="fas fa-share-alt me-2"></i>Compartilhar
            </button>
            <a href="{original_link}" target="_blank" rel="noopener noreferrer" class="btn btn-outline-secondary">
                <i class="fas fa-external-link-alt me-2"></i>Ver Original
            </a>
            <a href="{{{{ url_for('noticias') }}}}" class="btn btn-outline-primary">
                <i class="fas fa-arrow-left me-2"></i>Voltar para Notícias
            </a>
            
            <!-- Botão de Exportação -->
            <div class="dropdown">
                <button class="btn btn-success dropdown-toggle" type="button" id="exportDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="fas fa-download me-2"></i>Exportar Notícia
                </button>
                <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="exportDropdown">
                    <li><h6 class="dropdown-header"><i class="fas fa-file-export me-2"></i>Escolha o formato</h6></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='csv') }}}}">
                        <i class="fas fa-file-csv me-2"></i>CSV
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='json') }}}}">
                        <i class="fas fa-file-code me-2"></i>JSON
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='pdf') }}}}">
                        <i class="fas fa-file-pdf me-2"></i>PDF
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='txt') }}}}">
                        <i class="fas fa-file-alt me-2"></i>TXT
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='docx') }}}}">
                        <i class="fas fa-file-word me-2"></i>DOCX
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='xml') }}}}">
                        <i class="fas fa-file-code me-2"></i>XML
                    </a></li>
                    <li><a class="dropdown-item" href="{{{{ url_for('export_news', slug='{slug}', format='odf') }}}}">
                        <i class="fas fa-file me-2"></i>ODF
                    </a></li>
                </ul>
            </div>
        </div>

        <!-- Créditos -->
        <div class="alert alert-light border">
            <p class="mb-0">
                <i class="fas fa-info-circle me-2"></i>
                <strong>Sobre esta notícia:</strong> Conteúdo publicado originalmente por 
                <a href="https://www.cisoadvisor.com.br" target="_blank" rel="noopener noreferrer">CISO Advisor</a> 
                e republicado pelo BNVD.org.
            </p>
        </div>
    </article>
</div>

<script>
function compartilharNoticia() {{
    const url = window.location.href;

    if (navigator.clipboard) {{
        navigator.clipboard.writeText(url).then(() => {{
            // Criar toast de sucesso
            const toastContainer = document.querySelector('.toast-container') || createToastContainer();
            const toast = document.createElement('div');
            toast.className = 'toast align-items-center text-white bg-success border-0';
            toast.setAttribute('role', 'alert');
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-check-circle me-2"></i>
                        Link copiado para a área de transferência!
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            toastContainer.appendChild(toast);
            const bsToast = new bootstrap.Toast(toast, {{ autohide: true, delay: 3000 }});
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        }}).catch(() => {{
            fallbackCopy(url);
        }});
    }} else {{
        fallbackCopy(url);
    }}
}}

function createToastContainer() {{
    const container = document.createElement('div');
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}}

function fallbackCopy(text) {{
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    document.body.appendChild(textArea);
    textArea.select();
    try {{
        document.execCommand('copy');
        alert('Link copiado para a área de transferência!');
    }} catch (err) {{
        alert('Erro ao copiar link. Por favor, copie manualmente: ' + text);
    }}
    document.body.removeChild(textArea);
}}
</script>

<style>
.news-content {{
    font-size: 1.1rem;
    line-height: 1.8;
}}

.news-content p {{
    margin-bottom: 1.5rem;
}}

.news-meta {{
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.5rem;
}}
</style>
{{% endblock %}}"""

        # Salvar HTML renderizado
        file_path = os.path.join(NEWS_HTML_DIR, f'{slug}.html')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML gerado para notícia: {file_path}")
        return file_path

    def fetch_article_content(self, url: str) -> str:
        """Busca o conteúdo completo da notícia"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Procurar especificamente pelo widget de conteúdo do Elementor usado pelo CISO Advisor
            # Tentar múltiplos seletores
            content_widget = (
                soup.find('div', class_=re.compile(r'elementor-widget-theme-post-content')) or
                soup.find('div', {'data-widget_type': 'theme-post-content.default'})
            )

            if content_widget:
                # Encontrar o container de conteúdo dentro do widget
                content_container = content_widget.find('div', class_='elementor-widget-container')

                if content_container:
                    # Remover elementos indesejados
                    for tag in content_container.find_all(['script', 'style', 'iframe', 'nav', 'aside', 'footer']):
                        tag.decompose()

                    # Remover comentários HTML
                    for comment in content_container.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
                        comment.extract()

                    # Remover divs de anúncios
                    for ad in content_container.find_all(['div', 'ins'], id=re.compile(r'div-gpt-ad')):
                        ad.decompose()

                    # Extrair todos os parágrafos
                    paragraphs = content_container.find_all('p')
                    content_parts = []

                    for p in paragraphs:
                        text = p.get_text().strip()
                        if text and not text.startswith('Leia também'):
                            content_parts.append(text)

                    if content_parts:
                        logger.info(f"Conteúdo extraído com sucesso via Elementor: {len(content_parts)} parágrafos")
                        return '\n\n'.join(content_parts)

            logger.warning("Widget Elementor não encontrado, tentando métodos alternativos")

            # Fallback: tentar métodos alternativos
            article = soup.find('article')
            if not article:
                article = soup.find('div', class_=re.compile(r'(post-content|entry-content|article-content|content)'))

            if not article:
                # Tentar buscar diretamente por parágrafos dentro do main/body
                main_content = soup.find('main') or soup.find('body')
                if main_content:
                    all_paragraphs = main_content.find_all('p')
                    content_parts = []
                    for p in all_paragraphs:
                        text = p.get_text().strip()
                        # Filtrar parágrafos muito curtos ou vazios
                        if text and len(text) > 50 and not text.startswith('Leia também'):
                            content_parts.append(text)

                    if len(content_parts) > 3:  # Pelo menos 3 parágrafos substanciais
                        logger.info(f"Conteúdo extraído via fallback: {len(content_parts)} parágrafos")
                        return '\n\n'.join(content_parts[:20])  # Limitar a 20 parágrafos

            if article:
                # Remover elementos indesejados
                for tag in article.find_all(['script', 'style', 'iframe', 'nav', 'aside', 'footer']):
                    tag.decompose()

                # Remover divs de anúncios
                for ad in article.find_all(['div', 'ins'], class_=re.compile(r'(ad|advertisement|banner|gpt)')):
                    ad.decompose()

                # Extrair texto
                paragraphs = article.find_all('p')
                content_parts = []

                for p in paragraphs:
                    text = p.get_text().strip()
                    if text and not text.startswith('Leia também'):
                        content_parts.append(text)

                if content_parts:
                    return '\n\n'.join(content_parts)

            return "Conteúdo não disponível"

        except Exception as e:
            logger.error(f"Erro ao buscar conteúdo do artigo {url}: {e}")
            return "Erro ao carregar conteúdo"

    def update_news(self):
        """Atualiza as notícias do feed RSS"""
        logger.info("Iniciando atualização de notícias...")

        # Buscar feed RSS
        rss_content = self.fetch_rss_feed()
        if not rss_content:
            logger.warning("Não foi possível obter o feed RSS")
            return

        # Parsear feed
        new_items = self.parse_rss_feed(rss_content)
        if not new_items:
            logger.warning("Nenhuma notícia encontrada no feed")
            return

        # Carregar notícias existentes
        existing_news = self.load_news()
        existing_links = {news['link'] for news in existing_news}

        # Adicionar apenas notícias novas
        added_count = 0
        updated_count = 0
        html_generated_count = 0

        for item in new_items:
            if item['link'] not in existing_links:
                # Buscar conteúdo completo para notícias novas
                logger.info(f"Buscando conteúdo de nova notícia: {item['title']}")
                item['content'] = self.fetch_article_content(item['link'])

                # Criar slug
                item['slug'] = self.create_slug(item['title'])

                # Formatar data
                item['pub_date_formatted'] = self.format_date_brazilian(item.get('pub_date', ''))

                # Gerar HTML automaticamente
                try:
                    self.generate_news_html(item)
                    html_generated_count += 1
                    logger.info(f"HTML gerado para: {item['title']}")
                except Exception as e:
                    logger.error(f"Erro ao gerar HTML para {item['title']}: {e}")

                existing_news.insert(0, item)  # Adicionar no início
                added_count += 1

        # Atualizar notícias existentes: adicionar slug e gerar HTML se não existir
        for news in existing_news:
            # Adicionar slug se não existir
            if 'slug' not in news or not news['slug']:
                news['slug'] = self.create_slug(news['title'])
                updated_count += 1

            # Adicionar data formatada se não existir
            if 'pub_date_formatted' not in news or not news['pub_date_formatted']:
                news['pub_date_formatted'] = self.format_date_brazilian(news.get('pub_date', ''))

            # Reatualizar conteúdo se não estiver disponível
            if not news.get('content') or news.get('content') == 'Conteúdo não disponível':
                logger.info(f"Reatualizando conteúdo de: {news['title']}")
                news['content'] = self.fetch_article_content(news['link'])
                updated_count += 1

            # Gerar HTML se não existir
            slug = news.get('slug', '')
            html_path = os.path.join(NEWS_HTML_DIR, f'{slug}.html')
            if slug and not os.path.exists(html_path):
                try:
                    self.generate_news_html(news)
                    html_generated_count += 1
                    logger.info(f"HTML gerado para: {news['title']}")
                except Exception as e:
                    logger.error(f"Erro ao gerar HTML para {news['title']}: {e}")

        # Salvar notícias atualizadas
        if added_count > 0 or updated_count > 0:
            self.save_news(existing_news)
            logger.info(f"Adicionadas {added_count} novas notícias, {updated_count} atualizadas, {html_generated_count} HTMLs gerados")
        else:
            logger.info("Nenhuma notícia nova encontrada")

    def format_date_brazilian(self, date_string: str) -> str:
        """Formata data para padrão brasileiro com horário de Brasília (UTC-3)"""
        if not date_string:
            return ""
        try:
            # RSS usa formato: Mon, 01 Jan 2024 12:00:00 +0000
            # A data vem em UTC, precisamos converter para horário de Brasília (UTC-3)
            date_obj = datetime.strptime(date_string.split('+')[0].strip(), '%a, %d %b %Y %H:%M:%S')

            # Converter de UTC para horário de Brasília (subtrair 3 horas)
            brasilia_time = date_obj - timedelta(hours=3)

            return brasilia_time.strftime('%d/%m/%Y às %H:%M')
        except:
            return date_string

    def get_recent_news(self, limit: int = 5) -> List[Dict]:
        """Retorna as notícias mais recentes do dia atual (horário de Brasília)"""
        news = self.load_news()
        # Usar horário de Brasília para comparação
        brasilia_now = datetime.now() - timedelta(hours=3)
        today = brasilia_now.date()

        today_news = []
        for item in news:
            try:
                pub_date = item.get('pub_date', '')
                if pub_date:
                    # Data vem em UTC
                    date_obj_utc = datetime.strptime(pub_date.split('+')[0].strip(), '%a, %d %b %Y %H:%M:%S')
                    # Converter para horário de Brasília
                    date_obj_brasilia = date_obj_utc - timedelta(hours=3)

                    if date_obj_brasilia.date() == today:
                        # Adicionar data formatada
                        item['pub_date_formatted'] = self.format_date_brazilian(pub_date)
                        today_news.append(item)
            except:
                continue

        # Se não houver notícias de hoje, retornar as mais recentes com data formatada
        if not today_news:
            for item in news[:limit]:
                item['pub_date_formatted'] = self.format_date_brazilian(item.get('pub_date', ''))
            return news[:limit]

        return today_news[:limit]

    def get_month_news(self) -> List[Dict]:
        """Retorna todas as notícias do mês atual (horário de Brasília) com data formatada"""
        news = self.load_news()
        # Usar horário de Brasília para comparação
        brasilia_now = datetime.now() - timedelta(hours=3)
        current_month = brasilia_now.month
        current_year = brasilia_now.year

        month_news = []
        for item in news:
            try:
                # Tentar parsear a data
                pub_date = item.get('pub_date', '')
                if pub_date:
                    # RSS usa formato: Mon, 01 Jan 2024 12:00:00 +0000 (UTC)
                    date_obj_utc = datetime.strptime(pub_date.split('+')[0].strip(), '%a, %d %b %Y %H:%M:%S')
                    # Converter para horário de Brasília
                    date_obj_brasilia = date_obj_utc - timedelta(hours=3)

                    if date_obj_brasilia.month == current_month and date_obj_brasilia.year == current_year:
                        item['pub_date_formatted'] = self.format_date_brazilian(pub_date)
                        month_news.append(item)
            except:
                continue

        # Fallback para as 20 mais recentes com data formatada
        if not month_news:
            for item in news[:20]:
                item['pub_date_formatted'] = self.format_date_brazilian(item.get('pub_date', ''))
            return news[:20]

        return month_news

    def start_scheduler(self):
        """Inicia o scheduler para atualização automática"""
        if self.scheduler is None:
            self.scheduler = BackgroundScheduler()
            self.scheduler.add_job(
                self.update_news,
                'interval',
                seconds=UPDATE_INTERVAL,
                id='update_news',
                replace_existing=True
            )
            self.scheduler.start()
            logger.info(f"Scheduler iniciado - atualizações a cada {UPDATE_INTERVAL/3600} hora(s)")

            # Fazer primeira atualização imediatamente
            self.update_news()

    def stop_scheduler(self):
        """Para o scheduler"""
        if self.scheduler:
            self.scheduler.shutdown()
            logger.info("Scheduler parado")

# Instância global
advisor_monitor = CISOAdvisorMonitor()

def init_advisor():
    """Inicializa o monitor de notícias"""
    # Forçar reatualização completa incluindo conteúdo de notícias existentes
    logger.info("Inicializando sistema de notícias com atualização completa")
    advisor_monitor.update_news()
    advisor_monitor.start_scheduler()

def get_recent_news(limit: int = 5) -> List[Dict]:
    """Função helper para obter notícias recentes"""
    return advisor_monitor.get_recent_news(limit)

def get_month_news() -> List[Dict]:
    """Função helper para obter notícias do mês"""
    return advisor_monitor.get_month_news()

def get_all_news() -> List[Dict]:
    """Função helper para obter todas as notícias"""
    news = advisor_monitor.load_news()
    # Adicionar data formatada para todas as notícias
    for item in news:
        if 'pub_date_formatted' not in item or not item['pub_date_formatted']:
            item['pub_date_formatted'] = advisor_monitor.format_date_brazilian(item.get('pub_date', ''))
    return news

def get_news_by_slug(slug: str) -> Optional[Dict]:
    """Função helper para obter uma notícia específica pelo slug"""
    news = advisor_monitor.load_news()
    for item in news:
        if item.get('slug') == slug:
            # Adicionar data formatada se não existir
            if 'pub_date_formatted' not in item or not item['pub_date_formatted']:
                item['pub_date_formatted'] = advisor_monitor.format_date_brazilian(item.get('pub_date', ''))
            return item
    return None

def get_news_content(link: str) -> str:
    """Função helper para obter conteúdo de uma notícia específica"""
    news = advisor_monitor.load_news()
    for item in news:
        if item['link'] == link:
            return item.get('content', 'Conteúdo não disponível')
    return 'Notícia não encontrada'

if __name__ == "__main__":
    # Teste manual
    monitor = CISOAdvisorMonitor()
    monitor.update_news()

    print(f"\n{'='*60}")
    print("5 Notícias mais recentes:")
    print('='*60)
    for news in monitor.get_recent_news(5):
        print(f"\nTítulo: {news['title']}")
        print(f"Data: {news['pub_date']}")
        print(f"Categoria: {news['category']}")
        print(f"Descrição: {news['description'][:100]}...")