// BNVD - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Inicializar componentes
    initializeTooltips();
    initializeAlerts();
    initializeSearchForm();
    initializeLoadingStates();
    initializeScrollToTop();
    
    // Adicionar animações suaves
    addFadeInAnimations();
});

/**
 * Inicializar tooltips do Bootstrap
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Auto-hide alerts após 5 segundos
 */
function initializeAlerts() {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
}

/**
 * Melhorar formulário de busca
 */
function initializeSearchForm() {
    const searchForms = document.querySelectorAll('form');
    
    searchForms.forEach(form => {
        // Adicionar indicador de loading ao submeter
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Buscando...';
                submitBtn.disabled = true;
                
                // Restaurar após 10 segundos como fallback
                setTimeout(() => {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }, 10000);
            }
        });
        
        // Validação em tempo real
        const inputs = form.querySelectorAll('input[type="text"]');
        inputs.forEach(input => {
            input.addEventListener('input', function() {
                validateInput(this);
            });
        });
    });
}

/**
 * Validar entrada de CVE ID
 */
function validateInput(input) {
    if (input.name === 'cve_id' && input.value) {
        const cvePattern = /^CVE-\d{4}-\d{4,}$/i;
        const isValid = cvePattern.test(input.value);
        
        input.classList.toggle('is-valid', isValid);
        input.classList.toggle('is-invalid', !isValid && input.value.length > 0);
        
        // Mostrar feedback
        let feedback = input.nextElementSibling;
        if (!feedback || !feedback.classList.contains('feedback')) {
            feedback = document.createElement('div');
            feedback.classList.add('feedback', 'small', 'mt-1');
            input.parentNode.insertBefore(feedback, input.nextSibling);
        }
        
        if (!isValid && input.value.length > 0) {
            feedback.textContent = 'Formato deve ser: CVE-YYYY-NNNN';
            feedback.className = 'feedback small mt-1 text-danger';
        } else if (isValid) {
            feedback.textContent = 'Formato válido';
            feedback.className = 'feedback small mt-1 text-success';
        } else {
            feedback.textContent = '';
        }
    }
}

/**
 * Estados de loading para elementos
 */
function initializeLoadingStates() {
    // Adicionar loading aos links de detalhes
    const detailLinks = document.querySelectorAll('a[href*="/vulnerabilidade/"]');
    detailLinks.forEach(link => {
        link.addEventListener('click', function() {
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Carregando...';
        });
    });
}

/**
 * Botão de volta ao topo
 */
function initializeScrollToTop() {
    // Criar botão com label
    const scrollBtn = document.createElement('a');
    scrollBtn.href = '#';
    scrollBtn.className = 'scroll-to-top';
    scrollBtn.innerHTML = `
        <i class="fas fa-arrow-up"></i>
        <span class="btn-text">Topo</span>
    `;
    scrollBtn.setAttribute('title', 'Voltar ao topo');
    scrollBtn.setAttribute('aria-label', 'Voltar ao topo da página');
    
    document.body.appendChild(scrollBtn);
    
    // Mostrar/esconder baseado no scroll
    window.addEventListener('scroll', debounce(() => {
        if (window.scrollY > 300) {
            scrollBtn.classList.add('show');
        } else {
            scrollBtn.classList.remove('show');
        }
    }, 100));
    
    // Scroll suave para o topo
    scrollBtn.addEventListener('click', (e) => {
        e.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
        
        // Feedback visual
        scrollBtn.style.transform = 'translateY(-5px) scale(0.95)';
        setTimeout(() => {
            scrollBtn.style.transform = '';
        }, 150);
    });
}

/**
 * Adicionar animações de fade-in
 */
function addFadeInAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observar cards e elementos importantes
    const elementsToAnimate = document.querySelectorAll('.card, .alert, .hero-section');
    elementsToAnimate.forEach(el => {
        observer.observe(el);
    });
}

/**
 * Copiar texto para clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Link copiado para a área de transferência!', 'success');
        }).catch(() => {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

/**
 * Fallback para copiar texto (navegadores antigos)
 */
function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('Link copiado para a área de transferência!', 'success');
    } catch (err) {
        showNotification('Erro ao copiar link', 'error');
    }
    
    document.body.removeChild(textArea);
}

/**
 * Mostrar notificação toast
 */
function showNotification(message, type = 'info') {
    // Criar container de toasts se não existir
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }
    
    // Criar toast
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas fa-${type === 'success' ? 'check' : 'info'}-circle me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    // Mostrar toast
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 3000
    });
    bsToast.show();
    
    // Remover do DOM após fechar
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

/**
 * Formatear número com separadores de milhares
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

/**
 * Debounce para otimizar eventos
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Atualizar contadores na página
 */
function updateCounters() {
    const counters = document.querySelectorAll('[data-counter]');
    counters.forEach(counter => {
        const target = parseInt(counter.getAttribute('data-counter'));
        const duration = 2000;
        const step = target / (duration / 16);
        let current = 0;
        
        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            counter.textContent = formatNumber(Math.floor(current));
        }, 16);
    });
}

/**
 * Verificar conectividade
 */
function checkConnectivity() {
    const isOnline = navigator.onLine;
    const statusIndicator = document.querySelector('.connectivity-status');
    
    if (statusIndicator) {
        statusIndicator.className = `connectivity-status badge ${isOnline ? 'bg-success' : 'bg-danger'}`;
        statusIndicator.textContent = isOnline ? 'Online' : 'Offline';
    }
}

// Event listeners para conectividade
window.addEventListener('online', checkConnectivity);
window.addEventListener('offline', checkConnectivity);

/**
 * Melhorar acessibilidade
 */
function enhanceAccessibility() {
    // Adicionar ARIA labels dinâmicos
    const buttons = document.querySelectorAll('button:not([aria-label])');
    buttons.forEach(btn => {
        if (btn.textContent.trim()) {
            btn.setAttribute('aria-label', btn.textContent.trim());
        }
    });
    
    // Melhorar navegação por teclado
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.setAttribute('tabindex', '0');
        card.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                const link = card.querySelector('a');
                if (link) {
                    link.click();
                }
            }
        });
    });
}

// Inicializar melhorias de acessibilidade
document.addEventListener('DOMContentLoaded', enhanceAccessibility);

/**
 * Analytics simples (sem cookies)
 */
function trackPageView() {
    // Implementar analytics respeitando LGPD
    const pageData = {
        url: window.location.pathname,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent.substring(0, 100)
    };
    
    // Enviar dados apenas se consentimento for dado
    const hasConsent = localStorage.getItem('analytics_consent');
    if (hasConsent === 'true') {
        // Implementar envio de dados aqui
        console.log('Page view tracked:', pageData);
    }
}

/**
 * Gerenciar preferências do usuário
 */
function manageUserPreferences() {
    // Tema escuro/claro
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-theme');
            const isDark = document.body.classList.contains('dark-theme');
            localStorage.setItem('dark_theme', isDark);
        });
    }
    
    // Carregar preferência salva
    const savedTheme = localStorage.getItem('dark_theme');
    if (savedTheme === 'true') {
        document.body.classList.add('dark-theme');
    }
}

// Exportar funções para uso global
window.CVEBrasil = {
    copyToClipboard,
    showNotification,
    formatNumber,
    updateCounters,
    trackPageView
};
