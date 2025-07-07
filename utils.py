import re
from datetime import datetime
from typing import Dict, List, Any, Optional

def translate_severity(severity: str) -> str:
    """Traduz severidade CVSS para português"""
    translations = {
        'NONE': 'Nenhuma',
        'LOW': 'Baixa',
        'MEDIUM': 'Média',
        'HIGH': 'Alta',
        'CRITICAL': 'Crítica'
    }
    return translations.get(severity.upper(), severity)

def translate_cvss_metrics(term: str) -> str:
    """Traduz termos relacionados a métricas CVSS para português"""
    translations = {
        # Attack Vector / Vetor de Ataque
        'NETWORK': 'Rede',
        'ADJACENT_NETWORK': 'Rede Adjacente',
        'LOCAL': 'Local',
        'PHYSICAL': 'Físico',
        
        # Attack Complexity / Complexidade do Ataque
        'LOW': 'Baixa',
        'HIGH': 'Alta',
        
        # Privileges Required / Privilégios Necessários
        'NONE': 'Nenhum',
        'REQUIRED': 'Necessário',
        
        # User Interaction / Interação do Usuário
        'REQUIRED': 'Necessária',
        
        # Scope / Escopo
        'UNCHANGED': 'Inalterado',
        'CHANGED': 'Alterado',
        
        # Impact Metrics / Métricas de Impacto
        'COMPLETE': 'Completo',
        'PARTIAL': 'Parcial',
        
        # Base Score / Pontuação Base
        'CRITICAL': 'Crítica',
        'HIGH': 'Alta',
        'MEDIUM': 'Média',
        'LOW': 'Baixa',
        'NONE': 'Nenhuma',
        
        # Exploitability / Explorabilidade
        'UNPROVEN': 'Não Comprovada',
        'PROOF_OF_CONCEPT': 'Prova de Conceito',
        'FUNCTIONAL': 'Funcional',
        'HIGH': 'Alta',
        
        # Remediation Level / Nível de Correção
        'OFFICIAL_FIX': 'Correção Oficial',
        'TEMPORARY_FIX': 'Correção Temporária',
        'WORKAROUND': 'Solução Alternativa',
        'UNAVAILABLE': 'Indisponível',
        
        # Report Confidence / Confiança do Relatório
        'UNKNOWN': 'Desconhecida',
        'REASONABLE': 'Razoável',
        'CONFIRMED': 'Confirmada',
        
        # Status Vulnerability - Comprehensive Status Translations (100+ new entries)
        'AWAITING_ANALYSIS': 'Aguardando Análise',
        'ANALYZED': 'Analisada',
        'MODIFIED': 'Modificada',
        'PUBLISHED': 'Publicada',
        'REJECTED': 'Rejeitada',
        'UNDERGOING_ANALYSIS': 'Em Análise',
        'RECEIVED': 'Recebida',
        'DISPUTED': 'Contestada',
        'DEFERRED': 'Adiada',
        'PENDING': 'Pendente',
        'APPROVED': 'Aprovada',
        'CANCELLED': 'Cancelada',
        'SUSPENDED': 'Suspensa',
        'ACTIVE': 'Ativa',
        'INACTIVE': 'Inativa',
        'ARCHIVED': 'Arquivada',
        'DRAFT': 'Rascunho',
        'PRELIMINARY': 'Preliminar',
        'FINAL': 'Final',
        'UPDATED': 'Atualizada',
        'WITHDRAWN': 'Retirada',
        'SUPERSEDED': 'Substituída',
        'OBSOLETE': 'Obsoleta',
        'DEPRECATED': 'Descontinuada',
        'RESERVED': 'Reservada',
        'ASSIGNED': 'Designada',
        'UNASSIGNED': 'Não Designada',
        'OPEN': 'Aberta',
        'CLOSED': 'Fechada',
        'RESOLVED': 'Resolvida',
        'FIXED': 'Corrigida',
        'UNFIXED': 'Não Corrigida',
        'PATCHED': 'Corrigida com Patch',
        'UNPATCHED': 'Sem Patch',
        'VERIFIED': 'Verificada',
        'UNVERIFIED': 'Não Verificada',
        'CONFIRMED': 'Confirmada',
        'UNCONFIRMED': 'Não Confirmada',
        'VALIDATED': 'Validada',
        'INVALID': 'Inválida',
        'DUPLICATE': 'Duplicada',
        'FALSE_POSITIVE': 'Falso Positivo',
        'TRUE_POSITIVE': 'Verdadeiro Positivo',
        'ESCALATED': 'Escalada',
        'DE_ESCALATED': 'Desescalada',
        'PRIORITIZED': 'Priorizada',
        'DEPRIORITIZED': 'Despriorizada',
        'TRIAGED': 'Triaged',
        'UNTRIAGED': 'Não Triaged',
        'INVESTIGATED': 'Investigada',
        'UNDER_INVESTIGATION': 'Sob Investigação',
        'REPRODUCED': 'Reproduzida',
        'UNREPRODUCED': 'Não Reproduzida',
        'TESTING': 'Em Teste',
        'TESTED': 'Testada',
        'ACCEPTED': 'Aceita',
        'DECLINED': 'Recusada',
        'POSTPONED': 'Postergada',
        'SCHEDULED': 'Agendada',
        'IN_PROGRESS': 'Em Progresso',
        'COMPLETED': 'Completada',
        'INCOMPLETE': 'Incompleta',
        'BLOCKED': 'Bloqueada',
        'UNBLOCKED': 'Desbloqueada',
        'MERGED': 'Mesclada',
        'SPLIT': 'Dividida',
        'LINKED': 'Vinculada',
        'UNLINKED': 'Desvinculada',
        'RELATED': 'Relacionada',
        'UNRELATED': 'Não Relacionada',
        'REFERENCED': 'Referenciada',
        'UNREFERENCED': 'Não Referenciada',
        'DOCUMENTED': 'Documentada',
        'UNDOCUMENTED': 'Não Documentada',
        'NOTIFIED': 'Notificada',
        'UNNOTIFIED': 'Não Notificada',
        'DISCLOSED': 'Divulgada',
        'UNDISCLOSED': 'Não Divulgada',
        'PUBLIC': 'Pública',
        'PRIVATE': 'Privada',
        'CONFIDENTIAL': 'Confidencial',
        'RESTRICTED': 'Restrita',
        'CLASSIFIED': 'Classificada',
        'UNCLASSIFIED': 'Não Classificada',
        'SENSITIVE': 'Sensível',
        'INSENSITIVE': 'Não Sensível',
        'CRITICAL': 'Crítica',
        'NONCRITICAL': 'Não Crítica',
        'URGENT': 'Urgente',
        'NORMAL': 'Normal',
        'ROUTINE': 'Rotineira',
        'EMERGENCY': 'Emergência',
        'IMMEDIATE': 'Imediata',
        'EXPEDITED': 'Expedita',
        'STANDARD': 'Padrão',
        'CUSTOM': 'Personalizada',
        'AUTOMATED': 'Automatizada',
        'MANUAL': 'Manual',
        'SYSTEMATIC': 'Sistemática',
        'ADHOC': 'Ad Hoc',
        'SCHEDULED': 'Programada',
        'UNSCHEDULED': 'Não Programada',
        'COORDINATED': 'Coordenada',
        'UNCOORDINATED': 'Não Coordenada',
        'SYNCHRONIZED': 'Sincronizada',
        'UNSYNCHRONIZED': 'Não Sincronizada',
        'ALIGNED': 'Alinhada',
        'MISALIGNED': 'Desalinhada',
        'CONSISTENT': 'Consistente',
        'INCONSISTENT': 'Inconsistente',
        'STABLE': 'Estável',
        'UNSTABLE': 'Instável',
        'SECURE': 'Segura',
        'INSECURE': 'Insegura',
        'VULNERABLE': 'Vulnerável',
        'INVULNERABLE': 'Invulnerável',
        'EXPOSED': 'Exposta',
        'PROTECTED': 'Protegida',
        'MONITORED': 'Monitorada',
        'UNMONITORED': 'Não Monitorada',
        'TRACKED': 'Rastreada',
        'UNTRACKED': 'Não Rastreada',
        'LOGGED': 'Registrada',
        'UNLOGGED': 'Não Registrada',
        'AUDITED': 'Auditada',
        'UNAUDITED': 'Não Auditada',
        
        # Additional CVSS Terms
        'CONFIDENTIALITY': 'Confidencialidade',
        'INTEGRITY': 'Integridade',
        'AVAILABILITY': 'Disponibilidade',
        'AUTHENTICATION': 'Autenticação',
        'ACCESS_VECTOR': 'Vetor de Acesso',
        'ACCESS_COMPLEXITY': 'Complexidade de Acesso',
        'SINGLE': 'Único',
        'MULTIPLE': 'Múltiplo',
        'IMPACT': 'Impacto',
        'EXPLOITABILITY': 'Explorabilidade',
        'ENVIRONMENTAL': 'Ambiental',
        'TEMPORAL': 'Temporal'
    }
    return translations.get(term.upper(), term)

def translate_cwe(cwe_id: str) -> str:
    """Traduz CWE comuns para português - Dicionário Extenso com 100+ CWEs"""
    translations = {
        # Top 25 Most Dangerous Software Weaknesses
        'CWE-79': 'Cross-site Scripting (XSS) - Script Entre Sites',
        'CWE-89': 'Injeção SQL',
        'CWE-20': 'Validação de Entrada Inadequada',
        'CWE-125': 'Leitura Fora dos Limites',
        'CWE-78': 'Injeção de Comando do Sistema Operacional',
        'CWE-22': 'Travessia de Diretório/Caminho',
        'CWE-352': 'Cross-Site Request Forgery (CSRF)',
        'CWE-434': 'Upload de Arquivo Perigoso',
        'CWE-862': 'Autorização Ausente',
        'CWE-476': 'Desreferenciamento de Ponteiro NULL',
        'CWE-287': 'Autenticação Inadequada',
        'CWE-190': 'Overflow de Inteiro',
        'CWE-502': 'Desserialização de Dados Não Confiáveis',
        'CWE-77': 'Neutralização Inadequada de Elementos Especiais Usados em Comando',
        'CWE-119': 'Restrição Inadequada de Operações Dentro dos Limites de Buffer',
        'CWE-798': 'Uso de Credenciais Codificadas',
        'CWE-918': 'Falsificação de Solicitação do Lado do Servidor (SSRF)',
        'CWE-306': 'Autenticação Ausente para Função Crítica',
        'CWE-362': 'Acesso Concorrente a Recursos Compartilhados',
        'CWE-269': 'Gerenciamento de Privilégios Inadequado',
        'CWE-94': 'Injeção de Código',
        'CWE-863': 'Autorização Incorreta',
        'CWE-276': 'Permissões Padrão Incorretas',
        'CWE-200': 'Exposição de Informações Sensíveis',
        'CWE-522': 'Credenciais Insuficientemente Protegidas',
        
        # Buffer Errors / Erros de Buffer
        'CWE-120': 'Cópia de Buffer Sem Verificação de Tamanho',
        'CWE-121': 'Overflow de Buffer Baseado em Stack',
        'CWE-122': 'Overflow de Buffer Baseado em Heap',
        'CWE-124': 'Underflow de Buffer',
        'CWE-126': 'Underrun de Buffer',
        'CWE-127': 'Overflow de Buffer',
        'CWE-131': 'Cálculo de Tamanho de Buffer Incorreto',
        'CWE-787': 'Escrita Fora dos Limites',
        'CWE-788': 'Acesso a Memória Usando Índice Incorreto',
        'CWE-416': 'Uso Após Liberação',
        'CWE-415': 'Liberação Dupla',
        'CWE-404': 'Liberação Inadequada de Recurso',
        
        # Injection Flaws / Falhas de Injeção
        'CWE-90': 'Injeção LDAP',
        'CWE-91': 'Injeção XML',
        'CWE-93': 'Neutralização Inadequada de Elementos CRLF',
        'CWE-95': 'Injeção de Código Eval',
        'CWE-96': 'Injeção de Código Server-Side Includes',
        'CWE-97': 'Inclusão de Arquivo Server-Side',
        'CWE-98': 'Inclusão de Arquivo Remoto',
        'CWE-99': 'Neutralização Inadequada de Elementos de Controle de Recurso',
        'CWE-100': 'Tecnologia Obsoleta',
        'CWE-601': 'Redirecionamento para Site Não Confiável',
        
        # Cryptographic Issues / Problemas Criptográficos
        'CWE-327': 'Uso de Algoritmo Criptográfico Quebrado ou Arriscado',
        'CWE-328': 'Hash Reversível',
        'CWE-329': 'Geração de Valor Pseudo-Aleatório Inadequada',
        'CWE-330': 'Uso de Valores Insuficientemente Aleatórios',
        'CWE-331': 'Entropia Insuficiente',
        'CWE-332': 'Entropia Insuficiente na PRNG',
        'CWE-333': 'Gerador de Números Pseudo-Aleatórios Pequeno Demais',
        'CWE-334': 'Estado Pequeno na PRNG',
        'CWE-335': 'Seed de PRNG Incorreta',
        'CWE-336': 'Mesma Seed na PRNG',
        'CWE-337': 'PRNG Previsível',
        'CWE-338': 'Uso de PRNG Criptograficamente Fraca',
        
        # Authentication Issues / Problemas de Autenticação
        'CWE-288': 'Autenticação Usando Credenciais Alternativas',
        'CWE-290': 'Falsificação de Autenticação',
        'CWE-294': 'Interceptação de Canal de Autenticação',
        'CWE-295': 'Validação Inadequada de Certificado',
        'CWE-297': 'Validação Inadequada de Certificado com Incompatibilidade de Host',
        'CWE-300': 'Canal Não Criptografado para Credenciais',
        'CWE-302': 'Falha na Validação de Token de Autenticação',
        'CWE-304': 'Ausência de Autenticação para Função Crítica',
        'CWE-305': 'Falha na Autenticação para Função Crítica',
        
        # Authorization Issues / Problemas de Autorização
        'CWE-285': 'Autorização Inadequada',
        'CWE-286': 'Permissões Inadequadas',
        'CWE-732': 'Atribuição Incorreta de Permissões para Recurso Crítico',
        'CWE-264': 'Permissões, Privilégios e Controles de Acesso',
        'CWE-266': 'Privilégios Incorretos',
        'CWE-267': 'Verificação de Privilégio Inadequada',
        'CWE-268': 'Gerenciamento de Privilégio Inadequado',
        'CWE-270': 'Separação de Privilégio Inadequada',
        'CWE-271': 'Dropping de Privilégio Inadequado',
        
        # Input Validation / Validação de Entrada
        'CWE-74': 'Neutralização Inadequada de Elementos Especiais em Saída',
        'CWE-75': 'Falha na Sanitização de Elementos Especiais',
        'CWE-76': 'Neutralização Inadequada de Equivalentes Codificados',
        'CWE-80': 'Cross-site Scripting (XSS) Baseado em Atributo',
        'CWE-81': 'Cross-site Scripting (XSS) de Tratamento de Erro',
        'CWE-82': 'Neutralização Inadequada de Comentários',
        'CWE-83': 'Neutralização Inadequada de Tags de Script',
        'CWE-84': 'Cross-site Scripting (XSS) Refletido',
        'CWE-85': 'Cross-site Scripting (XSS) Duplo Codificado',
        'CWE-86': 'Cross-site Scripting (XSS) Baseado em URL',
        'CWE-87': 'Falha na Neutralização de Caracteres Alternativos',
        'CWE-88': 'Falha na Construção de Argumento',
        
        # Session Management / Gerenciamento de Sessão
        'CWE-384': 'Fixação de Sessão',
        'CWE-346': 'Fixação de Origem',
        'CWE-347': 'Validação Inadequada de Assinatura Criptográfica',
        'CWE-384': 'Fixação de Sessão',
        'CWE-613': 'Expiração Inadequada de Sessão',
        
        # Information Disclosure / Divulgação de Informações
        'CWE-209': 'Geração de Mensagem de Erro com Informações Sensíveis',
        'CWE-215': 'Vazamento de Informações Através de Mensagens de Debug',
        'CWE-532': 'Inserção de Informações Sensíveis em Arquivo de Log',
        'CWE-533': 'Exposição de Informações Através de Arquivos Temporários',
        'CWE-534': 'Exposição de Informações Através de Comentários',
        'CWE-535': 'Exposição de Informações Através de Dados de Shell History',
        'CWE-536': 'Exposição de Informações Através de Arquivo Servlet',
        'CWE-537': 'Inserção de Informações Java Runtime Error em JSP',
        
        # Resource Management / Gerenciamento de Recursos
        'CWE-401': 'Liberação Inadequada de Memória',
        'CWE-402': 'Transmissão de Dados Privados para Esfera Errada',
        'CWE-403': 'Exposição de Dados de Arquivo ou Diretório',
        'CWE-405': 'Exaustão de Recurso Assimétrica',
        'CWE-406': 'Exaustão de Recurso Insuficiente',
        'CWE-407': 'Ineficiência Algorítmica',
        'CWE-408': 'Ineficiência Algorítmica Incorreta',
        'CWE-409': 'Controle Inadequado de Recursos',
        'CWE-410': 'Alocação Inadequada de Recursos',
        'CWE-411': 'Liberação Inadequada de Recursos',
        
        # Concurrency Issues / Problemas de Concorrência
        'CWE-364': 'Signal Handler com Funções Não Seguras',
        'CWE-365': 'Condição de Corrida em Switch',
        'CWE-366': 'Condição de Corrida Dentro de Thread',
        'CWE-367': 'Time-of-check Time-of-use (TOCTOU)',
        'CWE-368': 'Dependência de Contexto',
        'CWE-369': 'Divisão por Zero',
        'CWE-370': 'Número de Referência Ausente ou Incorreto',
        'CWE-371': 'Resolução de Estado Incompatível',
        'CWE-372': 'Estado Incompatível',
        'CWE-820': 'Sincronização Inadequada',
        
        # Additional CWE Translations - 200+ New Entries
        'CWE-1': 'Condição de Corrida em Variáveis Estáticas',
        'CWE-2': 'Buffer Overflow via Variável de Ambiente',
        'CWE-3': 'Buffer Overflow via Parâmetro de Linha de Comando',
        'CWE-4': 'Buffer Overflow em Função',
        'CWE-5': 'Buffer Overflow em Valor de Índice J2EE',
        'CWE-6': 'Buffer Overflow em stdin',
        'CWE-7': 'Buffer Overflow de Script J2EE',
        'CWE-8': 'Buffer Overflow de Objeto J2EE',
        'CWE-9': 'Buffer Overflow de Struts',
        'CWE-10': 'Buffer Overflow de ASP.NET',
        'CWE-11': 'Falha na Verificação de Limite em Estrutura ASP.NET',
        'CWE-12': 'Falha na Verificação de Limite em Estrutura ASP.NET Misconfigured',
        'CWE-13': 'Falha na Verificação de Limite em ASP.NET',
        'CWE-14': 'Comparação de Ponteiro',
        'CWE-15': 'Acesso Externo a Sistema de Arquivos',
        'CWE-16': 'Configuração',
        'CWE-17': 'Bloqueio de Código',
        'CWE-18': 'Path Injection',
        'CWE-19': 'Resolução de Dados Incorreta',
        'CWE-21': 'Path Equivalence: Nome de Caminho',
        'CWE-23': 'Path Equivalence: Caminho Absoluto',
        'CWE-24': 'Path Equivalence: internal dot',
        'CWE-25': 'Path Equivalence: multiple internal dot',
        'CWE-26': 'Path Equivalence: filename space',
        'CWE-27': 'Path Equivalence: filename starts with space',
        'CWE-28': 'Path Equivalence: filename tilde',
        'CWE-29': 'Path Equivalence: filename nullbyte',
        'CWE-30': 'Path Equivalence: filename leading dot',
        'CWE-31': 'Path Equivalence: filename multiple dot',
        'CWE-32': 'Path Equivalence: mixed case',
        'CWE-33': 'Path Equivalence: file extension inconsistency',
        'CWE-34': 'Path Equivalence: trailing space',
        'CWE-35': 'Path Equivalence: trailing dot',
        'CWE-36': 'Path Equivalence: leading dot',
        'CWE-37': 'Path Equivalence: multiple leading dots',
        'CWE-38': 'Path Equivalence: leading dot-dot',
        'CWE-39': 'Path Equivalence: not canonical',
        'CWE-40': 'Path Equivalence: UNC share',
        'CWE-41': 'Resolução Inadequada de Elemento de Caminho',
        'CWE-42': 'Path Equivalence: filename space EOF',
        'CWE-43': 'Path Equivalence: multiple trailing slash',
        'CWE-44': 'Path Equivalence: file.dir',
        'CWE-45': 'Path Equivalence: file...dir',
        'CWE-46': 'Path Equivalence: filename (space) name',
        'CWE-47': 'Path Equivalence: space filename',
        'CWE-48': 'Path Equivalence: file name',
        'CWE-49': 'Path Equivalence: filename leading space',
        'CWE-50': 'Path Equivalence: irregularities',
        'CWE-51': 'Path Equivalence: single dot',
        'CWE-52': 'Path Equivalence: multiple internal backslash',
        'CWE-53': 'Path Equivalence: multiple internal slash',
        'CWE-54': 'Path Equivalence: trailing slash',
        'CWE-55': 'Path Equivalence: alternate character encoding',
        'CWE-56': 'Path Equivalence: alternate character encoding dot',
        'CWE-57': 'Path Equivalence: alternate character encoding slash',
        'CWE-58': 'Path Equivalence: Windows 8.3 filename',
        'CWE-59': 'Resolução Inadequada de Link para Arquivo',
        'CWE-60': 'Unix Symbolic Link Following',
        'CWE-61': 'Unix Hard Link',
        'CWE-62': 'Unix Symbolic Link Following to File',
        'CWE-63': 'Windows Shortcut Following',
        'CWE-64': 'Windows Shortcut Following',
        'CWE-65': 'Windows Hard Link',
        'CWE-66': 'Neutralização Inadequada de Delimitadores',
        'CWE-67': 'Neutralização Inadequada de Elementos Especiais em Query',
        'CWE-68': 'Windows Executable Forgery',
        'CWE-69': 'Neutralização Inadequada de Valor em Meta-tag HTTP',
        'CWE-70': 'Neutralização Inadequada de Comentários em Script',
        'CWE-71': 'Validação Inadequada de Apple .DS_Store',
        'CWE-72': 'Validação Inadequada de Controle de Versão',
        'CWE-73': 'Controle Externo de Nome de Arquivo',
        'CWE-92': 'Sanitização Cross-site Scripting',
        'CWE-101': 'Struts: Duplicated Validation Forms',
        'CWE-102': 'Struts: Incomplete Error Handling',
        'CWE-103': 'Struts: Incomplete Resource Cleanup',
        'CWE-104': 'Struts: Form Bean Does Not Extend Validation Class',
        'CWE-105': 'Struts: Form Field Without Validator',
        'CWE-106': 'Struts: Plug-in Framework not in Use',
        'CWE-107': 'Struts: Unused Validation Form',
        'CWE-108': 'Struts: Unvalidated Action Form',
        'CWE-109': 'Struts: Validator Turned Off',
        'CWE-110': 'Struts: Validator Without Form Field',
        'CWE-111': 'Direct Use of Unsafe JNI',
        'CWE-112': 'Missing XML Validation',
        'CWE-113': 'Neutralização Inadequada de CRLF em HTTP Headers',
        'CWE-114': 'Process Control',
        'CWE-115': 'Misinterpretation of Input',
        'CWE-116': 'Encoding ou Escaping Inadequados',
        'CWE-117': 'Log Output Neutralization',
        'CWE-118': 'Acesso Incorreto a Buffer Indexado',
        'CWE-123': 'Write-what-where Condition',
        'CWE-128': 'Wrap-around Error',
        'CWE-129': 'Uso Inadequado de Validação de Array Index',
        'CWE-130': 'Uso Inadequado de Validação de Array Index',
        'CWE-132': 'Misuse of Storage',
        'CWE-133': 'String Representation Error',
        'CWE-134': 'Uso de String Format Externa Não Controlada',
        'CWE-135': 'Multibyte Encoding with Inconsistent Leading Bytes',
        'CWE-136': 'Type Errors',
        'CWE-137': 'Representation Errors',
        'CWE-138': 'Neutralização Inadequada de Dados',
        'CWE-140': 'Neutralização Inadequada de Delimitadores',
        'CWE-141': 'Neutralização Inadequada de Parâmetros',
        'CWE-142': 'Neutralização Inadequada de Value Delimiters',
        'CWE-143': 'Neutralização Inadequada de Record Delimiters',
        'CWE-144': 'Neutralização Inadequada de Line Delimiters',
        'CWE-145': 'Neutralização Inadequada de Section Delimiters',
        'CWE-146': 'Neutralização Inadequada de Expression Delimiters',
        'CWE-147': 'Neutralização Inadequada de Quote Delimiters',
        'CWE-148': 'Neutralização Inadequada de Comment Delimiters',
        'CWE-149': 'Neutralização Inadequada de Quoting Syntax',
        'CWE-150': 'Neutralização Inadequada de Escape/Meta Characters',
        'CWE-151': 'Neutralização Inadequada de Comment Delimiters',
        'CWE-152': 'Neutralização Inadequada de Macro Symbol',
        'CWE-153': 'Neutralização Inadequada de Substitution Characters',
        'CWE-154': 'Neutralização Inadequada de Variable Name Delimiters',
        'CWE-155': 'Neutralização Inadequada de Wildcards',
        'CWE-156': 'Neutralização Inadequada de Whitespace',
        'CWE-157': 'Failure to Sanitize Paired Delimiters',
        'CWE-158': 'Neutralização Inadequada de Null Bytes',
        'CWE-159': 'Neutralização Inadequada de Special Elements',
        'CWE-160': 'Neutralização Inadequada de Leading Special Elements',
        'CWE-161': 'Neutralização Inadequada de Multiple Leading Special Elements',
        'CWE-162': 'Neutralização Inadequada de Trailing Special Elements',
        'CWE-163': 'Neutralização Inadequada de Multiple Trailing Special Elements',
        'CWE-164': 'Neutralização Inadequada de Internal Special Elements',
        'CWE-165': 'Neutralização Inadequada de Multiple Internal Special Elements',
        'CWE-166': 'Neutralização Inadequada de Alternate Encoding',
        'CWE-167': 'Neutralização Inadequada de Alternate Name',
        'CWE-168': 'Neutralização Inadequada de Inconsistent Special Elements',
        'CWE-169': 'Neutralização Inadequada de Invalid Characters',
        'CWE-170': 'Neutralização Inadequada de Web Scripting Syntax',
        'CWE-171': 'Neutralização Inadequada de Web Scripting Syntax in Headers',
        'CWE-172': 'Encoding Error',
        'CWE-173': 'Neutralização Inadequada de Alternate Encoding',
        'CWE-174': 'Double Decoding of the Same Data',
        'CWE-175': 'Neutralização Inadequada de Mixed Encoding',
        'CWE-176': 'Neutralização Inadequada de Unicode Encoding',
        'CWE-177': 'Neutralização Inadequada de URL Encoding',
        'CWE-178': 'Neutralização Inadequada de Case Sensitivity',
        'CWE-179': 'Incorrect Behavior Order: Early Validation',
        'CWE-180': 'Incorrect Behavior Order: Validate Before Canonicalize',
        'CWE-181': 'Incorrect Behavior Order: Validate Before Filter',
        'CWE-182': 'Collapse of Data into Unsafe Value',
        'CWE-183': 'Permissive List of Allowed Inputs',
        'CWE-184': 'Incomplete List of Disallowed Inputs',
        'CWE-185': 'Incorrect Regular Expression',
        'CWE-186': 'Overly Restrictive Regular Expression',
        'CWE-187': 'Partial String Comparison',
        'CWE-188': 'Reliance on Data/Memory Layout',
        'CWE-189': 'Numeric Errors',
        'CWE-191': 'Integer Underflow',
        'CWE-192': 'Integer Coercion Error',
        'CWE-193': 'Off-by-one Error',
        'CWE-194': 'Unexpected Sign Extension',
        'CWE-195': 'Signed to Unsigned Conversion Error',
        'CWE-196': 'Unsigned to Signed Conversion Error',
        'CWE-197': 'Numeric Truncation Error',
        'CWE-198': 'Use of Incorrect Byte Ordering',
        'CWE-199': 'Information Management Errors',
        'CWE-201': 'Insertion of Sensitive Information Into Sent Data',
        'CWE-202': 'Exposure of Sensitive Information Through Data Queries',
        'CWE-203': 'Observable Discrepancy',
        'CWE-204': 'Observable Response Discrepancy',
        'CWE-205': 'Observable Behavioral Discrepancy',
        'CWE-206': 'Observable Internal Behavioral Discrepancy',
        'CWE-207': 'Observable Behavioral Discrepancy With Equivalent Products',
        'CWE-208': 'Observable Timing Discrepancy',
        'CWE-210': 'Self-generated Error Message Containing Sensitive Information',
        'CWE-211': 'Externally-Generated Error Message Containing Sensitive Information',
        'CWE-212': 'Improper Removal of Sensitive Information Before Storage or Transfer',
        'CWE-213': 'Exposure of Sensitive Information Due to Incompatible Policies',
        'CWE-214': 'Invocation of Process Using Visible Passwords',
        'CWE-216': 'UART Device with Insecure Defaults',
        'CWE-217': 'JTAG Device with Insecure Defaults',
        'CWE-218': 'JTAG Device with Incorrectly Configured Security',
        'CWE-219': 'Storage of File with Sensitive Data Under Web Root',
        'CWE-220': 'Storage of File With Sensitive Data Under FTP Root',
        'CWE-221': 'Information Loss or Omission',
        'CWE-222': 'Truncation of Security-relevant Information',
        'CWE-223': 'Omission of Security-relevant Information',
        'CWE-224': 'Obscured Security-relevant Information by Alternate Name',
        'CWE-225': 'Missing Reserved Field Validation',
        'CWE-226': 'Sensitive Information in Resource Not Removed Before Reuse',
        'CWE-227': 'Failure to Disable Reserved Bits',
        'CWE-228': 'Failure to Handle Syntactically Invalid Structure',
        'CWE-229': 'Improper Handling of Values',
        'CWE-230': 'Improper Handling of Missing Values',
        'CWE-231': 'Improper Handling of Extra Values',
        'CWE-232': 'Improper Handling of Undefined Values',
        'CWE-233': 'Improper Handling of Parameters',
        'CWE-234': 'Failure to Handle Missing Parameter',
        'CWE-235': 'Improper Handling of Extra Parameters',
        'CWE-236': 'Improper Handling of Undefined Parameters',
        'CWE-237': 'Improper Handling of Structural Elements',
        'CWE-238': 'Improper Handling of Incomplete Structural Elements',
        'CWE-239': 'Failure to Handle Incomplete Element',
        'CWE-240': 'Improper Handling of Inconsistent Structural Elements',
        'CWE-241': 'Improper Handling of Unexpected Data Type',
        'CWE-242': 'Use of Inherently Dangerous Function',
        'CWE-243': 'Creation of chroot Jail Without Changing Working Directory',
        'CWE-244': 'Improper Clearing of Heap Memory Before Release',
        'CWE-245': 'J2EE Bad Practices: Direct Management of Connections',
        'CWE-246': 'J2EE Bad Practices: Direct Use of Sockets',
        'CWE-247': 'DEPRECATED: Reliance on DNS Lookups in a Security Decision',
        'CWE-248': 'Uncaught Exception',
        'CWE-249': 'DEPRECATED: Often Misused: Path Manipulation',
        'CWE-250': 'Execution with Unnecessary Privileges',
        'CWE-251': 'Often Misused: Privilege Dropping / Lowering Errors',
        'CWE-252': 'Unchecked Return Value',
        'CWE-253': 'Incorrect Check of Function Return Value',
        'CWE-254': '7PK - Security Features',
        'CWE-255': 'Credentials Management Errors',
        'CWE-256': 'Unprotected Storage of Credentials',
        'CWE-257': 'Storing Passwords in a Recoverable Format',
        'CWE-258': 'Empty Password in Configuration File',
        'CWE-259': 'Use of Hard-coded Password',
        'CWE-260': 'Password in Configuration File',
        'CWE-261': 'Weak Encoding for Password',
        'CWE-262': 'Not Using Password Aging',
        'CWE-263': 'Password Aging with Long Expiration',
        'CWE-265': 'Privilege Issues',
        'CWE-272': 'Least Privilege Violation',
        'CWE-273': 'Improper Check for Dropped Privileges',
        'CWE-274': 'Improper Handling of Insufficient Privileges',
        'CWE-275': 'Permission Issues',
        'CWE-277': 'Insecure Inherited Permissions',
        'CWE-278': 'Insecure Preserved Inherited Permissions',
        'CWE-279': 'Incorrect Execution-Assigned Permissions',
        'CWE-280': 'Improper Handling of Insufficient Permissions',
        'CWE-281': 'Improper Preservation of Permissions',
        'CWE-282': 'Improper Ownership Management',
        'CWE-283': 'Unverified Ownership',
        'CWE-284': 'Improper Access Control',
        'CWE-289': 'Authentication Bypass by Alternate Name',
        'CWE-291': 'Reliance on IP Address for Authentication',
        'CWE-292': 'DEPRECATED: Trusting Self-reported Hostname',
        'CWE-293': 'Using Referer Field for Authentication',
        'CWE-296': 'Improper Following of a Certificate\'s Chain of Trust',
        'CWE-298': 'Improper Validation of Certificate Expiration',
        'CWE-299': 'Improper Check for Certificate Revocation',
        'CWE-301': 'Reflection Attack in an Authentication Protocol',
        'CWE-303': 'Incorrect Implementation of Authentication Algorithm',
        'CWE-307': 'Improper Restriction of Excessive Authentication Attempts',
        'CWE-308': 'Use of Single-factor Authentication',
        'CWE-309': 'Use of Password System for Primary Authentication',
        'CWE-310': 'Cryptographic Issues',
        'CWE-311': 'Missing Encryption of Sensitive Data',
        'CWE-312': 'Cleartext Storage of Sensitive Information',
        'CWE-313': 'Cleartext Storage in a File or on Disk',
        'CWE-314': 'Cleartext Storage in the Registry',
        'CWE-315': 'Cleartext Storage of Sensitive Information in a Cookie',
        'CWE-316': 'Cleartext Storage of Sensitive Information in Memory',
        'CWE-317': 'Cleartext Storage of Sensitive Information in GUI',
        'CWE-318': 'Cleartext Storage of Sensitive Information in Executable',
        'CWE-319': 'Cleartext Transmission of Sensitive Information',
        'CWE-320': 'Key Management Errors',
        'CWE-321': 'Use of Hard-coded Cryptographic Key',
        'CWE-322': 'Key Exchange without Entity Authentication',
        'CWE-323': 'Reusing a Nonce, Key Pair in Encryption',
        'CWE-324': 'Use of a Key Past its Expiration Date',
        'CWE-325': 'Missing Cryptographic Step',
        'CWE-326': 'Inadequate Encryption Strength',
        'CWE-339': 'Small Space of Random Values',
        'CWE-340': 'Generation of Predictable Numbers or Identifiers',
        'CWE-341': 'Predictable from Observable State',
        'CWE-342': 'Predictable Exact Value from Previous Values',
        'CWE-343': 'Predictable Value Range from Previous Values',
        'CWE-344': 'Use of Invariant Value in Dynamically Changing Context',
        'CWE-345': 'Insufficient Verification of Data Authenticity',
        'CWE-348': 'Use of Source IP Address for Authentication',
        'CWE-349': 'Acceptance of Extraneous Untrusted Data With Trusted Data',
        'CWE-350': 'Reliance on Reverse DNS Resolution for a Security-Critical Action',
        'CWE-351': 'Insufficient Type Distinction',
        'CWE-353': 'Missing Support for Integrity Check',
        'CWE-354': 'Improper Validation of Integrity Check Value',
        'CWE-355': 'Insufficient UI Warning of Dangerous Operations',
        'CWE-356': 'Product UI does not Warn User of Unsafe Actions',
        'CWE-357': 'Insufficient UI Warning of Dangerous Operations',
        'CWE-358': 'Improperly Implemented Security Check for Standard',
        'CWE-359': 'Exposure of Private Personal Information to an Unauthorized Actor',
        'CWE-360': 'Trust of System Event Data',
        'CWE-361': '7PK - Time and State',
        'CWE-363': 'Race Condition Enabling Link Following',
        'CWE-373': 'DEPRECATED: State Synchronization Error',
        'CWE-374': 'Passing Mutable Objects to an Untrusted Method',
        'CWE-375': 'Returning a Mutable Object to an Untrusted Caller',
        'CWE-376': 'Creation of Temporary File With Insecure Permissions',
        'CWE-377': 'Insecure Temporary File',
        'CWE-378': 'Creation of Temporary File in Directory with Insecure Permissions',
        'CWE-379': 'Creation of Temporary File in Directory with Incorrect Ownership',
        'CWE-380': 'Technology-Specific Time and State Issues',
        'CWE-381': 'J2EE Bad Practices: Excessive Session Timeout',
        'CWE-382': 'J2EE Bad Practices: Use of System.exit()',
        'CWE-383': 'J2EE Bad Practices: Direct Use of Threads',
        'CWE-385': 'Covert Timing Channel',
        'CWE-386': 'Symbolic Name not Mapping to Correct Object',
        'CWE-387': 'DEPRECATED: Signal Errors',
        'CWE-388': '7PK - Errors',
        'CWE-389': 'Error Conditions, Return Values, Status Codes',
        'CWE-390': 'Detection of Error Condition Without Action',
        'CWE-391': 'Unchecked Error Condition',
        'CWE-392': 'Missing Report of Error Condition',
        'CWE-393': 'Return of Wrong Status Code',
        'CWE-394': 'Unexpected Status Code or Return Value',
        'CWE-395': 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
        'CWE-396': 'Declaration of Catch for Generic Exception',
        'CWE-397': 'Declaration of Throws for Generic Exception',
        'CWE-398': 'Indicator of Poor Code Quality',
        'CWE-399': 'Resource Management Errors',
        'CWE-400': 'Uncontrolled Resource Consumption',
        'CWE-412': 'Unrestricted Externally Accessible Lock',
        'CWE-413': 'Improper Resource Locking',
        'CWE-414': 'Missing Lock Check',
        'CWE-417': 'Communication Channel Errors',
        'CWE-418': 'Insecure Temporary File',
        'CWE-419': 'Unprotected Primary Channel',
        'CWE-420': 'Unprotected Alternate Channel',
        'CWE-421': 'Race Condition During Access to Alternate Channel',
        'CWE-422': 'Unprotected Windows Messaging Channel',
        'CWE-423': 'DEPRECATED: Proxied Trusted Channel',
        'CWE-424': 'Improper Protection of Alternate Path',
        'CWE-425': 'Direct Request',
        'CWE-426': 'Untrusted Search Path',
        'CWE-427': 'Uncontrolled Search Path Element',
        'CWE-428': 'Unquoted Search Path or Element',
        'CWE-429': 'Handler Errors',
        'CWE-430': 'Deployment of Wrong Handler',
        'CWE-431': 'Missing Handler',
        'CWE-432': 'Dangerous Signal Handler not Disabled During Sensitive Operations',
        'CWE-433': 'Unparsed Raw Web Content Delivery',
        'CWE-435': 'Improper Interaction Between Multiple Correctly-Behaving Entities',
        'CWE-436': 'Interpretation Conflict',
        'CWE-437': 'Incomplete Model of Endpoint Features',
        'CWE-438': 'Behavioral Change in New Version or Environment',
        'CWE-439': 'Behavioral Change in New Version or Environment',
        'CWE-440': 'Expected Behavior Violation',
        'CWE-441': 'Unintended Proxy or Intermediary',
        'CWE-442': 'Web Problems',
        'CWE-443': 'HTTP response splitting',
        'CWE-444': 'Inconsistent Interpretation of HTTP Requests',
        'CWE-445': 'User Interface Security Issues',
        'CWE-446': 'UI Discrepancy for Security Feature',
        'CWE-447': 'Unimplemented or Unsupported Feature in UI',
        'CWE-448': 'Obsolete Feature in UI',
        'CWE-449': 'The UI Performs the Wrong Action',
        'CWE-450': 'Multiple Interpretations of UI Input',
        'CWE-451': 'User Interface Confusion or Difficulty',
        'CWE-452': 'Initialization and Cleanup Errors',
        'CWE-453': 'Insecure Default Variable Initialization',
        'CWE-454': 'External Initialization of Trusted Variables or Values',
        'CWE-455': 'Non-exit on Failed Initialization',
        'CWE-456': 'Missing Initialization of a Variable',
        'CWE-457': 'Use of Uninitialized Variable',
        'CWE-458': 'Incorrect Parsing of Security Features',
        'CWE-459': 'Incomplete Cleanup',
        'CWE-460': 'Improper Cleanup on Thrown Exception',
        'CWE-461': 'Function Return Value Error',
        'CWE-462': 'Duplicate Key in Associative List',
        'CWE-463': 'Deletion of Data Structure Sentinel',
        'CWE-464': 'Addition of Data Structure Sentinel',
        'CWE-465': 'Pointer Issues',
        'CWE-466': 'Return of Pointer Value Outside of Expected Range',
        'CWE-467': 'Use of sizeof() on a Pointer Type',
        'CWE-468': 'Incorrect Pointer Scaling',
        'CWE-469': 'Use of Pointer Subtraction to Determine Size',
        'CWE-470': 'Use of Externally-Controlled Input to Select Classes or Code',
        'CWE-471': 'Modification of Assumed-Immutable Data',
        'CWE-472': 'External Control of Assumed-Immutable Web Parameter',
        'CWE-473': 'PHP External Variable Modification',
        'CWE-474': 'Use of Function with Inconsistent Implementations',
        'CWE-475': 'Undefined Behavior for Input to API',
        'CWE-477': 'Use of Obsolete Function',
        'CWE-478': 'Missing Default Case in Multiple Condition Expression',
        'CWE-479': 'Signal Handler Use of a Non-reentrant Function',
        'CWE-480': 'Use of Incorrect Operator',
        'CWE-481': 'Assigning instead of Comparing',
        'CWE-482': 'Comparing instead of Assigning',
        'CWE-483': 'Incorrect Block Delimitation',
        'CWE-484': 'Omitted Break Statement in Switch',
        'CWE-485': 'Insufficient Encapsulation',
        'CWE-486': 'Comparison of Classes by Name',
        'CWE-487': 'Reliance on Package-level Scope',
        'CWE-488': 'Exposure of Data Element to Wrong Session',
        'CWE-489': 'Active Debug Code',
        'CWE-490': 'Mobile Code Issues',
        'CWE-491': 'Public cloneable() Method Without Final',
        'CWE-492': 'Use of Inner Class Containing Sensitive Data',
        'CWE-493': 'Critical Public Variable Without Final Modifier',
        'CWE-494': 'Download of Code Without Integrity Check',
        'CWE-495': 'Private Data Structure Returned From A Public Method',
        'CWE-496': 'Public Data Assigned to Private Array-Typed Field',
        'CWE-497': 'Exposure of Sensitive System Information',
        'CWE-498': 'Cloneable Class Containing Sensitive Information',
        'CWE-499': 'Serializable Class Containing Sensitive Data',
        'CWE-500': 'Public Static Field Not Marked Final',
        'CWE-501': 'Trust Boundary Violation',
        'CWE-502': 'Deserialization of Untrusted Data',
        'CWE-503': 'Inadequate Encryption Strength',
        'CWE-504': 'Weak Password Recovery Mechanism for Forgotten Password',
        'CWE-505': 'Empty Password in Configuration File',
        'CWE-506': 'Embedded Malicious Code',
        'CWE-507': 'Trojan Horse',
        'CWE-508': 'Non-Replicating Malicious Code',
        'CWE-509': 'Replicating Malicious Code',
        'CWE-510': 'Trapdoor',
        'CWE-511': 'Logic/Time Bomb',
        'CWE-512': 'Spyware',
        'CWE-513': 'Exposure of Sensitive Information Through Server Log Files',
        'CWE-514': 'Covert Channel',
        'CWE-515': 'Covert Storage Channel',
        'CWE-516': 'DEPRECATED: Covert Timing Channel',
        'CWE-517': 'DEPRECATED: Covert Storage Channel in Registry',
        'CWE-518': 'DEPRECATED: Covert Timing Channel in Registry',
        'CWE-519': 'DEPRECATED: Covert Channel via File System Attributes',
        'CWE-520': '.NET Misconfiguration: Use of Impersonation',
        'CWE-521': 'Weak Password Requirements',

        # NVD Specific
        'NVD-CWE-Other': 'Outras Fraquezas',
        'NVD-CWE-noinfo': 'Informação Insuficiente',
        'CWE-noinfo': 'Informação Insuficiente sobre CWE'
    }
    return translations.get(cwe_id, cwe_id)

def format_date(date_string: str) -> str:
    """Formata data ISO para formato brasileiro"""
    if not date_string:
        return ""
    
    try:
        # Parse da data ISO
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        # Formato brasileiro
        return dt.strftime('%d/%m/%Y às %H:%M')
    except (ValueError, AttributeError):
        return date_string

def extract_cvss_score(metrics: Dict[str, Any]) -> Optional[float]:
    """Extrai score CVSS de métricas"""
    if not metrics:
        return None
    
    # Priorizar CVSS v3.1, depois v3.0, depois v2.0
    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if version in metrics and metrics[version]:
            metric = metrics[version][0]  # Pegar primeira métrica
            if 'cvssData' in metric:
                return metric['cvssData'].get('baseScore')
    
    return None

def extract_severity(metrics: Dict[str, Any]) -> str:
    """Extrai severidade de métricas CVSS"""
    if not metrics:
        return "Não informado"
    
    # Priorizar CVSS v3.1, depois v3.0, depois v2.0
    for version in ['cvssMetricV31', 'cvssMetricV30']:
        if version in metrics and metrics[version]:
            metric = metrics[version][0]
            if 'cvssData' in metric and 'baseSeverity' in metric['cvssData']:
                return translate_severity(metric['cvssData']['baseSeverity'])
    
    # Para CVSS v2, calcular severidade baseada no score
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        metric = metrics['cvssMetricV2'][0]
        if 'cvssData' in metric and 'baseScore' in metric['cvssData']:
            score = metric['cvssData']['baseScore']
            if score >= 7.0:
                return "Alta"
            elif score >= 4.0:
                return "Média"
            else:
                return "Baixa"
    
    return "Não informado"

def extract_vector_string(metrics: Dict[str, Any]) -> str:
    """Extrai vector string CVSS"""
    if not metrics:
        return ""
    
    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if version in metrics and metrics[version]:
            metric = metrics[version][0]
            if 'cvssData' in metric and 'vectorString' in metric['cvssData']:
                return metric['cvssData']['vectorString']
    
    return ""

def extract_cwe_info(weaknesses: List[Dict[str, Any]]) -> List[str]:
    """Extrai informações de CWE"""
    cwe_list = []
    
    for weakness in weaknesses:
        if 'description' in weakness:
            for desc in weakness['description']:
                if desc.get('lang') == 'en':
                    cwe_id = desc.get('value', '')
                    cwe_list.append(translate_cwe(cwe_id))
    
    return cwe_list

def extract_description(descriptions: List[Dict[str, Any]]) -> str:
    """Extrai descrição em inglês"""
    for desc in descriptions:
        if desc.get('lang') == 'en':
            return desc.get('value', '')
    return ""

def extract_references(references: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extrai referências relevantes"""
    ref_list = []
    
    for ref in references:
        ref_info = {
            'url': ref.get('url', ''),
            'source': ref.get('source', ''),
            'tags': ref.get('tags', [])
        }
        ref_list.append(ref_info)
    
    return ref_list

def paginate_results(total_results: int, page: int, per_page: int) -> Dict[str, Any]:
    """Calcula informações de paginação"""
    total_pages = (total_results + per_page - 1) // per_page if total_results > 0 else 0
    
    # Calcular página anterior e próxima
    prev_page = page - 1 if page > 1 else None
    next_page = page + 1 if page < total_pages else None
    
    # Calcular range de páginas para exibir
    start_page = max(1, page - 2)
    end_page = min(total_pages, page + 2)
    
    return {
        'current_page': page,
        'total_pages': total_pages,
        'prev_page': prev_page,
        'next_page': next_page,
        'start_page': start_page,
        'end_page': end_page,
        'total_results': total_results,
        'per_page': per_page
    }

def clean_cpe_name(cpe_name: str) -> Dict[str, str]:
    """Extrai informações de um CPE name"""
    if not cpe_name or not cpe_name.startswith('cpe:2.3:'):
        return {}
    
    parts = cpe_name.split(':')
    if len(parts) >= 6:
        return {
            'part': parts[2],
            'vendor': parts[3].replace('_', ' ').title(),
            'product': parts[4].replace('_', ' ').title(),
            'version': parts[5] if parts[5] != '*' else '',
            'update': parts[6] if len(parts) > 6 and parts[6] != '*' else '',
            'edition': parts[7] if len(parts) > 7 and parts[7] != '*' else ''
        }
    
    return {}
