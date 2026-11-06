import re
from typing import Dict, Any, List
import pandas as pd


class AttackPrimitive:
    RECON_INFO_LEAK = "RECON_INFO_LEAK"
    AUTH_BYPASS = "AUTH_BYPASS"
    INJECTION_RCE = "INJECTION_RCE"
    PRIV_ESC = "PRIV_ESC"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    GENERIC_VULN = "GENERIC_VULN"


# Mapeamento da fase na Cyber Kill Chain (1 a 5)
KILL_CHAIN_STAGES = {
    AttackPrimitive.RECON_INFO_LEAK: 1,      # Fase 1: Reconhecimento & Vazamento de Informações
    AttackPrimitive.AUTH_BYPASS: 2,          # Fase 2: Quebra de Perímetro & Contorno de Autenticação
    AttackPrimitive.INJECTION_RCE: 3,        # Fase 3: Execução de Código & Injeção de Comandos
    AttackPrimitive.PRIV_ESC: 4,             # Fase 4: Escalação Local de Privilégios (Root/Admin)
    AttackPrimitive.DENIAL_OF_SERVICE: 5,    # Fase 5: Negação de Serviço (DoS/Crash)
    AttackPrimitive.GENERIC_VULN: 0
}

# Padrões Regex compilados para classificação determinística de primitivas
PRIMITIVE_PATTERNS = {
    AttackPrimitive.PRIV_ESC: [
        r"\b(privilege escalation|escalate privileges|gain (elevated|root|admin|administrator) privileges)\b",
        r"\b(local privilege escalation|lpe|arbitrary file write to root)\b",
        r"\b(elevation of privilege|gain unauthorized privileges)\b"
    ],
    AttackPrimitive.INJECTION_RCE: [
        r"\b(remote code execution|execute arbitrary (code|commands?))\b",
        r"\b(command injection|sql injection|sqli|code injection|rce)\b",
        r"\b(arbitrary file upload|untrusted deserialization|insecure deserialization)\b",
        r"\b(buffer overflow|heap[- ]based buffer overflow|stack[- ]based buffer overflow)\b",
        r"\b(out[- ]of[- ]bounds write|use[- ]after[- ]free|memory corruption)\b",
        r"\b(cross[- ]site scripting|stored xss|dom xss)\b"
    ],
    AttackPrimitive.AUTH_BYPASS: [
        r"\b(bypass authentication|authentication bypass|improper authentication)\b",
        r"\b(missing authentication|unauthenticated access|broken access control)\b",
        r"\b(improper authorization|privilege bypass|token bypass|session fixation)\b",
        r"\b(access control bypass|bypass (login|security restrictions))\b",
        r"\b(unauthenticated remote attackers? to (bypass|access))\b"
    ],
    AttackPrimitive.RECON_INFO_LEAK: [
        r"\b(information disclosure|information leak|sensitive data exposure)\b",
        r"\b(read arbitrary files|arbitrary file read|directory traversal|path traversal)\b",
        r"\b(unauthorized access to sensitive (information|data))\b",
        r"\b(cleartext transmission|memory disclosure|ssrf|server[- ]side request forgery)\b"
    ],
    AttackPrimitive.DENIAL_OF_SERVICE: [
        r"\b(denial of service|dos|crash|resource exhaustion)\b",
        r"\b(infinite loop|segmentation fault|null pointer dereference)\b",
        r"\b(cause a denial of service|trigger a crash)\b"
    ]
}

# Padrões de tecnologias e ecossistemas conhecidos
TECH_PATTERNS = {
    "Microsoft / Windows": [r"\b(windows|microsoft|exchange|active directory|iis|azure|sharepoint)\b"],
    "Linux / Kernel": [r"\b(linux|kernel|ubuntu|debian|red hat|rhel|centos|alpine)\b"],
    "Apache Foundation": [r"\b(apache|tomcat|struts|kafka|hadoop|activemq)\b"],
    "Cisco Systems": [r"\b(cisco|ios[- ]xe|asa|anyconnect|catalyst)\b"],
    "Apple": [r"\b(apple|macos|ios|ipados|safari|webkit)\b"],
    "Google / Android": [r"\b(google|android|chrome|chromium)\b"],
    "Oracle": [r"\b(oracle|weblogic|java|mysql|peoplesoft)\b"],
    "WordPress": [r"\b(wordpress|wp[- ]plugin|wp[- ]theme)\b"],
    "GitLab / DevOps": [r"\b(gitlab|github|jenkins|docker|kubernetes|containerd)\b"],
    "VMware": [r"\b(vmware|esxi|vcenter|vsphere)\b"],
    "PHP Ecosystem": [r"\b(php|laravel|symfony)\b"],
    "OpenSSL / Crypto": [r"\b(openssl|gnutls|libssl)\b"],
    "Fortinet / SonicWall": [r"\b(fortinet|fortios|fortigate|sonicwall)\b"]
}

# Mapeamento determinístico de CWEs para Primitivas de Ataque da Cyber Kill Chain
CWE_PRIMITIVE_MAP = {
    # RCE / Injeção / Corrupção de Memória
    "CWE-89": AttackPrimitive.INJECTION_RCE,
    "CWE-78": AttackPrimitive.INJECTION_RCE,
    "CWE-94": AttackPrimitive.INJECTION_RCE,
    "CWE-77": AttackPrimitive.INJECTION_RCE,
    "CWE-502": AttackPrimitive.INJECTION_RCE,
    "CWE-119": AttackPrimitive.INJECTION_RCE,
    "CWE-120": AttackPrimitive.INJECTION_RCE,
    "CWE-121": AttackPrimitive.INJECTION_RCE,
    "CWE-122": AttackPrimitive.INJECTION_RCE,
    "CWE-416": AttackPrimitive.INJECTION_RCE,
    "CWE-787": AttackPrimitive.INJECTION_RCE,
    "CWE-79": AttackPrimitive.INJECTION_RCE,
    "CWE-434": AttackPrimitive.INJECTION_RCE,

    # Bypass de Autenticação & Quebra de Controle de Acesso
    "CWE-287": AttackPrimitive.AUTH_BYPASS,
    "CWE-306": AttackPrimitive.AUTH_BYPASS,
    "CWE-862": AttackPrimitive.AUTH_BYPASS,
    "CWE-863": AttackPrimitive.AUTH_BYPASS,
    "CWE-284": AttackPrimitive.AUTH_BYPASS,
    "CWE-384": AttackPrimitive.AUTH_BYPASS,
    "CWE-640": AttackPrimitive.AUTH_BYPASS,

    # Escalação de Privilégios (PrivEsc / LPE)
    "CWE-269": AttackPrimitive.PRIV_ESC,
    "CWE-250": AttackPrimitive.PRIV_ESC,
    "CWE-732": AttackPrimitive.PRIV_ESC,
    "CWE-276": AttackPrimitive.PRIV_ESC,

    # Reconhecimento & Vazamento de Informações
    "CWE-200": AttackPrimitive.RECON_INFO_LEAK,
    "CWE-22": AttackPrimitive.RECON_INFO_LEAK,
    "CWE-918": AttackPrimitive.RECON_INFO_LEAK,
    "CWE-125": AttackPrimitive.RECON_INFO_LEAK,
    "CWE-532": AttackPrimitive.RECON_INFO_LEAK,
    "CWE-319": AttackPrimitive.RECON_INFO_LEAK,

    # Negação de Serviço (DoS / Crash)
    "CWE-400": AttackPrimitive.DENIAL_OF_SERVICE,
    "CWE-476": AttackPrimitive.DENIAL_OF_SERVICE,
    "CWE-835": AttackPrimitive.DENIAL_OF_SERVICE
}

CPE_VENDOR_MAP = {
    "microsoft": "Microsoft / Windows",
    "linux": "Linux / Kernel",
    "canonical": "Linux / Kernel",
    "redhat": "Linux / Kernel",
    "debian": "Linux / Kernel",
    "apache": "Apache Foundation",
    "cisco": "Cisco Systems",
    "apple": "Apple",
    "google": "Google / Android",
    "oracle": "Oracle",
    "wordpress": "WordPress",
    "gitlab": "GitLab / DevOps",
    "github": "GitLab / DevOps",
    "docker": "GitLab / DevOps",
    "jenkins": "GitLab / DevOps",
    "vmware": "VMware",
    "php": "PHP Ecosystem",
    "openssl": "OpenSSL / Crypto",
    "fortinet": "Fortinet / SonicWall",
    "sonicwall": "Fortinet / SonicWall"
}


def extrair_primitiva(descricao: str, cwe: str = None) -> Dict[str, Any]:
    """
    Analisa CWE estruturado e descrição técnica da vulnerabilidade,
    inferindo a primitiva de ataque e seu estágio na Cyber Kill Chain.
    """
    # 1. Prioridade para CWE estruturado do NIST (precisão determinística)
    if cwe and cwe in CWE_PRIMITIVE_MAP:
        prim = CWE_PRIMITIVE_MAP[cwe]
        return {
            "primitiva": prim,
            "estagio": KILL_CHAIN_STAGES[prim],
            "termo_encontrado": cwe
        }

    if not descricao or not isinstance(descricao, str):
        return {
            "primitiva": AttackPrimitive.GENERIC_VULN,
            "estagio": 0,
            "termo_encontrado": None
        }

    texto_lower = descricao.lower()

    # 2. Heurística Regex por ordem de impacto tático
    ordem_checagem = [
        AttackPrimitive.PRIV_ESC,
        AttackPrimitive.INJECTION_RCE,
        AttackPrimitive.AUTH_BYPASS,
        AttackPrimitive.RECON_INFO_LEAK,
        AttackPrimitive.DENIAL_OF_SERVICE
    ]

    for primitiva in ordem_checagem:
        patterns = PRIMITIVE_PATTERNS[primitiva]
        for pattern in patterns:
            match = re.search(pattern, texto_lower)
            if match:
                return {
                    "primitiva": primitiva,
                    "estagio": KILL_CHAIN_STAGES[primitiva],
                    "termo_encontrado": match.group(0)
                }

    return {
        "primitiva": AttackPrimitive.GENERIC_VULN,
        "estagio": 0,
        "termo_encontrado": None
    }


def extrair_tecnologia(descricao: str, cpe_vendor: str = None, cpe_product: str = None) -> str:
    """
    Identifica o ecossistema ou fabricante afetado a partir do CPE estruturado
    ou heurística de descrição técnica.
    """
    # 1. Resolução via CPE estruturado (Configurations do NIST)
    if cpe_vendor:
        vendor_clean = str(cpe_vendor).lower().strip()
        if vendor_clean in CPE_VENDOR_MAP:
            return CPE_VENDOR_MAP[vendor_clean]

    if not descricao or not isinstance(descricao, str):
        return "Desconhecido / Geral"

    texto_lower = descricao.lower()

    # 2. Regex nos padrões de ecossistemas conhecidos
    for tech_nome, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, texto_lower):
                return tech_nome

    # Fallback: Tenta identificar "in <Component> before <Version>"
    match_component = re.search(r"\bin\s+([A-Za-z0-9_\-\.]+)\s+(?:before|through|version|prior)", descricao, re.IGNORECASE)
    if match_component:
        candidato = match_component.group(1).strip()
        if len(candidato) > 2 and not candidato.lower() in ["the", "all", "any", "some"]:
            return candidato

    return "Desconhecido / Geral"


def enriquecer_vulnerabilidades(vulnerabilidades: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Recebe a lista de vulnerabilidades, enriquece com Primitivas de Ataque
    e Tecnologia afetada (utilizando dados estruturados CWE e CPE),
    retornando um DataFrame do Pandas pronto para análise.
    """
    if not vulnerabilidades:
        return pd.DataFrame()

    df = pd.DataFrame(vulnerabilidades)

    primitivas = []
    estagios = []
    tecnologias = []

    for _, row in df.iterrows():
        desc = row.get("descricao", "")
        cwe = row.get("cwe")
        cpe_vendor = row.get("cpe_vendor")
        cpe_product = row.get("cpe_product")

        info_primitiva = extrair_primitiva(desc, cwe=cwe)
        tech = extrair_tecnologia(desc, cpe_vendor=cpe_vendor, cpe_product=cpe_product)

        primitivas.append(info_primitiva["primitiva"])
        estagios.append(info_primitiva["estagio"])
        tecnologias.append(tech)

    df["primitiva"] = primitivas
    df["estagio_kill_chain"] = estagios
    df["tecnologia"] = tecnologias

    return df
