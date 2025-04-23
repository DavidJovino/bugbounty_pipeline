"""
Definições de ferramentas para a pipeline de Bug Bounty.
Contém informações sobre todas as ferramentas utilizadas, incluindo:
- Comando para execução
- Método de instalação
- Dependências
- Módulos que utilizam a ferramenta
- Alternativas disponíveis
"""

# Definição de todas as ferramentas utilizadas na pipeline
TOOLS = {
    # Ferramentas de reconhecimento de subdomínios
    "amass": {
        "command": "amass",
        "package": "github.com/owasp-amass/amass/v3/...",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["subfinder", "assetfinder"],
        "description": "Ferramenta de reconhecimento de subdomínios"
    },
    "subfinder": {
        "command": "subfinder",
        "package": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["amass", "assetfinder"],
        "description": "Ferramenta de descoberta passiva de subdomínios"
    },
    "assetfinder": {
        "command": "assetfinder",
        "package": "github.com/tomnomnom/assetfinder",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["amass", "subfinder"],
        "description": "Ferramenta para encontrar domínios e subdomínios relacionados"
    },
    "anew": {
        "command": "anew",
        "package": "github.com/tomnomnom/anew",
        "install_method": "go",
        "required_for": ["recon", "enum"],
        "alternatives": [],
        "description": "Ferramenta para adicionar linhas de um arquivo a outro, apenas se forem novas"
    },
    
    # Ferramentas de enumeração de endpoints
    "httpx": {
        "command": "httpx",
        "package": "github.com/projectdiscovery/httpx/cmd/httpx",
        "install_method": "go",
        "required_for": ["enum", "specific"],
        "alternatives": [],
        "description": "Ferramenta para probing de HTTP"
    },
    "katana": {
        "command": "katana",
        "package": "github.com/projectdiscovery/katana/cmd/katana",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["hakrawler"],
        "description": "Ferramenta de crawling de websites"
    },
    "hakrawler": {
        "command": "hakrawler",
        "package": "github.com/hakluke/hakrawler",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["katana"],
        "description": "Ferramenta de crawling simples e rápida"
    },
    "waybackurls": {
        "command": "waybackurls",
        "package": "github.com/tomnomnom/waybackurls",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["gau"],
        "description": "Ferramenta para extrair URLs do Wayback Machine"
    },
    "gau": {
        "command": "gau",
        "package": "github.com/lc/gau/v2/cmd/gau",
        "install_method": "go",
        "required_for": ["enum"],
        "alternatives": ["waybackurls"],
        "description": "Ferramenta para obter URLs conhecidos do AlienVault's OTX, Wayback Machine e Common Crawl"
    },
    "ffuf": {
        "command": "ffuf",
        "package": "github.com/ffuf/ffuf",
        "install_method": "go",
        "required_for": ["enum", "specific"],
        "alternatives": ["feroxbuster"],
        "description": "Ferramenta de fuzzing web rápida"
    },
    "feroxbuster": {
        "command": "feroxbuster",
        "package": "",
        "install_method": "curl",
        "install_command": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash",
        "required_for": ["enum"],
        "alternatives": ["ffuf"],
        "description": "Ferramenta de fuzzing recursiva de diretórios"
    },
    
    # Ferramentas de escaneamento de vulnerabilidades
    "nuclei": {
        "command": "nuclei",
        "package": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei",
        "install_method": "go",
        "required_for": ["scan"],
        "alternatives": [],
        "description": "Ferramenta de escaneamento baseada em templates"
    },
    "naabu": {
        "command": "naabu",
        "package": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "install_method": "go",
        "required_for": ["scan"],
        "alternatives": ["nmap"],
        "description": "Ferramenta de escaneamento de portas"
    },
    "sqlmap": {
        "command": "sqlmap",
        "package": "sqlmap",
        "install_method": "pip",
        "required_for": ["scan"],
        "alternatives": [],
        "description": "Ferramenta de detecção e exploração de SQL Injection"
    },
    "nikto": {
        "command": "nikto",
        "package": "",
        "install_method": "apt",
        "required_for": ["scan"],
        "alternatives": [],
        "description": "Ferramenta de escaneamento de vulnerabilidades em servidores web"
    },
    "dalfox": {
        "command": "dalfox",
        "package": "github.com/hahwul/dalfox/v2",
        "install_method": "go",
        "required_for": ["scan"],
        "alternatives": ["xsstrike"],
        "description": "Ferramenta de detecção de XSS"
    },
    "xsstrike": {
        "command": "xsstrike",
        "package": "xsstrike",
        "install_method": "pip",
        "required_for": ["scan"],
        "alternatives": ["dalfox"],
        "description": "Ferramenta avançada de detecção e exploração de XSS"
    },
    
    # Ferramentas para testes específicos
    "curl": {
        "command": "curl",
        "package": "",
        "install_method": "apt",
        "required_for": ["specific"],
        "alternatives": [],
        "description": "Ferramenta para transferência de dados com URL"
    },
    "jq": {
        "command": "jq",
        "package": "",
        "install_method": "apt",
        "required_for": ["specific"],
        "alternatives": [],
        "description": "Processador de JSON em linha de comando"
    },
    "unfurl": {
        "command": "unfurl",
        "package": "github.com/tomnomnom/unfurl",
        "install_method": "go",
        "required_for": ["specific"],
        "alternatives": [],
        "description": "Ferramenta para extrair e analisar partes de URLs"
    },
    # Ferramentas problemáticas (tratamento especial)
    "xxeinjector": {
        "command": "xxeinjector",
        "package": "",
        "install_method": "git",
        "install_command": "git clone https://github.com/enjoiz/XXEinjector.git",
        "binary_path": "~/tools/XXEinjector/XXEinjector.rb",
        "run_command": "ruby ~/tools/XXEinjector/XXEinjector.rb",
        "required_for": ["specific"],
        "alternatives": ["python_xxe_scanner"],
        "description": "Ferramenta para teste de XXE (XML External Entity)",
        "dependencies": ["ruby", "nokogiri"],
        "available_via_pip": False,
        "special_handling": True
    },
    "xsrfprobe": {
        "command": "xsrfprobe",
        "package": "xsrfprobe",
        "install_method": "pip",
        "required_for": ["specific"],
        "alternatives": ["python_csrf_scanner"],
        "description": "Ferramenta moderna para teste de CSRF (Cross-Site Request Forgery)",
        "available_via_pip": True,
        "special_handling": False
    }
}

# Ferramentas essenciais que devem estar presentes para o funcionamento básico
ESSENTIAL_TOOLS = ["curl", "wget", "git", "python3", "pip3"]

# Dependências do sistema que podem ser necessárias
SYSTEM_DEPENDENCIES = {
    "apt": [
        "git", "python3", "python3-pip", "golang", "ruby", "ruby-dev", 
        "nmap", "masscan", "whois", "nikto", "dirb", "sqlmap", "hydra", 
        "wfuzz", "curl", "wget", "zip", "unzip", "jq", "build-essential", 
        "libssl-dev", "libffi-dev", "python3-dev", "chromium-browser"
    ]
}

# Dependências Python que serão instaladas automaticamente
PYTHON_DEPENDENCIES = [
    "requests", "beautifulsoup4", "colorama", "tqdm", "argparse", 
    "pyyaml", "jinja2", "markdown", "python-dateutil"
]

# Mapeamento de módulos para ferramentas necessárias
MODULE_TOOLS = {
    "recon": ["amass", "subfinder", "assetfinder", "anew", "httpx"],
    "enum": ["httpx", "katana", "hakrawler", "waybackurls", "gau", "ffuf", "feroxbuster"],
    "scan": ["nuclei", "naabu", "sqlmap", "nikto", "dalfox", "xsstrike"],
    "specific": ["curl", "jq", "httpx", "ffuf", "unfurl", "xxeinjector", "xsrfprobe"]
}

# Função para obter ferramentas necessárias para um módulo
def get_tools_for_module(module_name):
    """
    Retorna a lista de ferramentas necessárias para um módulo específico.
    
    Args:
        module_name (str): Nome do módulo
        
    Returns:
        list: Lista de ferramentas necessárias
    """
    if module_name in MODULE_TOOLS:
        return MODULE_TOOLS[module_name]
    elif module_name == "all":
        # Combinar todas as ferramentas de todos os módulos
        all_tools = []
        for tools in MODULE_TOOLS.values():
            all_tools.extend(tools)
        return list(set(all_tools))  # Remover duplicatas
    else:
        return []

# Função para obter alternativas para uma ferramenta
def get_alternatives(tool_name):
    """
    Retorna as alternativas disponíveis para uma ferramenta.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        list: Lista de ferramentas alternativas
    """
    if tool_name in TOOLS and "alternatives" in TOOLS[tool_name]:
        return TOOLS[tool_name]["alternatives"]
    return []

# Função para verificar se uma ferramenta requer tratamento especial
def requires_special_handling(tool_name):
    """
    Verifica se uma ferramenta requer tratamento especial.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        bool: True se a ferramenta requer tratamento especial, False caso contrário
    """
    if tool_name in TOOLS and "special_handling" in TOOLS[tool_name]:
        return TOOLS[tool_name]["special_handling"]
    return False
