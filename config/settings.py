"""
Configurações globais para a pipeline de Bug Bounty.
"""
import os
TOOLS_DIR = os.getenv("TOOLS_DIR", os.path.expanduser("~/tools"))

# Configurações gerais
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 2800  # segundos
DEFAULT_OUTPUT_DIR = "bug_bounty_results"
DEFAULT_LOG_LEVEL = "INFO"

# Cores para output no terminal
COLORS = {
    "RED": "\033[1;31m",
    "GREEN": "\033[1;32m",
    "BLUE": "\033[1;36m",
    "YELLOW": "\033[1;33m",
    "ORANGE": "\033[38;5;208m",
    "PURPLE": "\033[0;35m",
    "RESET": "\033[0m"
}

# Configurações de módulos
MODULES = {
    "recon": {
        "name": "Reconhecimento de Subdomínios",
        "description": "Descobre subdomínios usando múltiplas ferramentas",
        "enabled": True
    },
    "enum": {
        "name": "Enumeração de Endpoints",
        "description": "Identifica URLs, diretórios e endpoints",
        "enabled": True
    },
    "scan": {
        "name": "Escaneamento de Vulnerabilidades",
        "description": "Detecta vulnerabilidades usando várias ferramentas",
        "enabled": True
    },
    "specific": {
        "name": "Testes Específicos",
        "description": "Realiza testes direcionados para vulnerabilidades específicas",
        "enabled": True
    }
}

# Configurações de diretórios
DIRECTORIES = {
    "tools": TOOLS_DIR,
    "wordlists": os.getenv("WORDLISTS_DIR", "/app/wordlists"),
    "temp": "/tmp/bug_bounty"
}

# Configurações de relatórios
REPORT_FORMATS = ["md", "html", "json"]
DEFAULT_REPORT_FORMAT = "md"

# Configurações de notificações
NOTIFICATION_CHANNELS = ["discord", "slack", "telegram", "email"]
