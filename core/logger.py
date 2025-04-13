"""
Módulo de logging para a pipeline de Bug Bounty.
Implementa um sistema de logging avançado com suporte a cores e diferentes níveis de log.
"""

import logging
import os
import sys
from datetime import datetime
from config.settings import COLORS, DEFAULT_LOG_LEVEL

# Configuração de formatação de logs
class ColoredFormatter(logging.Formatter):
    """
    Formatter personalizado que adiciona cores aos logs no terminal.
    """
    FORMATS = {
        logging.DEBUG: COLORS["BLUE"] + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + COLORS["RESET"],
        logging.INFO: COLORS["GREEN"] + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + COLORS["RESET"],
        logging.WARNING: COLORS["YELLOW"] + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + COLORS["RESET"],
        logging.ERROR: COLORS["RED"] + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + COLORS["RESET"],
        logging.CRITICAL: COLORS["RED"] + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + COLORS["RESET"]
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logger(name, log_file=None, level=DEFAULT_LOG_LEVEL):
    """
    Configura e retorna um logger com o nome especificado.
    
    Args:
        name (str): Nome do logger
        log_file (str, optional): Caminho para o arquivo de log. Se None, logs serão apenas no console.
        level (str, optional): Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        logging.Logger: Logger configurado
    """
    # Converter string de nível para constante do logging
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = level_map.get(level.upper(), logging.INFO)
    
    # Criar logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Evitar duplicação de handlers
    if logger.handlers:
        return logger
    
    # Handler para console com cores
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # Handler para arquivo se especificado
    if log_file:
        # Garantir que o diretório do arquivo de log existe
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
    
    return logger

class Logger:
    def __init__(self, name, output_dir=None, log_file=None, level=DEFAULT_LOG_LEVEL):
        """
        Inicializa o logger.
        
        Args:
            name (str): Nome do logger
            output_dir (str, optional): Diretório de saída para os logs
            log_file (str, optional): Caminho completo para o arquivo de log
            level (str, optional): Nível de log
        """
        self.name = name
        
        # Configurar arquivo de log
        if log_file:
            # Se log_file foi especificado, usar isso
            final_log_file = log_file
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        elif output_dir:
            # Se output_dir foi especificado, criar arquivo com nome padrão
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            final_log_file = os.path.join(output_dir, f"{name}_{timestamp}.log")
        else:
            final_log_file = None
        
        # Configurar logger
        self.logger = setup_logger(name, final_log_file, level)
    
    def debug(self, message):
        """Log de nível DEBUG"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log de nível INFO"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log de nível WARNING"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log de nível ERROR"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log de nível CRITICAL"""
        self.logger.critical(message)
    
    def success(self, message):
        """Log de sucesso (nível INFO com formatação especial)"""
        self.logger.info(f"{COLORS['GREEN']}[+] {message}{COLORS['RESET']}")
    
    def step(self, message):
        """Log de passo (nível INFO com formatação especial)"""
        self.logger.info(f"{COLORS['BLUE']}[*] {message}{COLORS['RESET']}")
    
    def alert(self, message):
        """Log de alerta (nível WARNING com formatação especial)"""
        self.logger.warning(f"{COLORS['YELLOW']}[!] {message}{COLORS['RESET']}")
    
    def fail(self, message):
        """Log de falha (nível ERROR com formatação especial)"""
        self.logger.error(f"{COLORS['RED']}[!] {message}{COLORS['RESET']}")
    
    def banner(self, title):
        """Exibe um banner com o título especificado"""
        width = 60
        padding = (width - len(title) - 2) // 2
        
        self.logger.info(f"{COLORS['BLUE']}{'═' * width}{COLORS['RESET']}")
        self.logger.info(f"{COLORS['BLUE']}║{' ' * padding} {title} {' ' * (padding + (1 if len(title) % 2 == 1 else 0))}║{COLORS['RESET']}")
        self.logger.info(f"{COLORS['BLUE']}{'═' * width}{COLORS['RESET']}")
