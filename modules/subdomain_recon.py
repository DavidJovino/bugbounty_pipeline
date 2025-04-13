"""
Módulo de reconhecimento de subdomínios para a pipeline de Bug Bounty.
Responsável por descobrir subdomínios de um domínio alvo usando múltiplas ferramentas.
"""

import os
import sys
import time
import json
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from config.settings import DEFAULT_THREADS, DEFAULT_TIMEOUT

class SubdomainRecon:
    """
    Classe para reconhecimento de subdomínios.
    """
    def __init__(self, logger=None, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT):
        """
        Inicializa o módulo de reconhecimento de subdomínios.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
            threads (int, optional): Número de threads para execução paralela
            timeout (int, optional): Timeout para comandos externos
        """
        self.logger = logger or Logger("subdomain_recon")
        self.executor = CommandExecutor(logger)
        self.checker = ToolChecker(logger)
        self.threads = threads
        self.timeout = timeout
        
        # Verificar ferramentas disponíveis
        self.tools_status = self.checker.check_tools_for_module("recon")
        self.available_tools = self.tools_status["available"]
        self.missing_tools = self.tools_status["missing"]
        self.alternative_tools = self.tools_status["alternatives"]
        
        # Registrar status das ferramentas
        if self.missing_tools:
            self.logger.warning(f"Ferramentas faltantes: {', '.join(self.missing_tools)}")
            if self.alternative_tools:
                self.logger.info(f"Alternativas disponíveis: {self.alternative_tools}")
        else:
            self.logger.success("Todas as ferramentas necessárias estão disponíveis")
    
    def run(self, domain, output_dir):
        """
        Executa o reconhecimento de subdomínios para um domínio.
        
        Args:
            domain (str): Domínio alvo
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados do reconhecimento
        """
        self.logger.banner("Reconhecimento de Subdomínios")
        self.logger.info(f"Domínio alvo: {domain}")
        self.logger.info(f"Diretório de saída: {output_dir}")
        
        # Validar domínio
        if not self._validate_domain(domain):
            self.logger.error(f"Domínio inválido: {domain}")
            return {"success": False, "subdomains": [], "error": "Domínio inválido"}
        
        # Criar estrutura de diretórios
        domain_dir = os.path.join(output_dir, domain)
        subdomain_dir = os.path.join(domain_dir, "subdomain_enum")
        os.makedirs(subdomain_dir, exist_ok=True)
        
        # Arquivos de saída
        raw_subdomains_file = os.path.join(domain_dir, "raw_subdomains.txt")
        final_subdomains_file = os.path.join(domain_dir, "final_subdomains.txt")
        
        # Executar ferramentas de enumeração em paralelo
        self.logger.step("Executando ferramentas de enumeração de subdomínios")
        results = self._run_enumeration_tools(domain, subdomain_dir)
        
        # Consolidar resultados
        self.logger.step("Consolidando resultados")
        subdomains = self._consolidate_results(results, raw_subdomains_file)
        
        # Verificar subdomínios ativos
        self.logger.step("Verificando subdomínios ativos")
        active_subdomains = self._check_active_subdomains(subdomains, final_subdomains_file)
        
        # Resumo
        self.logger.success(f"Reconhecimento concluído para {domain}")
        self.logger.info(f"Total de subdomínios encontrados: {len(subdomains)}")
        self.logger.info(f"Subdomínios ativos: {len(active_subdomains)}")
        self.logger.info(f"Resultados salvos em: {domain_dir}")
        
        return {
            "success": True,
            "domain": domain,
            "subdomains": subdomains,
            "active_subdomains": active_subdomains,
            "raw_file": raw_subdomains_file,
            "final_file": final_subdomains_file
        }
    
    def _validate_domain(self, domain):
        """
        Valida um domínio.
        
        Args:
            domain (str): Domínio a ser validado
            
        Returns:
            bool: True se o domínio é válido, False caso contrário
        """
        import re
        domain_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(domain_regex, domain))
    
    def _run_enumeration_tools(self, domain, output_dir):
        """
        Executa ferramentas de enumeração de subdomínios em paralelo.
        
        Args:
            domain (str): Domínio alvo
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados da execução de cada ferramenta
        """
        results = {}
        
        # Definir comandos para cada ferramenta
        commands = {}
        
        # Amass
        if "amass" in self.available_tools:
            amass_output = os.path.join(output_dir, "amass.txt")
            commands["amass"] = f"amass enum -passive -d {domain} -o {amass_output}"
        
        # Subfinder
        if "subfinder" in self.available_tools:
            subfinder_output = os.path.join(output_dir, "subfinder.txt")
            commands["subfinder"] = f"subfinder -d {domain} -all -o {subfinder_output}"
        
        # Assetfinder
        if "assetfinder" in self.available_tools:
            assetfinder_output = os.path.join(output_dir, "assetfinder.txt")
            commands["assetfinder"] = f"assetfinder --subs-only {domain} > {assetfinder_output}"
        
        # Verificar se há comandos para executar
        if not commands:
            self.logger.warning("Nenhuma ferramenta de enumeração disponível")
            return results
        
        # Executar comandos em paralelo
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for tool, command in commands.items():
                self.logger.info(f"Iniciando {tool}...")
                futures[executor.submit(self._run_tool, tool, command)] = tool
            
            for future in as_completed(futures):
                tool = futures[future]
                try:
                    result = future.result()
                    results[tool] = result
                    if result["success"]:
                        self.logger.success(f"{tool} concluído com sucesso")
                    else:
                        self.logger.warning(f"{tool} falhou: {result.get('error', 'Erro desconhecido')}")
                except Exception as e:
                    self.logger.error(f"Erro ao executar {tool}: {str(e)}")
        
        return results
    
    def _run_tool(self, tool, command):
        """
        Executa uma ferramenta de enumeração.
        
        Args:
            tool (str): Nome da ferramenta
            command (str): Comando a ser executado
            
        Returns:
            dict: Resultado da execução
        """
        try:
            start_time = time.time()
            result = self.executor.execute(command, timeout=self.timeout, shell=True)
            end_time = time.time()
            
            return {
                "tool": tool,
                "command": command,
                "success": result["success"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "returncode": result["returncode"],
                "duration": end_time - start_time
            }
        except Exception as e:
            return {
                "tool": tool,
                "command": command,
                "success": False,
                "error": str(e),
                "duration": 0
            }
    
    def _consolidate_results(self, results, output_file):
        """
        Consolida os resultados das ferramentas de enumeração.
        
        Args:
            results (dict): Resultados da execução de cada ferramenta
            output_file (str): Arquivo de saída para os subdomínios consolidados
            
        Returns:
            list: Lista de subdomínios únicos
        """
        subdomains = set()
        
        # Coletar subdomínios de cada ferramenta
        for tool, result in results.items():
            if not result["success"]:
                continue
            
            # Determinar arquivo de saída da ferramenta
            if tool == "amass":
                tool_output = os.path.dirname(output_file) + "/subdomain_enum/amass.txt"
            elif tool == "subfinder":
                tool_output = os.path.dirname(output_file) + "/subdomain_enum/subfinder.txt"
            elif tool == "assetfinder":
                tool_output = os.path.dirname(output_file) + "/subdomain_enum/assetfinder.txt"
            else:
                continue
            
            # Ler subdomínios do arquivo
            if os.path.exists(tool_output):
                with open(tool_output, "r") as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            subdomains.add(subdomain)
        
        # Salvar subdomínios consolidados
        subdomains_list = sorted(list(subdomains))
        with open(output_file, "w") as f:
            for subdomain in subdomains_list:
                f.write(f"{subdomain}\n")
        
        self.logger.info(f"Total de subdomínios encontrados: {len(subdomains_list)}")
        self.logger.info(f"Subdomínios consolidados salvos em: {output_file}")
        
        return subdomains_list
    
    def _check_active_subdomains(self, subdomains, output_file):
        """
        Verifica quais subdomínios estão ativos.
        
        Args:
            subdomains (list): Lista de subdomínios
            output_file (str): Arquivo de saída para os subdomínios ativos
            
        Returns:
            list: Lista de subdomínios ativos
        """
        active_subdomains = []
        
        # Verificar se httpx está disponível
        if "httpx" not in self.available_tools:
            self.logger.warning("httpx não encontrado, não é possível verificar subdomínios ativos")
            # Copiar todos os subdomínios para o arquivo final
            with open(output_file, "w") as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            return subdomains
        
        # Criar arquivo temporário com subdomínios
        temp_file = os.path.dirname(output_file) + "/temp_subdomains.txt"
        with open(temp_file, "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        # Executar httpx
        self.logger.info("Verificando subdomínios ativos com httpx...")
        command = f"cat {temp_file} | httpx -silent -threads {self.threads} -o {output_file}"
        result = self.executor.execute(command, timeout=self.timeout, shell=True)
        
        # Verificar resultado
        if result["success"]:
            # Ler subdomínios ativos
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    active_subdomains = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Subdomínios ativos: {len(active_subdomains)}")
            self.logger.info(f"Subdomínios ativos salvos em: {output_file}")
        else:
            self.logger.warning("Falha ao verificar subdomínios ativos")
            self.logger.debug(f"Erro: {result['stderr']}")
            
            # Copiar todos os subdomínios para o arquivo final
            with open(output_file, "w") as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            active_subdomains = subdomains
        
        # Remover arquivo temporário
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        return active_subdomains
