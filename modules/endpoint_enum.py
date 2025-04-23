"""
Módulo de enumeração de endpoints para a pipeline de Bug Bounty.
Responsável por descobrir URLs, diretórios e endpoints em hosts alvo.
"""

import os
import sys
import time
import json
import random
import tempfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from config.tools import get_tools_for_module

class EndpointEnum:
    """
    Classe para enumeração de endpoints em hosts alvo.
    """
    def __init__(self, logger=None, threads=10, timeout=300):
        """
        Inicializa o enumerador de endpoints.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
            threads (int, optional): Número de threads para execução paralela
            timeout (int, optional): Timeout para comandos externos em segundos
        """

        self.logger = logger or Logger("endpoint_enum")
        self.executor = CommandExecutor(self.logger)
        self.tool_checker = ToolChecker(self.logger)
        self.threads = threads
        self.timeout = timeout
        
        # Verificar ferramentas necessárias
        self.tools_status = self.tool_checker.check_tools_for_module("enum")
        
        # Resultados
        self.endpoints = []
        self.active_endpoints = []
        self.directories = []
        self.parameters = []
    
    def run(self, hosts_file, output_dir, domain):
        """
        Executa a enumeração de endpoints.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados da enumeração
        """
        self.logger.info(f"Iniciando enumeração de endpoints a partir de {hosts_file}")
        
        # Verificar arquivo de hosts - tentar encontrar alternativas se não existir
        if not os.path.exists(hosts_file):
            self.logger.warning(f"Arquivo de hosts não encontrado: {hosts_file}")
            
            # Tentar encontrar arquivo de subdomínios em locais alternativos
            possible_locations = [
                hosts_file,
                os.path.join(os.path.dirname(hosts_file), "subdomains.txt"),
                os.path.join(os.path.dirname(os.path.dirname(hosts_file)), "recon", "subdomains.txt"),
                os.path.join(os.path.dirname(os.path.dirname(hosts_file)), f"{self.args.domain}_subdomains.txt")
            ]
            
            for location in possible_locations:
                if os.path.exists(location):
                    hosts_file = location
                    self.logger.info(f"Usando arquivo de hosts alternativo: {hosts_file}")
                    break
            else:
                self.logger.error("Nenhum arquivo de hosts válido encontrado")
                return {"success": False, "error": "Arquivo de hosts não encontrado"}
        
        # Criar diretório de saída
        domain = Path(hosts_file).stem  # ou outra forma de extrair o domínio atual
        enum_dir = os.path.join(output_dir, "enum", domain)
        os.makedirs(enum_dir, exist_ok=True)
        
        # Arquivos de saída
        endpoints_file = os.path.join(enum_dir, "endpoints.txt")
        active_endpoints_file = os.path.join(enum_dir, "active_endpoints.txt")
        directories_file = os.path.join(enum_dir, "directories.txt")
        parameters_file = os.path.join(enum_dir, "parameters.txt")
        
        try:
            # 1. Verificar hosts ativos com httpx
            active_hosts_file = self._check_active_hosts(hosts_file, enum_dir)
            if not active_hosts_file:
                self.logger.error("Falha ao verificar hosts ativos")
                return {"success": False, "error": "Falha ao verificar hosts ativos"}
            
            # 2. Executar crawling com katana ou hakrawler
            self._run_crawler(active_hosts_file, endpoints_file)
            
            # 3. Obter URLs históricas com waybackurls ou gau
            self._run_historical_urls(hosts_file, endpoints_file)
            
            # 4. Executar fuzzing de diretórios com ffuf ou feroxbuster
            self._run_directory_fuzzing(active_hosts_file, directories_file)
            
            # 5. Consolidar resultados
            results = self._consolidate_results(
                endpoints_file,
                active_endpoints_file,
                directories_file,
                parameters_file,
                enum_dir
            )
            
            # Adicionar caminhos de arquivos aos resultados
            results["endpoints_file"] = endpoints_file
            results["active_endpoints_file"] = active_endpoints_file
            results["directories_file"] = directories_file
            results["parameters_file"] = parameters_file
            
            return results
        except Exception as e:
            self.logger.error(f"Erro ao executar enumeração de endpoints: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    def _check_active_hosts(self, hosts_file, output_dir):
        """
        Verifica quais hosts estão ativos usando httpx.
        """
        self.logger.step("Verificando hosts ativos com httpx")
        
        # Verificar se httpx está disponível e funcionando
        if "httpx" not in self.tools_status["available"]:
            self.logger.warning("httpx não está disponível, pulando verificação de hosts ativos")
            return hosts_file
        
        # Testar se o httpx está funcionando
        test_cmd = "httpx -silent -title -u http://example.com"
        test_result = self.executor.execute(test_cmd, timeout=10)
        if not test_result["success"]:
            self.logger.error("HTTPX não está funcionando corretamente. Erro: " + test_result.get("stderr", "Desconhecido"))
            return None

        # Arquivo de saída
        active_hosts_file = os.path.join(output_dir, "active_hosts.txt")
        
        try:
            # Comando mais robusto
            command = [
                "httpx",
                "-l", hosts_file,
                "-silent",
                "-threads", str(self.threads),
                "-retries", "2",
                "-timeout", "10",
                "-o", active_hosts_file,
                "-status-code",
                "-content-length",
                "-title"
            ]
            
            result = self.executor.execute(command, timeout=self.timeout * 2)
            
            if not result["success"]:
                self.logger.error(f"Falha ao executar httpx: {result['stderr']}")
                return None
            
            # Verificar resultados
            if not os.path.exists(active_hosts_file):
                self.logger.warning("Nenhum host ativo encontrado (arquivo de saída não criado)")
                return None
                
            with open(active_hosts_file, "r", encoding="utf-8", errors="ignore") as f:
                active_hosts = [line.strip() for line in f if line.strip()]
                
            if not active_hosts:
                self.logger.warning("Nenhum host ativo encontrado (arquivo vazio)")
                return None
                
            self.logger.success(f"Encontrados {len(active_hosts)} hosts ativos")
            return active_hosts_file
            
        except Exception as e:
            self.logger.error(f"Erro inesperado ao verificar hosts ativos: {str(e)}")
            return None
    
    def _run_crawler(self, hosts_file, output_file):
        """
        Executa crawling nos hosts tentando katana e, se falhar, hakrawler.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_file (str): Arquivo de saída para endpoints
            
        Returns:
            bool: True se o crawling foi executado com sucesso (em qualquer ferramenta), False caso contrário
        """
        self.logger.step("Executando crawling para descobrir endpoints")
        
        # 1. Validação do arquivo de entrada
        if not os.path.exists(hosts_file):
            self.logger.error(f"Arquivo de hosts não encontrado: {hosts_file}")
            return False
            
        if os.path.getsize(hosts_file) == 0:
            self.logger.error(f"Arquivo de hosts vazio: {hosts_file}")
            return False

        # 2. Tentar Katana primeiro (se disponível)
        if "katana" in self.tools_status["available"]:
            katana_cmd = (
                f"cat '{hosts_file}' | "
                f"katana -silent -kf -c 10 -t {self.threads} -o '{output_file}'"
            )
            self.logger.debug(f"Tentando Katana com comando: {katana_cmd}")
            
            result = self.executor.execute(katana_cmd, timeout=self.timeout * 2, shell=True)
            
            if result["success"] and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r', encoding="utf-8", errors="ignore") as f:
                    endpoints = [line.strip() for line in f if line.strip()]
                self.logger.success(f"Katana encontrou {len(endpoints)} endpoints")
                return True
            else:
                self.logger.warning(
                    f"Katana falhou ou não retornou resultados: {result.get('stderr','Sem mensagem')}"
                )
        
        # 3. Se Katana falhou ou não disponível, tentar Hakrawler
        if "hakrawler" in self.tools_status["available"]:
            hak_cmd = f"cat '{hosts_file}' | hakrawler -t {self.threads} > '{output_file}'"
            self.logger.debug(f"Tentando Hakrawler com comando: {hak_cmd}")
            
            result = self.executor.execute(hak_cmd, timeout=self.timeout * 2, shell=True)
            
            if result["success"] and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r', encoding="utf-8", errors="ignore") as f:
                    endpoints = [line.strip() for line in f if line.strip()]
                self.logger.success(f"Hakrawler encontrou {len(endpoints)} endpoints")
                return True
            else:
                self.logger.error(
                    f"Hakrawler também falhou: {result.get('stderr','Sem mensagem de erro')}"
                )
        else:
            self.logger.warning("Hakrawler não disponível como alternativa")
        
        # 4. Se ambas falharem
        self.logger.error("Todos os crawlers disponíveis falharam")
        return False
    
    def _run_historical_urls(self, hosts_file, output_file):
        """
        Obtém URLs históricas usando waybackurls ou gau.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_file (str): Arquivo de saída para endpoints
            
        Returns:
            bool: True se a obtenção de URLs históricas foi executada com sucesso, False caso contrário
        """
        self.logger.step("Obtendo URLs históricas")
        
        # Verificar se waybackurls ou gau estão disponíveis
        if "gau" in self.tools_status["available"]:
            historical_tool = "gau"
        elif "waybackurls" in self.tools_status["available"]:
            historical_tool = "waybackurls"
        else:
            self.logger.warning("Nenhuma ferramenta de URLs históricas disponível, pulando etapa")
            return False
        
        # Arquivo temporário para resultados
        historical_output = os.path.join(os.path.dirname(output_file), f"{historical_tool}_output.txt")
        
        # Extrair domínios do arquivo de hosts
        domains_file = os.path.join(os.path.dirname(output_file), "domains.txt")
        command = f"cat {hosts_file} | cut -d/ -f3 | sort -u > {domains_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(domains_file) or os.path.getsize(domains_file) == 0:
            self.logger.error("Falha ao extrair domínios do arquivo de hosts")
            return False
        
        # Executar ferramenta de URLs históricas
        if historical_tool == "gau":
            command = f"cat {domains_file} | gau --threads {self.threads} > {historical_output}"
            result = self.executor.execute(command, timeout=self.timeout, shell=True)

            if not result["success"]:
                self.logger.error(f"Falha ao executar gau: {result['stderr']}")
                return False

        else:  # waybackurls
            self.logger.info("Executando waybackurls por subdomínio (modo individual)")
            with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
                domains = [line.strip() for line in f if line.strip()]

            temp_result_file = historical_output + ".tmp"

            with open(temp_result_file, "w") as out_file:
                for domain in domains:
                    cmd = f"echo {domain} | waybackurls"
                    result = self.executor.execute(cmd, timeout=60, shell=True)

                    if result["success"]:
                        out_file.write(result["stdout"])
                    else:
                        self.logger.warning(f"waybackurls falhou para {domain}: {result['stderr']}")

            # Ordenar e deduplicar
            command = f"cat {temp_result_file} | sort -u > {historical_output}"
            result = self.executor.execute(command, timeout=20, shell=True)

            if not result["success"]:
                self.logger.error(f"Erro ao ordenar resultados do waybackurls: {result['stderr']}")
                return False

            if os.path.exists(temp_result_file):
                os.remove(temp_result_file)

        
        # Verificar se o arquivo foi criado
        if not os.path.exists(historical_output) or os.path.getsize(historical_output) == 0:
            self.logger.warning(f"Nenhuma URL histórica encontrada com {historical_tool}")
            return False
        
        # Adicionar resultados ao arquivo de endpoints
        command = f"cat {historical_output} >> {output_file}"
        result = self.executor.execute(command, timeout=10)
        
        if not result["success"]:
            self.logger.error(f"Falha ao adicionar resultados do {historical_tool} ao arquivo de endpoints: {result['stderr']}")
            return False
        
        # Contar URLs históricas
        with open(historical_output, "r", encoding="utf-8", errors="ignore") as f:
            urls = f.read().splitlines()
        
        self.logger.success(f"Encontradas {len(urls)} URLs históricas com {historical_tool}")
        return True
    
    def _run_directory_fuzzing(self, hosts_file, output_file):
        """
        Executa fuzzing de diretórios usando ffuf ou feroxbuster.
        
        Args:
            hosts_file (str): Arquivo com lista de hosts
            output_file (str): Arquivo de saída para diretórios
            
        Returns:
            bool: True se o fuzzing foi executado com sucesso, False caso contrário
        """
        self.logger.step("Executando fuzzing de diretórios")
        
        # Verificar se ffuf ou feroxbuster estão disponíveis
        if "ffuf" in self.tools_status["available"]:
            fuzzer = "ffuf"
        elif "feroxbuster" in self.tools_status["available"]:
            fuzzer = "feroxbuster"
        else:
            self.logger.warning("Nenhum fuzzer disponível, pulando fuzzing de diretórios")
            return False
        
        # Verificar se o arquivo de hosts existe
        if not hosts_file or not os.path.exists(hosts_file) or os.path.getsize(hosts_file) == 0:
            self.logger.warning("Arquivo de hosts vazio ou não encontrado, pulando fuzzing de diretórios")
            return False
        
        # Arquivo temporário para resultados
        fuzzer_output = os.path.join(os.path.dirname(output_file), f"{fuzzer}_output.txt")
        
        # Diretório base das wordlists (setado no Docker)
        wordlists_dir = os.environ.get("WORDLISTS_DIR", "/app/wordlists")

        # Caminhos alternativos
        wordlist_candidates = [
            os.path.join(wordlists_dir, "Discovery/Web-Content/common.txt"),
            os.path.join(wordlists_dir, "Discovery/Web-Content/directory-list-2.3-medium.txt")
        ]

        # Verifica qual wordlist existe
        wordlist = None
        for candidate in wordlist_candidates:
            if os.path.exists(candidate):
                wordlist = candidate
                break

        if not wordlist:
            self.logger.warning("Nenhuma wordlist encontrada, pulando fuzzing de diretórios")
            return False

        
        # Ler hosts do arquivo
        with open(hosts_file, "r", encoding="utf-8", errors="ignore") as f:
            hosts = f.read().splitlines()
        
        # Limitar número de hosts para fuzzing
        max_hosts = 5
        if len(hosts) > max_hosts:
            self.logger.info(f"Limitando fuzzing para {max_hosts} hosts aleatórios")
            hosts = random.sample(hosts, max_hosts)
        
        # Executar fuzzing para cada host
        success = False
        for host in hosts:
            self.logger.info(f"Executando fuzzing em {host}")
            
            # Arquivo temporário para resultados deste host
            host_output = os.path.join(os.path.dirname(output_file), f"{fuzzer}_{urlparse(host).netloc}.txt")
            
            # Executar fuzzer
            if fuzzer == "ffuf":
                command = f"ffuf -u {host}/FUZZ -w {wordlist} -mc 200,201,202,203,204,301,302,307,401,403,405 -o {host_output} -of csv"
            else:  # feroxbuster
                command = f"feroxbuster -u {host} -w {wordlist} -o {host_output} --silent"
            
            result = self.executor.execute(command, timeout=self.timeout)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao executar {fuzzer} em {host}: {result['stderr']}")
                continue
            
            # Verificar se o arquivo foi criado
            if not os.path.exists(host_output) or os.path.getsize(host_output) == 0:
                self.logger.warning(f"Nenhum diretório encontrado em {host}")
                continue
            
            # Processar resultados
            if fuzzer == "ffuf":
                # Extrair URLs do CSV
                command = f"tail -n +2 {host_output} | cut -d ',' -f 2 >> {fuzzer_output}"
            else:  # feroxbuster
                # Extrair URLs
                command = f"cat {host_output} | grep -o 'http[s]*://[^ ]*' >> {fuzzer_output}"
            
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao processar resultados do {fuzzer} para {host}: {result['stderr']}")
                continue
            
            success = True
        
        if not success:
            self.logger.warning("Nenhum diretório encontrado em nenhum host")
            return False
        
        # Adicionar resultados ao arquivo de diretórios
        if os.path.exists(fuzzer_output) and os.path.getsize(fuzzer_output) > 0:
            command = f"cat {fuzzer_output} | sort -u > {output_file}"
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.error(f"Falha ao adicionar resultados do {fuzzer} ao arquivo de diretórios: {result['stderr']}")
                return False
            
            # Contar diretórios
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                directories = f.read().splitlines()
            
            self.logger.success(f"Encontrados {len(directories)} diretórios com {fuzzer}")
            return True
        else:
            self.logger.warning("Nenhum diretório encontrado")
            return False
    
    def _consolidate_results(self, endpoints_file, active_endpoints_file, directories_file, parameters_file, output_dir):
        """
        Consolida os resultados da enumeração.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            active_endpoints_file (str): Arquivo para salvar endpoints ativos
            directories_file (str): Arquivo com lista de diretórios
            parameters_file (str): Arquivo para salvar parâmetros
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados consolidados
        """
        self.logger.step("Consolidando resultados da enumeração")
        
        # Verificar se o arquivo de endpoints existe
        if not os.path.exists(endpoints_file) or os.path.getsize(endpoints_file) == 0:
            # Criar arquivo vazio
            with open(endpoints_file, "w", encoding="utf-8", errors="ignore") as f:
                pass
            self.logger.warning("Nenhum endpoint encontrado")
        
        # Remover duplicatas e ordenar endpoints
        sorted_endpoints_file = os.path.join(output_dir, "sorted_endpoints.txt")
        command = f"cat {endpoints_file} | sort -u > {sorted_endpoints_file} && mv {sorted_endpoints_file} {endpoints_file}"
        result = self.executor.execute(command, timeout=30, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao ordenar endpoints: {result['stderr']}")
        
        if "httpx" in self.tools_status["available"]:
            self.logger.info("Verificando endpoints ativos com httpx")
            
            # Usar timeout maior para muitos endpoints
            current_timeout = max(self.timeout, len(self.endpoints) * 2)
            
            command = [
                "httpx",
                "-l", endpoints_file,
                "-silent",
                "-threads", str(self.threads),
                "-retries", "1",
                "-timeout", "15",
                "-o", active_endpoints_file,
                "-status-code"
            ]
            
            result = self.executor.execute(command, timeout=current_timeout)
            
            if not result["success"]:
                self.logger.error(f"Falha ao verificar endpoints ativos: {result['stderr']}")
                # Tentando fallback mais simples
                simple_cmd = f"httpx -l {endpoints_file} -silent -o {active_endpoints_file}"
                self.executor.execute(simple_cmd, timeout=current_timeout, shell=True)
        
        # Extrair parâmetros de URLs
        if os.path.exists(endpoints_file) and os.path.getsize(endpoints_file) > 0:
            self.logger.info("Extraindo parâmetros de URLs")
            
            # Usar grep para extrair parâmetros
            command = f"cat {endpoints_file} | grep -o '\\?[^\"]*' | cut -d '?' -f2 | tr '&' '\\n' | cut -d '=' -f1 | sort -u > {parameters_file}"
            result = self.executor.execute(command, timeout=30, shell=True)
            
            if not result["success"]:
                self.logger.error(f"Falha ao extrair parâmetros: {result['stderr']}")
        
        # Contar resultados
        endpoints_count = 0
        active_endpoints_count = 0
        directories_count = 0
        parameters_count = 0
        
        if os.path.exists(endpoints_file) and os.path.getsize(endpoints_file) > 0:
            with open(endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
                endpoints = f.read().splitlines()
                endpoints_count = len(endpoints)
                self.endpoints = endpoints
        
        if os.path.exists(active_endpoints_file) and os.path.getsize(active_endpoints_file) > 0:
            with open(active_endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
                active_endpoints = f.read().splitlines()
                active_endpoints_count = len(active_endpoints)
                self.active_endpoints = active_endpoints
        
        if os.path.exists(directories_file) and os.path.getsize(directories_file) > 0:
            with open(directories_file, "r", encoding="utf-8", errors="ignore") as f:
                directories = f.read().splitlines()
                directories_count = len(directories)
                self.directories = directories
        
        if os.path.exists(parameters_file) and os.path.getsize(parameters_file) > 0:
            with open(parameters_file, "r", encoding="utf-8", errors="ignore") as f:
                parameters = f.read().splitlines()
                parameters_count = len(parameters)
                self.parameters = parameters
        
        # Resumo
        self.logger.success(f"Enumeração concluída: {endpoints_count} endpoints, {active_endpoints_count} ativos, {directories_count} diretórios, {parameters_count} parâmetros")
        
        # Resultados
        return {
            "success": True,
            "endpoints": self.endpoints,
            "active_endpoints": self.active_endpoints,
            "directories": self.directories,
            "parameters": self.parameters,
            "stats": {
                "endpoints_count": endpoints_count,
                "active_endpoints_count": active_endpoints_count,
                "directories_count": directories_count,
                "parameters_count": parameters_count
            }
        }
