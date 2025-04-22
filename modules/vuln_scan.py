"""
Módulo de escaneamento de vulnerabilidades para a pipeline de Bug Bounty.
Responsável por detectar vulnerabilidades em endpoints usando várias ferramentas.
"""

import os
import sys
import time
import json
import tempfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from config.tools import get_tools_for_module

class VulnScan:
    """
    Classe para escaneamento de vulnerabilidades em endpoints.
    """
    def __init__(self, logger=None, threads=3, timeout=300):
        """
        Inicializa o escaneador de vulnerabilidades.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
            threads (int, optional): Número de threads para execução paralela
            timeout (int, optional): Timeout para comandos externos em segundos
        """
        self.logger = logger or Logger("vuln_scan")
        self.executor = CommandExecutor(self.logger)
        self.tool_checker = ToolChecker(self.logger)
        self.threads = threads
        self.timeout = timeout
        
        # Verificar ferramentas necessárias
        self.tools_status = self.tool_checker.check_tools_for_module("scan")
        
        # Resultados
        self.vulnerabilities = []
    
    def run(self, endpoints_file, output_dir, domain):
        """
        Executa o escaneamento de vulnerabilidades.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados do escaneamento
        """
        self.logger.info(f"Iniciando escaneamento de vulnerabilidades em {endpoints_file}")
        
        # Verificar arquivo de endpoints
        if not os.path.exists(endpoints_file):
            self.logger.error(f"Arquivo de endpoints não encontrado: {endpoints_file}")
            return {"success": False, "error": "Arquivo de endpoints não encontrado"}
        
        # Criar diretório de saída
        scan_dir = os.path.join(output_dir, "scan", domain)
        os.makedirs(scan_dir, exist_ok=True)
        
        # Arquivo de saída para vulnerabilidades
        vulns_file = os.path.join(scan_dir, "vulnerabilities.json")
        
        try:
            # 1. Executar Nuclei
            nuclei_results = self._run_nuclei(endpoints_file, scan_dir)
            
            # 2. Executar Naabu para escaneamento de portas
            naabu_results = self._run_naabu(endpoints_file, scan_dir)
            
            # 3. Executar SQLMap para detecção de SQL Injection
            sqlmap_results = self._run_sqlmap(endpoints_file, scan_dir)
            
            # 4. Executar Nikto para escaneamento de vulnerabilidades em servidores web
            nikto_results = self._run_nikto(endpoints_file, scan_dir)
            
            # 5. Executar Dalfox para detecção de XSS
            dalfox_results = self._run_dalfox(endpoints_file, scan_dir)
            
            # Consolidar resultados
            self._consolidate_results(vulns_file)
            
            # Retornar resultados
            return {
                "success": True,
                "vulnerabilities": self.vulnerabilities,
                "stats": {
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "nuclei_vulnerabilities": len(nuclei_results) if nuclei_results else 0,
                    "naabu_open_ports": len(naabu_results) if naabu_results else 0,
                    "sqlmap_vulnerabilities": len(sqlmap_results) if sqlmap_results else 0,
                    "nikto_vulnerabilities": len(nikto_results) if nikto_results else 0,
                    "dalfox_vulnerabilities": len(dalfox_results) if dalfox_results else 0
                }
            }
        except Exception as e:
            self.logger.error(f"Erro ao executar escaneamento de vulnerabilidades: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    def _run_nuclei(self, endpoints_file, output_dir):
        """
        Executa o Nuclei para detecção de vulnerabilidades.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando Nuclei para detecção de vulnerabilidades")
        
        # Verificar se o Nuclei está disponível
        if "nuclei" not in self.tools_status["available"]:
            self.logger.warning("Nuclei não está disponível, pulando detecção de vulnerabilidades com Nuclei")
            return []
        
        # Arquivo de saída para resultados do Nuclei
        nuclei_output = os.path.join(output_dir, "nuclei_results.json")
        
        # Executar Nuclei
        command = f"nuclei -l {endpoints_file} -o {nuclei_output} -silent -c {self.threads}"
        result = self.executor.execute(command, timeout=self.timeout)
        
        if not result["success"]:
            self.logger.error(f"Falha ao executar Nuclei: {result['stderr']}")
            return []
        
        # Verificar se o arquivo foi criado
        if not os.path.exists(nuclei_output) or os.path.getsize(nuclei_output) == 0:
            self.logger.warning("Nenhuma vulnerabilidade encontrada com Nuclei")
            return []
        
        # Processar resultados
        vulnerabilities = []
        try:
            # Nuclei gera um arquivo JSON com uma vulnerabilidade por linha
            with open(nuclei_output, "r") as f:
                for line in f:
                    try:
                        vuln = json.loads(line.strip())
                        
                        # Converter para formato padrão
                        vulnerability = {
                            "name": vuln.get("info", {}).get("name", "Vulnerabilidade Desconhecida"),
                            "url": vuln.get("matched-at", ""),
                            "type": vuln.get("template-id", "").split("/")[-1] if vuln.get("template-id") else "unknown",
                            "severity": vuln.get("info", {}).get("severity", "unknown").lower(),
                            "description": vuln.get("info", {}).get("description", ""),
                            "tool": "nuclei",
                            "raw": vuln
                        }
                        
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Falha ao processar linha do resultado do Nuclei: {line}")
                        continue
        except Exception as e:
            self.logger.error(f"Erro ao processar resultados do Nuclei: {str(e)}")
            return []
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades com Nuclei")
        return vulnerabilities
    
    def _run_naabu(self, endpoints_file, output_dir):
        """
        Executa o Naabu para escaneamento de portas.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de portas abertas encontradas
        """
        self.logger.step("Executando Naabu para escaneamento de portas")
        
        # Verificar se o Naabu está disponível
        if "naabu" not in self.tools_status["available"]:
            self.logger.warning("Naabu não está disponível, pulando escaneamento de portas")
            return []
        
        # Extrair domínios do arquivo de endpoints
        domains_file = os.path.join(output_dir, "domains.txt")
        command = f"cat {endpoints_file} | cut -d/ -f3 | sort -u > {domains_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(domains_file) or os.path.getsize(domains_file) == 0:
            self.logger.error("Falha ao extrair domínios do arquivo de endpoints")
            return []
        
        # Arquivo de saída para resultados do Naabu
        naabu_output = os.path.join(output_dir, "naabu_results.json")
        
        # Executar Naabu
        command = f"naabu -l {domains_file} -json -o {naabu_output} -silent -c {self.threads}"
        result = self.executor.execute(command, timeout=self.timeout)
        
        if not result["success"]:
            self.logger.error(f"Falha ao executar Naabu: {result['stderr']}")
            return []
        
        # Verificar se o arquivo foi criado
        if not os.path.exists(naabu_output) or os.path.getsize(naabu_output) == 0:
            self.logger.warning("Nenhuma porta aberta encontrada com Naabu")
            return []
        
        # Processar resultados
        open_ports = []
        try:
            # Naabu gera um arquivo JSON com um resultado por linha
            with open(naabu_output, "r") as f:
                for line in f:
                    try:
                        port_info = json.loads(line.strip())
                        
                        # Adicionar à lista de portas abertas
                        open_ports.append(port_info)
                        
                        # Adicionar como vulnerabilidade de baixa severidade se for uma porta não comum
                        if port_info.get("port") not in [80, 443, 8080, 8443]:
                            vulnerability = {
                                "name": f"Porta não comum aberta: {port_info.get('port')}",
                                "url": f"{port_info.get('host')}:{port_info.get('port')}",
                                "type": "open_port",
                                "severity": "info",
                                "description": f"Porta não comum {port_info.get('port')} aberta em {port_info.get('host')}",
                                "tool": "naabu",
                                "raw": port_info
                            }
                            
                            self.vulnerabilities.append(vulnerability)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Falha ao processar linha do resultado do Naabu: {line}")
                        continue
        except Exception as e:
            self.logger.error(f"Erro ao processar resultados do Naabu: {str(e)}")
            return []
        
        self.logger.success(f"Encontradas {len(open_ports)} portas abertas com Naabu")
        return open_ports
    
    def _run_sqlmap(self, endpoints_file, output_dir):
        """
        Executa o SQLMap para detecção de SQL Injection.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando SQLMap para detecção de SQL Injection")
        
        # Verificar se o SQLMap está disponível
        if "sqlmap" not in self.tools_status["available"]:
            self.logger.warning("SQLMap não está disponível, pulando detecção de SQL Injection")
            return []
        
        # Extrair endpoints com parâmetros
        endpoints_with_params_file = os.path.join(output_dir, "endpoints_with_params.txt")
        command = f"cat {endpoints_file} | grep '?' > {endpoints_with_params_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(endpoints_with_params_file) or os.path.getsize(endpoints_with_params_file) == 0:
            self.logger.warning("Nenhum endpoint com parâmetros encontrado para testar com SQLMap")
            return []
        
        # Limitar número de endpoints para testar
        max_endpoints = 10
        command = f"head -n {max_endpoints} {endpoints_with_params_file} > {endpoints_with_params_file}.tmp && mv {endpoints_with_params_file}.tmp {endpoints_with_params_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        # Diretório de saída para resultados do SQLMap
        sqlmap_output_dir = os.path.join(output_dir, "sqlmap_results")
        os.makedirs(sqlmap_output_dir, exist_ok=True)
        
        # Ler endpoints com parâmetros
        with open(endpoints_with_params_file, "r") as f:
            endpoints_with_params = f.read().splitlines()
        
        # Executar SQLMap para cada endpoint
        vulnerabilities = []
        for endpoint in endpoints_with_params:
            self.logger.info(f"Testando SQL Injection em {endpoint}")
            
            # Nome do arquivo de saída baseado no endpoint
            endpoint_hash = str(abs(hash(endpoint)) % 10000)
            output_file = os.path.join(sqlmap_output_dir, f"sqlmap_result_{endpoint_hash}.json")
            
            # Executar SQLMap
            command = f"sqlmap -u '{endpoint}' --batch --level=1 --risk=1 --output-dir={sqlmap_output_dir} --forms --random-agent --threads={self.threads}"
            result = self.executor.execute(command, timeout=self.timeout)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao executar SQLMap para {endpoint}: {result['stderr']}")
                continue
            
            # Verificar se o arquivo foi criado
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                self.logger.debug(f"Nenhuma vulnerabilidade SQL Injection encontrada em {endpoint}")
                continue
            
            # Processar resultados
            try:
                with open(output_file, "r") as f:
                    sqlmap_result = json.load(f)
                
                # Verificar se foram encontradas vulnerabilidades
                if sqlmap_result.get("data", []) and any(sqlmap_result.get("data", {}).get(url, {}).get("status") == 1 for url in sqlmap_result.get("data", {})):
                    for url, data in sqlmap_result.get("data", {}).items():
                        if data.get("status") == 1:  # 1 = vulnerável
                            vulnerability = {
                                "name": "SQL Injection",
                                "url": url,
                                "type": "sqli",
                                "severity": "high",
                                "description": f"Vulnerabilidade de SQL Injection encontrada em {url}",
                                "tool": "sqlmap",
                                "raw": data
                            }
                            
                            vulnerabilities.append(vulnerability)
                            self.vulnerabilities.append(vulnerability)
                            self.logger.alert(f"Vulnerabilidade SQL Injection encontrada em {url}")
            except Exception as e:
                self.logger.error(f"Erro ao processar resultados do SQLMap para {endpoint}: {str(e)}")
                continue
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades SQL Injection com SQLMap")
        return vulnerabilities
    
    def _run_nikto(self, endpoints_file, output_dir):
        """
        Executa o Nikto para escaneamento de vulnerabilidades em servidores web.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando Nikto para escaneamento de vulnerabilidades em servidores web")
        
        # Verificar se o Nikto está disponível
        if "nikto" not in self.tools_status["available"]:
            self.logger.warning("Nikto não está disponível, pulando escaneamento de vulnerabilidades em servidores web")
            return []
        
        # Extrair domínios do arquivo de endpoints
        domains_file = os.path.join(output_dir, "domains.txt")
        command = f"cat {endpoints_file} | cut -d/ -f3 | sort -u > {domains_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(domains_file) or os.path.getsize(domains_file) == 0:
            self.logger.error("Falha ao extrair domínios do arquivo de endpoints")
            return []
        
        # Limitar número de domínios para testar
        max_domains = 5
        command = f"head -n {max_domains} {domains_file} > {domains_file}.tmp && mv {domains_file}.tmp {domains_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        # Ler domínios
        with open(domains_file, "r") as f:
            domains = f.read().splitlines()
        
        # Executar Nikto para cada domínio
        vulnerabilities = []
        for domain in domains:
            self.logger.info(f"Escaneando {domain} com Nikto")
            
            # Arquivo de saída para resultados do Nikto
            nikto_output = os.path.join(output_dir, f"nikto_results_{domain.replace(':', '_')}.json")
            
            # Executar Nikto
            command = f"nikto -h {domain} -Format json -output {nikto_output} -maxtime {self.timeout}"
            result = self.executor.execute(command, timeout=self.timeout)
            
            if not result["success"]:
                self.logger.warning(f"Falha ao executar Nikto para {domain}: {result['stderr']}")
                continue
            
            # Verificar se o arquivo foi criado
            if not os.path.exists(nikto_output) or os.path.getsize(nikto_output) == 0:
                self.logger.debug(f"Nenhuma vulnerabilidade encontrada em {domain} com Nikto")
                continue
            
            # Processar resultados
            try:
                with open(nikto_output, "r") as f:
                    nikto_result = json.load(f)
                
                # Extrair vulnerabilidades
                if "vulnerabilities" in nikto_result:
                    for vuln in nikto_result["vulnerabilities"]:
                        # Determinar severidade com base no ID do OSVDB
                        severity = "medium"  # Padrão
                        
                        vulnerability = {
                            "name": vuln.get("title", "Vulnerabilidade Desconhecida"),
                            "url": f"http://{domain}{vuln.get('url', '')}",
                            "type": "web_vulnerability",
                            "severity": severity,
                            "description": vuln.get("message", ""),
                            "tool": "nikto",
                            "raw": vuln
                        }
                        
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
            except Exception as e:
                self.logger.error(f"Erro ao processar resultados do Nikto para {domain}: {str(e)}")
                continue
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades com Nikto")
        return vulnerabilities
    
    def _run_dalfox(self, endpoints_file, output_dir):
        """
        Executa o Dalfox para detecção de XSS.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando Dalfox para detecção de XSS")
        
        # Verificar se o Dalfox está disponível
        if "dalfox" not in self.tools_status["available"]:
            self.logger.warning("Dalfox não está disponível, pulando detecção de XSS")
            return []
        
        # Extrair endpoints com parâmetros
        endpoints_with_params_file = os.path.join(output_dir, "endpoints_with_params.txt")
        command = f"cat {endpoints_file} | grep '?' > {endpoints_with_params_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"] or not os.path.exists(endpoints_with_params_file) or os.path.getsize(endpoints_with_params_file) == 0:
            self.logger.warning("Nenhum endpoint com parâmetros encontrado para testar com Dalfox")
            return []
        
        # Limitar número de endpoints para testar
        max_endpoints = 10
        command = f"head -n {max_endpoints} {endpoints_with_params_file} > {endpoints_with_params_file}.tmp && mv {endpoints_with_params_file}.tmp {endpoints_with_params_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        # Arquivo de saída para resultados do Dalfox
        dalfox_output = os.path.join(output_dir, "dalfox_results.json")
        
        # Executar Dalfox
        command = f"dalfox file {endpoints_with_params_file} -o {dalfox_output} --report-format json -silence -threads {self.threads}"
        result = self.executor.execute(command, timeout=self.timeout)
        
        if not result["success"]:
            self.logger.error(f"Falha ao executar Dalfox: {result['stderr']}")
            return []
        
        # Verificar se o arquivo foi criado
        if not os.path.exists(dalfox_output) or os.path.getsize(dalfox_output) == 0:
            self.logger.warning("Nenhuma vulnerabilidade XSS encontrada com Dalfox")
            return []
        
        # Processar resultados
        vulnerabilities = []
        try:
            with open(dalfox_output, "r") as f:
                dalfox_results = json.load(f)
            
            # Processar cada resultado
            for result in dalfox_results:
                if "poc" in result:
                    vulnerability = {
                        "name": "Cross-Site Scripting (XSS)",
                        "url": result.get("url", ""),
                        "type": "xss",
                        "severity": "high",
                        "description": f"Vulnerabilidade XSS encontrada em {result.get('url', '')}. PoC: {result.get('poc', '')}",
                        "tool": "dalfox",
                        "raw": result
                    }
                    
                    vulnerabilities.append(vulnerability)
                    self.vulnerabilities.append(vulnerability)
                    self.logger.alert(f"Vulnerabilidade XSS encontrada em {result.get('url', '')}")
        except Exception as e:
            self.logger.error(f"Erro ao processar resultados do Dalfox: {str(e)}")
            return []
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades XSS com Dalfox")
        return vulnerabilities
    
    def _consolidate_results(self, vulns_file):
        """
        Consolida os resultados do escaneamento.
        
        Args:
            vulns_file (str): Arquivo para salvar vulnerabilidades
        """
        self.logger.step("Consolidando resultados do escaneamento")
        
        # Contar vulnerabilidades por severidade
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
        
        # Registrar contagem
        for severity, count in severity_counts.items():
            self.logger.info(f"Vulnerabilidades {severity.capitalize()}: {count}")
        
        # Salvar vulnerabilidades em arquivo JSON
        try:
            with open(vulns_file, "w") as f:
                json.dump(self.vulnerabilities, f, indent=2)
            
            self.logger.success(f"Vulnerabilidades salvas em {vulns_file}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar vulnerabilidades: {str(e)}")
