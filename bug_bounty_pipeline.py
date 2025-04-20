#!/usr/bin/env python3
"""
Bug Bounty Pipeline - Aplicação principal

Este script é o ponto de entrada principal para a pipeline de Bug Bounty em Python.
Ele coordena a execução de todos os módulos e gerencia o fluxo de trabalho completo.
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from modules.installer import ToolInstaller
from modules.subdomain_recon import SubdomainRecon
from modules.endpoint_enum import EndpointEnum
from modules.vuln_scan import VulnScan
from modules.specific_tests import SpecificTests
from reporting.report_generator import ReportGenerator
from reporting.notify import NotifyManager
from config.settings import DEFAULT_THREADS, DEFAULT_TIMEOUT, DEFAULT_LOG_LEVEL

class BugBountyPipeline:
    """
    Classe principal que coordena a execução da pipeline de Bug Bounty.
    """
    def __init__(self, args):
        """
        Inicializa a pipeline de Bug Bounty.
        
        Args:
            args (Namespace): Argumentos da linha de comando
        """
        self.args = args
        self.start_time = datetime.now()
        
        # Configurar logger
        self.logger = Logger(
            name="bug_bounty_pipeline",
            log_file=args.log_file,
            level="DEBUG" if args.verbose else DEFAULT_LOG_LEVEL
        )
        self.logger.banner("Bug Bounty Pipeline - Python Edition")
        
        # Configurar diretórios
        self.output_dir = os.path.abspath(args.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Configurar executor de comandos
        self.executor = CommandExecutor(self.logger)
        
        # Configurar verificador de ferramentas
        self.tool_checker = ToolChecker(self.logger)
        
        # Configurar gerenciador de notificações
        self.notify_manager = NotifyManager(self.logger)
        if args.notify_config:
            self.notify_manager.load_config(args.notify_config)
        
        # Configurar gerador de relatórios
        self.report_generator = ReportGenerator(self.logger)
        
        # Registrar configurações
        self.logger.info(f"Diretório de saída: {self.output_dir}")
        self.logger.info(f"Threads: {args.threads}")
        self.logger.info(f"Timeout: {args.timeout} segundos")
        
        # Notificar início
        if args.notify:
            self.notify_manager.notify(
                message=f"Pipeline iniciada para o domínio: {args.domain}",
                title="Bug Bounty Pipeline Iniciada",
                level="info"
            )
    
    def run(self):
        """
        Executa a pipeline completa de Bug Bounty.
        
        Returns:
            bool: True se a pipeline foi executada com sucesso, False caso contrário
        """
        try:
            # Verificar ferramentas
            if self.args.check_only:
                self.logger.info("Modo de verificação de ferramentas ativado")
                return self.check_tools()
            
            # Instalar ferramentas
            if self.args.install:
                self.logger.info("Modo de instalação de ferramentas ativado")
                return self.install_tools()
            
            # Modo apenas enumeração
            if self.args.enum_only:
                self.logger.info("Modo de enumeração apenas ativado")
                
                # Verificar se o arquivo existe
                if not os.path.exists(self.args.enum_only):
                    self.logger.error(f"Arquivo de subdomínios não encontrado: {self.args.enum_only}")
                    return False
                
                # Executar apenas a enumeração
                endpoint_results = self.run_endpoint_enum(self.args.enum_only)
                if not endpoint_results or not endpoint_results.get("success", False):
                    self.logger.error("Enumeração de endpoints falhou")
                    return False
                
                # Gerar relatório parcial
                report_file = self.generate_enum_report(endpoint_results)
                
                # Notificar conclusão
                if self.args.notify:
                    self.notify_completion(report_file)
                
                self.print_enum_summary(endpoint_results, report_file)
                return True
            
            # Modo apenas escaneamento
            if self.args.scan_only:
                self.logger.info("Modo de escaneamento apenas ativado")

                if not os.path.exists(self.args.scan_only):
                    self.logger.error(f"Arquivo de endpoints não encontrado: {self.args.scan_only}")
                    return False

                active_path = Path(self.args.scan_only)
                if "enum" in active_path.parts:
                    domain_index = active_path.parts.index("enum") - 1
                    domain_name = active_path.parts[domain_index]
                else:
                    self.logger.error("Não foi possível extrair o domínio do caminho fornecido.")
                    return False
                vuln_results = self.run_vuln_scan(self.args.scan_only, domain=domain_name)
                
                if not vuln_results or not vuln_results.get("success", False):
                    self.logger.error("Escaneamento de vulnerabilidades falhou")
                    return False

                # Gerar relatório parcial se quiser
                if self.args.notify:
                    self.notify_manager.notify(
                        message=f"Scan concluído para: {domain_name}",
                        title="Scan finalizado",
                        level="success"
                    )

                return True
            
            # Executar pipeline completa
            self.logger.info("Executando pipeline completa")
            
            # 1. Verificar ferramentas necessárias
            if not self.check_tools(silent=True):
                self.logger.error("Verificação de ferramentas falhou. Use --install para instalar as ferramentas necessárias.")
                return False
            
            # 2. Reconhecimento de subdomínios
            subdomain_results = self.run_subdomain_recon()
            if not subdomain_results or not subdomain_results.get("success", False):
                self.logger.error("Reconhecimento de subdomínios falhou")
                return False
            
            # 3. Enumeração de endpoints
            endpoint_results = self.run_endpoint_enum(
                subdomain_results.get("subdomains_file"),
                domain=self.args.domain
            )
            if not endpoint_results or not endpoint_results.get("success", False):
                self.logger.error("Enumeração de endpoints falhou")
                return False
            
            # 4. Escaneamento de vulnerabilidades
            vuln_results = self.run_vuln_scan(
                endpoint_results.get("active_endpoints_file"),
                domain=self.args.domain
            )
            if not vuln_results or not vuln_results.get("success", False):
                self.logger.error("Escaneamento de vulnerabilidades falhou")
                return False
            
            # 5. Testes específicos
            specific_results = self.run_specific_tests(endpoint_results.get("active_endpoints_file"))
            if not specific_results or not specific_results.get("success", False):
                self.logger.error("Testes específicos falharam")
                return False
            
            # 6. Gerar relatório final
            report_file = self.generate_final_report(
                subdomain_results,
                endpoint_results,
                vuln_results,
                specific_results
            )
            
            # 7. Notificar conclusão
            if self.args.notify:
                self.notify_completion(report_file)
            
            # Resumo final
            self.print_summary(
                subdomain_results,
                endpoint_results,
                vuln_results,
                specific_results,
                report_file
            )
            
            return True
        except KeyboardInterrupt:
            self.logger.warning("Pipeline interrompida pelo usuário")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao executar pipeline: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def check_tools(self, silent=False):
        """
        Verifica se todas as ferramentas necessárias estão instaladas.
        
        Args:
            silent (bool, optional): Se True, não exibe mensagens detalhadas
            
        Returns:
            bool: True se todas as ferramentas estão disponíveis, False caso contrário
        """
        if not silent:
            self.logger.banner("Verificação de Ferramentas")
        
        # Verificar todas as ferramentas
        all_tools_status = self.tool_checker.check_all_tools()
        
        # Verificar se all_tools_status é um dicionário com as chaves esperadas
        if not isinstance(all_tools_status, dict) or not all(key in all_tools_status for key in ["available", "missing", "alternatives"]):
            self.logger.error("Formato de retorno inválido do verificador de ferramentas")
            return False
        
        # Obter listas de ferramentas
        available_tools = all_tools_status.get("available", [])
        missing_tools = all_tools_status.get("missing", [])
        alternatives = all_tools_status.get("alternatives", {})
        
        if not silent:
            self.logger.info(f"Ferramentas disponíveis: {len(available_tools)}/{len(available_tools) + len(missing_tools)}")
            
            if missing_tools:
                self.logger.warning(f"Ferramentas faltantes: {len(missing_tools)}")
                self.logger.warning(f"Ferramentas faltantes: {', '.join(missing_tools)}")
            
            if alternatives:
                self.logger.info(f"Alternativas disponíveis: {len(alternatives)}")
                for tool, alt in alternatives.items():
                    self.logger.info(f"  {tool} -> {alt}")
            
            # Exibir detalhes por módulo
            for module, module_tools in all_tools_status.items():
                self.logger.info(f"\nMódulo: {module}")
                self.logger.info(f"  Disponíveis: {', '.join(module_tools['available']) if module_tools['available'] else 'Nenhuma'}")
                self.logger.info(f"  Faltantes: {', '.join(module_tools['missing']) if module_tools['missing'] else 'Nenhuma'}")
                self.logger.info(f"  Alternativas: {', '.join(module_tools['alternatives']) if module_tools['alternatives'] else 'Nenhuma'}")
        
        # Verificar ferramentas críticas
        critical_missing = self.tool_checker.get_critical_missing_tools()
        if critical_missing:
            if not silent:
                self.logger.error(f"Ferramentas críticas faltantes: {', '.join(critical_missing)}")
                self.logger.info("Use --install para instalar as ferramentas necessárias")
            return False
        
        if not silent:
            self.logger.success("Todas as ferramentas críticas estão disponíveis")
        
        return True
    
    def install_tools(self):
        """
        Instala as ferramentas necessárias.
        
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.banner("Instalação de Ferramentas")
        
        # Verificar ferramentas faltantes
        all_tools_status = self.tool_checker.check_all_tools()
        missing_tools = []
        
        for module_tools in all_tools_status.values():
            missing_tools.extend(module_tools["missing"])
        
        if not missing_tools:
            self.logger.success("Todas as ferramentas já estão instaladas")
            return True
        
        self.logger.info(f"Ferramentas a serem instaladas: {', '.join(missing_tools)}")
        
        # Instalar ferramentas
        installer = ToolInstaller(self.logger)
        result = installer.install_tools(missing_tools)
        
        # Verificar novamente
        self.logger.info("Verificando ferramentas após instalação")
        return self.check_tools()
    
    def run_subdomain_recon(self):
        """
        Executa o reconhecimento de subdomínios.
        
        Returns:
            dict: Resultados do reconhecimento de subdomínios
        """
        self.logger.banner("Reconhecimento de Subdomínios")
        
        # Criar diretório de saída
        recon_dir = os.path.join(self.output_dir, "recon")
        os.makedirs(recon_dir, exist_ok=True)
        
        # Executar reconhecimento
        subdomain_recon = SubdomainRecon(
            self.logger,
            threads=self.args.threads,
            timeout=self.args.timeout
        )
        
        results = subdomain_recon.run(
            domain=self.args.domain,
            output_dir=recon_dir
        )
        
        # Definir o caminho correto do arquivo de subdomínios
        if results and results.get("success", False):
            results["subdomains_file"] = results.get("final_file")
        
        return results
    
    def run_endpoint_enum(self, subdomains_file, domain):
        """
        Executa a enumeração de endpoints.
        
        Args:
            subdomains_file (str): Arquivo com lista de subdomínios
            
        Returns:
            dict: Resultados da enumeração de endpoints
        """
        self.logger.banner("Enumeração de Endpoints")
        
        # Verificar arquivo de subdomínios
        if not subdomains_file or not os.path.exists(subdomains_file):
            self.logger.error(f"Arquivo de subdomínios não encontrado: {subdomains_file}")
            return {"success": False, "error": "Arquivo de subdomínios não encontrado"}
        
        # Executar enumeração
        endpoint_enum = EndpointEnum(
            self.logger,
            threads=self.args.threads,
            timeout=self.args.timeout
        )
        
        return endpoint_enum.run(
            hosts_file=subdomains_file,
            output_dir=self.output_dir,
            domain=domain
        )
    
    def run_vuln_scan(self, endpoints_file, domain):
        """
        Executa o escaneamento de vulnerabilidades.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            
        Returns:
            dict: Resultados do escaneamento de vulnerabilidades
        """
        self.logger.banner("Escaneamento de Vulnerabilidades")
        
        # Verificar arquivo de endpoints
        if not endpoints_file or not os.path.exists(endpoints_file):
            self.logger.error(f"Arquivo de endpoints não encontrado: {endpoints_file}")
            return {"success": False, "error": "Arquivo de endpoints não encontrado"}
        
        # Executar escaneamento
        vuln_scan = VulnScan(
            self.logger,
            threads=self.args.threads,
            timeout=self.args.timeout
        )
        
        return vuln_scan.run(
            endpoints_file=endpoints_file,
            output_dir=self.output_dir,
            domain=domain 
        )
    
    def run_specific_tests(self, endpoints_file):
        """
        Executa testes específicos.
        
        Args:
            endpoints_file (str): Arquivo com lista de endpoints
            
        Returns:
            dict: Resultados dos testes específicos
        """
        self.logger.banner("Testes Específicos")
        
        # Verificar arquivo de endpoints
        if not endpoints_file or not os.path.exists(endpoints_file):
            self.logger.error(f"Arquivo de endpoints não encontrado: {endpoints_file}")
            return {"success": False, "error": "Arquivo de endpoints não encontrado"}
        
        # Executar testes específicos
        specific_tests = SpecificTests(
            self.logger,
            threads=self.args.threads,
            timeout=self.args.timeout
        )
        
        return specific_tests.run(
            endpoints_file=endpoints_file,
            output_dir=self.output_dir
        )
    
    def generate_enum_report(self, endpoint_results):
        """
        Gera um relatório apenas para os resultados da enumeração.
        
        Args:
            endpoint_results (dict): Resultados da enumeração de endpoints
            
        Returns:
            str: Caminho para o relatório
        """
        self.logger.banner("Geração de Relatório de Enumeração")
        
        # Criar diretório de relatórios
        reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Arquivo de relatório
        report_file = os.path.join(reports_dir, f"enum_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        
        # Preparar dados para o relatório
        report_data = {
            "title": f"Relatório de Enumeração - {self.args.domain if self.args.domain else 'target'}",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": "Este relatório apresenta os resultados da enumeração de endpoints.",
            "stats": {
                "Endpoints": len(endpoint_results.get("endpoints", [])),
                "Endpoints ativos": len(endpoint_results.get("active_endpoints", [])),
                "Diretórios encontrados": len(endpoint_results.get("directories", [])),
                "Parâmetros encontrados": len(endpoint_results.get("parameters", []))
            },
            "conclusion": "Enumeração de endpoints concluída com sucesso."
        }
        
        # Gerar relatório
        self.report_generator.generate_report(report_data, report_file, format="md")
        
        # Gerar versões alternativas se solicitado
        if self.args.html_report:
            html_file = report_file.replace(".md", ".html")
            self.report_generator.generate_report(report_data, html_file, format="html")
        
        if self.args.json_report:
            json_file = report_file.replace(".md", ".json")
            self.report_generator.generate_report(report_data, json_file, format="json")
        
        self.logger.success(f"Relatório de enumeração gerado: {report_file}")
        return report_file

    def print_enum_summary(self, endpoint_results, report_file):
        """
        Imprime um resumo dos resultados da enumeração.
        
        Args:
            endpoint_results (dict): Resultados da enumeração
            report_file (str): Caminho para o relatório
        """
        self.logger.banner("Resumo da Enumeração")
        
        # Contar resultados
        endpoints_count = len(endpoint_results.get("endpoints", []))
        active_endpoints_count = len(endpoint_results.get("active_endpoints", []))
        directories_count = len(endpoint_results.get("directories", []))
        parameters_count = len(endpoint_results.get("parameters", []))
        
        self.logger.info(f"Endpoints encontrados: {endpoints_count}")
        self.logger.info(f"Endpoints ativos: {active_endpoints_count}")
        self.logger.info(f"Diretórios encontrados: {directories_count}")
        self.logger.info(f"Parâmetros encontrados: {parameters_count}")
        self.logger.info(f"Relatório gerado: {report_file}")


    def generate_final_report(self, subdomain_results, endpoint_results, vuln_results, specific_results):
        """
        Gera o relatório final consolidando todos os resultados.
        
        Args:
            subdomain_results (dict): Resultados do reconhecimento de subdomínios
            endpoint_results (dict): Resultados da enumeração de endpoints
            vuln_results (dict): Resultados do escaneamento de vulnerabilidades
            specific_results (dict): Resultados dos testes específicos
            
        Returns:
            str: Caminho para o relatório final
        """
        self.logger.banner("Geração de Relatório Final")
        
        # Criar diretório de relatórios
        reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Arquivo de relatório final
        final_report_file = os.path.join(reports_dir, f"bug_bounty_report_{self.args.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        
        # Consolidar vulnerabilidades
        all_vulnerabilities = []
        if vuln_results and "vulnerabilities" in vuln_results:
            all_vulnerabilities.extend(vuln_results["vulnerabilities"])
        
        if specific_results and "vulnerabilities" in specific_results:
            all_vulnerabilities.extend(specific_results["vulnerabilities"])
        
        # Contar vulnerabilidades por severidade
        severity_counts = {}
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
        
        # Preparar dados para o relatório
        report_data = {
            "title": f"Relatório de Bug Bounty - {self.args.domain}",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain": self.args.domain,
            "summary": f"Este relatório apresenta os resultados da pipeline de Bug Bounty para o domínio {self.args.domain}.",
            "stats": {
                "Duração": f"{(datetime.now() - self.start_time).total_seconds() / 60:.2f} minutos",
                "Subdomínios": len(subdomain_results.get("subdomains", [])) if subdomain_results else 0,
                "Endpoints": len(endpoint_results.get("endpoints", [])) if endpoint_results else 0,
                "Endpoints ativos": len(endpoint_results.get("active_endpoints", [])) if endpoint_results else 0,
                "Total de vulnerabilidades": len(all_vulnerabilities)
            },
            "vulnerabilities": all_vulnerabilities,
            "recommendations": [
                "Corrigir todas as vulnerabilidades críticas e de alta severidade imediatamente.",
                "Implementar um programa de gestão de vulnerabilidades para monitoramento contínuo.",
                "Realizar testes de penetração regulares para identificar novas vulnerabilidades."
            ],
            "conclusion": f"A análise de segurança do domínio {self.args.domain} identificou {len(all_vulnerabilities)} vulnerabilidades. Recomenda-se a correção imediata das vulnerabilidades críticas e de alta severidade."
        }
        
        # Adicionar contagem por severidade
        for severity, count in severity_counts.items():
            report_data["stats"][f"Vulnerabilidades {severity.capitalize()}"] = count
        
        # Gerar relatório
        self.logger.info(f"Gerando relatório final em {final_report_file}")
        self.report_generator.generate_report(report_data, final_report_file, format="md")
        
        # Gerar versão HTML se solicitado
        if self.args.html_report:
            html_report_file = final_report_file.replace(".md", ".html")
            self.logger.info(f"Gerando relatório HTML em {html_report_file}")
            self.report_generator.generate_report(report_data, html_report_file, format="html")
        
        # Gerar versão JSON se solicitado
        if self.args.json_report:
            json_report_file = final_report_file.replace(".md", ".json")
            self.logger.info(f"Gerando relatório JSON em {json_report_file}")
            self.report_generator.generate_report(report_data, json_report_file, format="json")
        
        self.logger.success(f"Relatório final gerado: {final_report_file}")
        return final_report_file
    
    def notify_completion(self, report_file):
        """
        Notifica a conclusão da pipeline.
        
        Args:
            report_file (str): Caminho para o relatório final
        """
        self.logger.info("Enviando notificação de conclusão")
        
        # Preparar mensagem
        duration = datetime.now() - self.start_time
        message = f"""
Pipeline de Bug Bounty concluída para o domínio {self.args.domain}.

Duração: {duration.total_seconds() / 60:.2f} minutos
Relatório: {os.path.basename(report_file)}
        """
        
        # Enviar notificação
        self.notify_manager.notify(
            message=message,
            title="Bug Bounty Pipeline Concluída",
            level="success",
            attachments=[report_file]
        )
    
    def print_summary(self, subdomain_results, endpoint_results, vuln_results, specific_results, report_file):
        """
        Imprime um resumo dos resultados.
        
        Args:
            subdomain_results (dict): Resultados do reconhecimento de subdomínios
            endpoint_results (dict): Resultados da enumeração de endpoints
            vuln_results (dict): Resultados do escaneamento de vulnerabilidades
            specific_results (dict): Resultados dos testes específicos
            report_file (str): Caminho para o relatório final
        """
        self.logger.banner("Resumo da Pipeline")
        
        # Duração
        duration = datetime.now() - self.start_time
        self.logger.info(f"Duração total: {duration.total_seconds() / 60:.2f} minutos")
        
        # Subdomínios
        subdomains_count = len(subdomain_results.get("subdomains", [])) if subdomain_results else 0
        active_subdomains_count = len(subdomain_results.get("active_subdomains", [])) if subdomain_results else 0
        self.logger.info(f"Subdomínios encontrados: {subdomains_count} (ativos: {active_subdomains_count})")
        
        # Endpoints
        endpoints_count = len(endpoint_results.get("endpoints", [])) if endpoint_results else 0
        active_endpoints_count = len(endpoint_results.get("active_endpoints", [])) if endpoint_results else 0
        self.logger.info(f"Endpoints encontrados: {endpoints_count} (ativos: {active_endpoints_count})")
        
        # Vulnerabilidades
        all_vulnerabilities = []
        if vuln_results and "vulnerabilities" in vuln_results:
            all_vulnerabilities.extend(vuln_results["vulnerabilities"])
        
        if specific_results and "vulnerabilities" in specific_results:
            all_vulnerabilities.extend(specific_results["vulnerabilities"])
        
        # Contar vulnerabilidades por severidade
        severity_counts = {}
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
        
        self.logger.info(f"Total de vulnerabilidades: {len(all_vulnerabilities)}")
        for severity, count in severity_counts.items():
            self.logger.info(f"  {severity.capitalize()}: {count}")
        
        # Relatório
        self.logger.info(f"Relatório final: {report_file}")
        
        # Diretório de saída
        self.logger.info(f"Todos os resultados estão disponíveis em: {self.output_dir}")

def parse_args():
    """
    Analisa os argumentos da linha de comando.
    
    Returns:
        argparse.Namespace: Argumentos analisados
    """
    parser = argparse.ArgumentParser(description="Bug Bounty Pipeline - Python Edition")
    
    # Argumentos obrigatórios
    parser.add_argument("domain", help="Domínio alvo para a pipeline")
    
    # Argumentos opcionais
    parser.add_argument("-o", "--output-dir", default="bug_bounty_results", help="Diretório de saída para os resultados")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Número de threads para execução paralela (padrão: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout para comandos externos em segundos (padrão: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso (exibe logs de debug)")
    parser.add_argument("--log-file", help="Arquivo de log")
    
    # Argumentos de relatório
    parser.add_argument("--html-report", action="store_true", help="Gerar relatório em formato HTML")
    parser.add_argument("--json-report", action="store_true", help="Gerar relatório em formato JSON")
    
    # Argumentos de notificação
    parser.add_argument("--notify", action="store_true", help="Enviar notificações")
    parser.add_argument("--notify-config", help="Arquivo de configuração para notificações")
    
    # Modos especiais
    parser.add_argument("--check-only", action="store_true", help="Apenas verificar ferramentas necessárias")
    parser.add_argument("--install", action="store_true", help="Instalar ferramentas necessárias")

    # Executar apenas a enumeração
    parser.add_argument("--enum-only", metavar="SUBDOMAINS_FILE", help="Executar apenas a enumeração usando um arquivo de subdomínios existente")

    # Executar apenas o scan de vulnerabilidade
    parser.add_argument("--scan-only", metavar="ACTIVE_ENDPOINTS_FILE", help="Executa apenas o escaneamento de vulnerabilidades")

    
    return parser.parse_args()

def main():
    """
    Função principal.
    """
    # Analisar argumentos
    args = parse_args()
    
    # Criar e executar pipeline
    pipeline = BugBountyPipeline(args)
    success = pipeline.run()
    
    # Retornar código de saída
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
