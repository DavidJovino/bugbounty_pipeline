"""
Módulo de geração de relatórios para a pipeline de Bug Bounty.
Responsável por gerar relatórios em diferentes formatos e enviar notificações.
"""

import os
import sys
import time
import json
import markdown
from datetime import datetime
from pathlib import Path
import jinja2

from core.logger import Logger

class ReportGenerator:
    """
    Classe para geração de relatórios em diferentes formatos.
    """
    def __init__(self, logger=None):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
        """
        self.logger = logger or Logger("report_generator")
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")
        
        # Configurar ambiente Jinja2
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    def generate_report(self, data, output_file, format="md"):
        """
        Gera um relatório no formato especificado.
        
        Args:
            data (dict): Dados para o relatório
            output_file (str): Arquivo de saída
            format (str, optional): Formato do relatório (md, html, json)
            
        Returns:
            bool: True se o relatório foi gerado com sucesso, False caso contrário
        """
        self.logger.info(f"Gerando relatório em formato {format.upper()}")
        
        try:
            if format.lower() == "md":
                return self._generate_markdown_report(data, output_file)
            elif format.lower() == "html":
                return self._generate_html_report(data, output_file)
            elif format.lower() == "json":
                return self._generate_json_report(data, output_file)
            else:
                self.logger.error(f"Formato de relatório não suportado: {format}")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório: {str(e)}")
            return False
    
    def _generate_markdown_report(self, data, output_file):
        """
        Gera um relatório em formato Markdown.
        
        Args:
            data (dict): Dados para o relatório
            output_file (str): Arquivo de saída
            
        Returns:
            bool: True se o relatório foi gerado com sucesso, False caso contrário
        """
        try:
            # Verificar se existe um template para o tipo de relatório
            report_type = data.get("report_type", "general")
            template_file = os.path.join(self.template_dir, f"{report_type}_report.md.j2")
            
            if os.path.exists(template_file):
                # Usar template Jinja2
                template = self.jinja_env.get_template(f"{report_type}_report.md.j2")
                content = template.render(**data)
            else:
                # Gerar relatório genérico
                content = self._generate_generic_markdown_report(data)
            
            # Salvar relatório
            with open(output_file, "w") as f:
                f.write(content)
            
            self.logger.success(f"Relatório Markdown gerado: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório Markdown: {str(e)}")
            return False
    
    def _generate_html_report(self, data, output_file):
        """
        Gera um relatório em formato HTML.
        
        Args:
            data (dict): Dados para o relatório
            output_file (str): Arquivo de saída
            
        Returns:
            bool: True se o relatório foi gerado com sucesso, False caso contrário
        """
        try:
            # Verificar se existe um template para o tipo de relatório
            report_type = data.get("report_type", "general")
            template_file = os.path.join(self.template_dir, f"{report_type}_report.html.j2")
            
            if os.path.exists(template_file):
                # Usar template Jinja2
                template = self.jinja_env.get_template(f"{report_type}_report.html.j2")
                content = template.render(**data)
            else:
                # Gerar HTML a partir do Markdown
                md_content = self._generate_generic_markdown_report(data)
                content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
                
                # Adicionar estilos básicos
                content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>{data.get('title', 'Bug Bounty Report')}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }}
                        h1, h2, h3 {{ color: #333; }}
                        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #f2f2f2; }}
                        tr:nth-child(even) {{ background-color: #f9f9f9; }}
                        .critical {{ color: #d9534f; }}
                        .high {{ color: #f0ad4e; }}
                        .medium {{ color: #5bc0de; }}
                        .low {{ color: #5cb85c; }}
                        .info {{ color: #5bc0de; }}
                        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                        code {{ font-family: monospace; }}
                    </style>
                </head>
                <body>
                    {content}
                </body>
                </html>
                """
            
            # Salvar relatório
            with open(output_file, "w") as f:
                f.write(content)
            
            self.logger.success(f"Relatório HTML gerado: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório HTML: {str(e)}")
            return False
    
    def _generate_json_report(self, data, output_file):
        """
        Gera um relatório em formato JSON.
        
        Args:
            data (dict): Dados para o relatório
            output_file (str): Arquivo de saída
            
        Returns:
            bool: True se o relatório foi gerado com sucesso, False caso contrário
        """
        try:
            # Adicionar metadados
            report_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "Bug Bounty Python Pipeline",
                    "version": "1.0.0"
                },
                "data": data
            }
            
            # Salvar relatório
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.success(f"Relatório JSON gerado: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório JSON: {str(e)}")
            return False
    
    def _generate_generic_markdown_report(self, data):
        """
        Gera um relatório Markdown genérico.
        
        Args:
            data (dict): Dados para o relatório
            
        Returns:
            str: Conteúdo do relatório
        """
        title = data.get("title", "Bug Bounty Report")
        date = data.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        content = f"# {title}\n\n"
        content += f"Data: {date}\n\n"
        
        # Adicionar resumo
        if "summary" in data:
            content += "## Resumo\n\n"
            content += f"{data['summary']}\n\n"
        
        # Adicionar estatísticas
        if "stats" in data:
            content += "## Estatísticas\n\n"
            stats = data["stats"]
            
            content += "| Métrica | Valor |\n"
            content += "|---------|-------|\n"
            
            for key, value in stats.items():
                content += f"| {key} | {value} |\n"
            
            content += "\n"
        
        # Adicionar resultados
        if "results" in data:
            content += "## Resultados\n\n"
            
            for section, items in data["results"].items():
                content += f"### {section}\n\n"
                
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            # Formato de item detalhado
                            item_title = item.get("title", "Item")
                            content += f"#### {item_title}\n\n"
                            
                            for key, value in item.items():
                                if key != "title":
                                    content += f"- **{key}**: {value}\n"
                            
                            content += "\n"
                        else:
                            # Formato de item simples
                            content += f"- {item}\n"
                else:
                    content += f"{items}\n"
                
                content += "\n"
        
        # Adicionar vulnerabilidades
        if "vulnerabilities" in data:
            content += "## Vulnerabilidades\n\n"
            
            # Agrupar por severidade
            severity_groups = {}
            for vuln in data["vulnerabilities"]:
                severity = vuln.get("severity", "unknown").lower()
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(vuln)
            
            # Resumo por severidade
            content += "### Resumo\n\n"
            content += "| Severidade | Quantidade |\n"
            content += "|------------|------------|\n"
            
            for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
                if severity in severity_groups:
                    content += f"| {severity.capitalize()} | {len(severity_groups[severity])} |\n"
            
            content += "\n"
            
            # Detalhes por severidade
            for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
                if severity in severity_groups and severity_groups[severity]:
                    content += f"### Vulnerabilidades {severity.capitalize()}\n\n"
                    
                    for i, vuln in enumerate(severity_groups[severity]):
                        content += f"#### {i+1}. {vuln.get('name', 'Vulnerabilidade Desconhecida')}\n\n"
                        content += f"- **URL:** {vuln.get('url', 'N/A')}\n"
                        content += f"- **Tipo:** {vuln.get('type', 'N/A')}\n"
                        content += f"- **Severidade:** {vuln.get('severity', 'N/A')}\n"
                        
                        if "description" in vuln and vuln["description"]:
                            content += f"- **Descrição:** {vuln['description']}\n"
                        
                        content += "\n"
        
        # Adicionar recomendações
        if "recommendations" in data:
            content += "## Recomendações\n\n"
            
            recommendations = data["recommendations"]
            if isinstance(recommendations, list):
                for i, rec in enumerate(recommendations):
                    content += f"{i+1}. {rec}\n"
            else:
                content += recommendations
            
            content += "\n"
        
        # Adicionar conclusão
        if "conclusion" in data:
            content += "## Conclusão\n\n"
            content += f"{data['conclusion']}\n\n"
        
        return content
    
    def consolidate_reports(self, report_files, output_file, format="md"):
        """
        Consolida múltiplos relatórios em um único relatório.
        
        Args:
            report_files (list): Lista de arquivos de relatório
            output_file (str): Arquivo de saída
            format (str, optional): Formato do relatório (md, html, json)
            
        Returns:
            bool: True se o relatório foi consolidado com sucesso, False caso contrário
        """
        self.logger.info(f"Consolidando {len(report_files)} relatórios")
        
        try:
            # Dados consolidados
            consolidated_data = {
                "title": "Relatório Consolidado de Bug Bounty",
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "summary": f"Este relatório consolida os resultados de {len(report_files)} relatórios individuais.",
                "stats": {},
                "results": {},
                "vulnerabilities": [],
                "recommendations": []
            }
            
            # Processar cada relatório
            for report_file in report_files:
                if not os.path.exists(report_file):
                    self.logger.warning(f"Arquivo de relatório não encontrado: {report_file}")
                    continue
                
                # Determinar formato do relatório
                file_ext = os.path.splitext(report_file)[1].lower()
                
                if file_ext == ".json":
                    # Processar relatório JSON
                    with open(report_file, "r") as f:
                        report_data = json.load(f)
                    
                    # Extrair dados
                    if "data" in report_data:
                        report_data = report_data["data"]
                    
                    # Consolidar vulnerabilidades
                    if "vulnerabilities" in report_data:
                        consolidated_data["vulnerabilities"].extend(report_data["vulnerabilities"])
                    
                    # Consolidar recomendações
                    if "recommendations" in report_data and isinstance(report_data["recommendations"], list):
                        consolidated_data["recommendations"].extend(report_data["recommendations"])
                    
                    # Consolidar resultados
                    if "results" in report_data:
                        for section, items in report_data["results"].items():
                            if section not in consolidated_data["results"]:
                                consolidated_data["results"][section] = []
                            
                            if isinstance(items, list):
                                consolidated_data["results"][section].extend(items)
                elif file_ext == ".md":
                    # Processar relatório Markdown
                    # Extrair vulnerabilidades e recomendações é mais complexo em Markdown
                    # Aqui apenas incluímos o conteúdo como uma seção
                    with open(report_file, "r") as f:
                        md_content = f.read()
                    
                    # Extrair título do relatório
                    import re
                    title_match = re.search(r'^# (.+)$', md_content, re.MULTILINE)
                    if title_match:
                        title = title_match.group(1)
                    else:
                        title = os.path.basename(report_file)
                    
                    # Adicionar como seção
                    consolidated_data["results"][title] = md_content
            
            # Calcular estatísticas consolidadas
            vulnerability_count = len(consolidated_data["vulnerabilities"])
            
            # Contar vulnerabilidades por severidade
            severity_counts = {}
            for vuln in consolidated_data["vulnerabilities"]:
                severity = vuln.get("severity", "unknown").lower()
                if severity not in severity_counts:
                    severity_counts[severity] = 0
                severity_counts[severity] += 1
            
            # Adicionar estatísticas
            consolidated_data["stats"]["Total de relatórios"] = len(report_files)
            consolidated_data["stats"]["Total de vulnerabilidades"] = vulnerability_count
            
            for severity, count in severity_counts.items():
                consolidated_data["stats"][f"Vulnerabilidades {severity.capitalize()}"] = count
            
            # Remover duplicatas de recomendações
            consolidated_data["recommendations"] = list(set(consolidated_data["recommendations"]))
            
            # Adicionar conclusão
            consolidated_data["conclusion"] = f"Este relatório consolidado identificou um total de {vulnerability_count} vulnerabilidades em {len(report_files)} relatórios individuais."
            
            # Gerar relatório consolidado
            return self.generate_report(consolidated_data, output_file, format)
        except Exception as e:
            self.logger.error(f"Erro ao consolidar relatórios: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
