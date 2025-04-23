"""
Módulo de instalação de ferramentas para a pipeline de Bug Bounty.
Responsável por instalar e configurar as ferramentas necessárias.
"""

import os
import sys
import time
import json
import shutil
import tempfile
import platform
from pathlib import Path
from datetime import datetime

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from config.tools import TOOLS, SYSTEM_DEPENDENCIES, PYTHON_DEPENDENCIES
from config.settings import DIRECTORIES

class ToolInstaller:
    """
    Classe para instalação e configuração de ferramentas.
    """
    def __init__(self, logger=None):
        """
        Inicializa o instalador de ferramentas.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
        """
        self.logger = logger or Logger("installer")
        self.executor = CommandExecutor(self.logger)
        self.tool_checker = ToolChecker(self.logger)
        
        # Diretório de ferramentas
        self.tools_dir = DIRECTORIES["tools"]
        os.makedirs(self.tools_dir, exist_ok=True)
        
        # Diretório temporário
        self.temp_dir = tempfile.mkdtemp()
        
        # Verificar sistema operacional
        self.os_type = platform.system().lower()
        self.is_debian = False
        
        if self.os_type == "linux":
            # Verificar se é baseado em Debian
            if os.path.exists("/etc/debian_version"):
                self.is_debian = True
    
    def install_tools(self, tools_list=None):
        """
        Instala as ferramentas especificadas.
        
        Args:
            tools_list (list, optional): Lista de ferramentas para instalar. Se None, instala todas as ferramentas faltantes.
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info("Iniciando instalação de ferramentas")
        
        # Se nenhuma lista for fornecida, verificar todas as ferramentas
        if tools_list is None:
            all_tools_status = self.tool_checker.check_all_tools()
            tools_list = []
            
            for module_tools in all_tools_status.values():
                tools_list.extend(module_tools["missing"])
            
            # Remover duplicatas
            tools_list = list(set(tools_list))
        
        if not tools_list:
            self.logger.success("Todas as ferramentas já estão instaladas")
            return True
        
        self.logger.info(f"Ferramentas a serem instaladas: {', '.join(tools_list)}")
        
        # Instalar dependências do sistema
        self._install_system_dependencies()
        
        # Instalar dependências Python
        self._install_python_dependencies()
        
        # Instalar cada ferramenta
        success_count = 0
        for tool_name in tools_list:
            if tool_name not in TOOLS:
                self.logger.warning(f"Ferramenta desconhecida: {tool_name}")
                continue
            
            tool_info = TOOLS[tool_name]
            
            # Verificar se a ferramenta já está instalada
            if self.tool_checker.check_tool(tool_name):
                self.logger.info(f"Ferramenta {tool_name} já está instalada")
                success_count += 1
                continue
            
            # Instalar ferramenta
            self.logger.step(f"Instalando {tool_name}")
            
            install_method = tool_info.get("install_method", "")
            
            if install_method == "go":
                success = self._install_go_tool(tool_name, tool_info)
            elif install_method == "pip":
                success = self._install_pip_tool(tool_name, tool_info)
            elif install_method == "apt":
                success = self._install_apt_tool(tool_name, tool_info)
            elif install_method == "git":
                success = self._install_git_tool(tool_name, tool_info)
            elif install_method == "curl":
                success = self._install_curl_tool(tool_name, tool_info)
            elif install_method == "internal":
                # Ferramentas internas não precisam ser instaladas
                success = True
            else:
                self.logger.warning(f"Método de instalação desconhecido para {tool_name}: {install_method}")
                success = False
            
            if success:
                self.logger.success(f"Ferramenta {tool_name} instalada com sucesso")
                success_count += 1
            else:
                self.logger.error(f"Falha ao instalar ferramenta {tool_name}")
        
        # Limpar diretório temporário
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Verificar resultado
        if success_count == len(tools_list):
            self.logger.success(f"Todas as {success_count} ferramentas foram instaladas com sucesso")
            return True
        else:
            self.logger.warning(f"Instaladas {success_count} de {len(tools_list)} ferramentas")
            return False
    
    def _install_system_dependencies(self):
        """
        Instala as dependências do sistema.
        
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.step("Instalando dependências do sistema")
        
        if not self.is_debian:
            self.logger.warning("Instalação automática de dependências do sistema só é suportada em sistemas baseados em Debian")
            return False
        
        # Atualizar repositórios
        self.logger.info("Atualizando repositórios")
        command = "apt-get update -y"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao atualizar repositórios: {result['stderr']}")
            return False
        
        # Instalar dependências
        dependencies = SYSTEM_DEPENDENCIES.get("apt", [])
        
        if not dependencies:
            self.logger.warning("Nenhuma dependência do sistema definida")
            return True
        
        self.logger.info(f"Instalando dependências: {', '.join(dependencies)}")
        command = f"apt-get install -y {' '.join(dependencies)}"
        result = self.executor.execute(command, timeout=600, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar dependências do sistema: {result['stderr']}")
            return False
        
        self.logger.success("Dependências do sistema instaladas com sucesso")
        return True
    
    def _install_python_dependencies(self):
        """
        Instala as dependências Python.
        
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.step("Instalando dependências Python")
        
        if not PYTHON_DEPENDENCIES:
            self.logger.warning("Nenhuma dependência Python definida")
            return True
        
        # Atualizar pip
        self.logger.info("Atualizando pip")
        command = "pip3 install --upgrade pip"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao atualizar pip: {result['stderr']}")
            return False
        
        # Instalar dependências
        self.logger.info(f"Instalando dependências Python: {', '.join(PYTHON_DEPENDENCIES)}")
        command = f"pip3 install {' '.join(PYTHON_DEPENDENCIES)}"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar dependências Python: {result['stderr']}")
            return False
        
        self.logger.success("Dependências Python instaladas com sucesso")
        return True
    
    def _install_go_tool(self, tool_name, tool_info):
        """
        Instala uma ferramenta usando Go.
        
        Args:
            tool_name (str): Nome da ferramenta
            tool_info (dict): Informações da ferramenta
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info(f"Instalando {tool_name} via Go")
        
        # Verificar se Go está instalado
        if not self.executor.check_command_exists("go"):
            self.logger.error("Go não está instalado")
            return False
        
        # Obter pacote
        package = tool_info.get("package", "")
        if not package:
            self.logger.error(f"Pacote Go não definido para {tool_name}")
            return False
        
        # Instalar ferramenta com GOBIN=/app/tools
        env = os.environ.copy()
        env["GOBIN"] = self.tools_dir
        command = f"go install {package}@latest"
        result = self.executor.execute(command, timeout=300, shell=True, env=env)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar {tool_name} via Go: {result['stderr']}")
            return False
        
        # Verificar se a ferramenta foi instalada no diretório esperado
        tool_path = os.path.join(self.tools_dir, tool_info["command"])
        if not os.path.exists(tool_path):
            self.logger.error(f"Ferramenta {tool_name} não encontrada em {tool_path}")
            return False
        
        return True
    
    def _install_pip_tool(self, tool_name, tool_info):
        """
        Instala uma ferramenta usando pip.
        
        Args:
            tool_name (str): Nome da ferramenta
            tool_info (dict): Informações da ferramenta
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info(f"Instalando {tool_name} via pip")
        
        # Verificar se pip está instalado
        if not self.executor.check_command_exists("pip3"):
            self.logger.error("pip3 não está instalado")
            return False
        
        # Obter pacote
        package = tool_info.get("package", tool_name)
        
        # Instalar ferramenta
        command = f"pip3 install {package}"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar {tool_name} via pip: {result['stderr']}")
            return False
        
        # Verificar se a ferramenta foi instalada
        if not self.tool_checker.check_tool(tool_name):
            self.logger.error(f"Ferramenta {tool_name} não foi instalada corretamente")
            return False
        
        return True
    
    def _install_apt_tool(self, tool_name, tool_info):
        """
        Instala uma ferramenta usando apt.
        
        Args:
            tool_name (str): Nome da ferramenta
            tool_info (dict): Informações da ferramenta
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info(f"Instalando {tool_name} via apt")
        
        if not self.is_debian:
            self.logger.error("Instalação via apt só é suportada em sistemas baseados em Debian")
            return False
        
        # Obter pacote
        package = tool_info.get("package", tool_name)
        
        # Instalar ferramenta
        command = f"apt-get install -y {package}"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar {tool_name} via apt: {result['stderr']}")
            return False
        
        # Verificar se a ferramenta foi instalada
        if not self.tool_checker.check_tool(tool_name):
            self.logger.error(f"Ferramenta {tool_name} não foi instalada corretamente")
            return False
        
        return True
    
    def _install_git_tool(self, tool_name, tool_info):
        """
        Instala uma ferramenta usando git.
        
        Args:
            tool_name (str): Nome da ferramenta
            tool_info (dict): Informações da ferramenta
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info(f"Instalando {tool_name} via git")
        
        # Verificar se git está instalado
        if not self.executor.check_command_exists("git"):
            self.logger.error("git não está instalado")
            return False
        
        # Obter comando de instalação
        install_command = tool_info.get("install_command", "")
        if not install_command:
            self.logger.error(f"Comando de instalação não definido para {tool_name}")
            return False
        
        # Executar comando de instalação
        result = self.executor.execute(install_command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar {tool_name} via git: {result['stderr']}")
            return False
        
        # Configurar ferramenta se necessário
        if tool_name == "xxeinjector":
            return self._configure_xxeinjector()
        
        # Verificar se a ferramenta foi instalada
        if not self.tool_checker.check_tool(tool_name):
            self.logger.error(f"Ferramenta {tool_name} não foi instalada corretamente")
            return False
        
        return True
    
    def _install_curl_tool(self, tool_name, tool_info):
        """
        Instala uma ferramenta usando curl.
        
        Args:
            tool_name (str): Nome da ferramenta
            tool_info (dict): Informações da ferramenta
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        self.logger.info(f"Instalando {tool_name} via curl")
        
        # Verificar se curl está instalado
        if not self.executor.check_command_exists("curl"):
            self.logger.error("curl não está instalado")
            return False
        
        # Obter comando de instalação
        install_command = tool_info.get("install_command", "")
        if not install_command:
            self.logger.error(f"Comando de instalação não definido para {tool_name}")
            return False
        
        # Executar comando de instalação
        result = self.executor.execute(install_command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar {tool_name} via curl: {result['stderr']}")
            return False
        
        # Verificar se a ferramenta foi instalada
        if not self.tool_checker.check_tool(tool_name):
            self.logger.error(f"Ferramenta {tool_name} não foi instalada corretamente")
            return False
        
        return True
    
    def _configure_xxeinjector(self):
        """
        Configura o XXEinjector após a instalação.
        
        Returns:
            bool: True se a configuração foi bem-sucedida, False caso contrário
        """
        self.logger.info("Configurando XXEinjector")
        
        # Verificar se o diretório do XXEinjector existe
        xxe_dir = os.path.expanduser("~/tools/XXEinjector")
        if not os.path.exists(xxe_dir):
            self.logger.error(f"Diretório do XXEinjector não encontrado: {xxe_dir}")
            return False
        
        # Verificar se o arquivo Ruby existe
        xxe_file = os.path.join(xxe_dir, "XXEinjector.rb")
        if not os.path.exists(xxe_file):
            self.logger.error(f"Arquivo XXEinjector.rb não encontrado: {xxe_file}")
            return False
        
        # Verificar se Ruby está instalado
        if not self.executor.check_command_exists("ruby"):
            self.logger.error("Ruby não está instalado")
            return False
        
        # Instalar dependências do Ruby
        self.logger.info("Instalando dependências do Ruby para XXEinjector")
        command = "gem install nokogiri"
        result = self.executor.execute(command, timeout=300, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao instalar dependências do Ruby para XXEinjector: {result['stderr']}")
            return False
        
        # Tornar o arquivo executável
        command = f"chmod +x {xxe_file}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao tornar XXEinjector.rb executável: {result['stderr']}")
            return False
        
        # Criar link simbólico para o diretório bin
        bin_dir = os.path.expanduser("~/.local/bin")
        os.makedirs(bin_dir, exist_ok=True)
        
        xxe_link = os.path.join(bin_dir, "xxeinjector")
        if os.path.exists(xxe_link):
            os.remove(xxe_link)
        
        command = f"ln -s {xxe_file} {xxe_link}"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao criar link simbólico para XXEinjector: {result['stderr']}")
            return False
        
        # Adicionar diretório bin ao PATH se necessário
        if bin_dir not in os.environ["PATH"]:
            self.logger.info(f"Adicionando {bin_dir} ao PATH")
            
            # Adicionar ao .bashrc
            bashrc_file = os.path.expanduser("~/.bashrc")
            with open(bashrc_file, "a") as f:
                f.write(f'\n# Adicionado pela pipeline de Bug Bounty\nexport PATH="{bin_dir}:$PATH"\n')
            
            # Atualizar PATH atual
            os.environ["PATH"] = f"{bin_dir}:{os.environ['PATH']}"
        
        # Verificar se a ferramenta está funcionando
        command = "ruby ~/tools/XXEinjector/XXEinjector.rb --help"
        result = self.executor.execute(command, timeout=10, shell=True)
        
        if not result["success"]:
            self.logger.error(f"Falha ao executar XXEinjector: {result['stderr']}")
            return False
        
        self.logger.success("XXEinjector configurado com sucesso")
        return True
