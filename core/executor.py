"""
Módulo executor para a pipeline de Bug Bounty.
Responsável por executar comandos externos com tratamento de erros e timeouts.
"""

import subprocess
import shlex
import os
import signal
import time
from threading import Timer
from config.settings import DEFAULT_TIMEOUT
from core.logger import Logger

class CommandExecutor:
    """
    Classe para execução de comandos externos com tratamento de erros e timeouts.
    """
    def __init__(self, logger=None):
        """
        Inicializa o executor de comandos.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
        """
        self.logger = logger or Logger("executor")
    
    def execute(self, command, timeout=DEFAULT_TIMEOUT, cwd=None, env=None, shell=None):
        """
        Executa um comando externo com tratamento de erros e timeout.
        
        Args:
            command (str|list): Comando a ser executado
            timeout (int, optional): Timeout em segundos
            cwd (str, optional): Diretório de trabalho
            env (dict, optional): Variáveis de ambiente
            shell (bool, optional): Força shell True/False ou auto-detecta se None
            
        Returns:
            dict: Dicionário com stdout, stderr, returncode e success
        """
        self.logger.debug(f"Preparando comando: {command}")
        
        # Preparar ambiente
        if env is None:
            env = os.environ.copy()
        
        # Auto-detectar se precisa de shell
        if shell is None:
            shell = self._requires_shell(command)
        
        # Preparar comando para shell=False
        if not shell and isinstance(command, str):
            command = shlex.split(command)
        
        self.logger.debug(f"Executando comando (shell={shell}): {command}")
        
        # Inicializar resultado
        result = {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "success": False,
            "timeout": False,
            "command": command
        }
        
        try:
            # Executar comando
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                shell=shell,
                universal_newlines=True
            )
            
            # Configurar timeout
            timer = None
            if timeout:
                def kill_process():
                    try:
                        process.kill()
                        result["timeout"] = True
                        self.logger.warning(f"Timeout excedido para comando: {command}")
                    except:
                        pass
                
                timer = Timer(timeout, kill_process)
                timer.start()
            
            # Capturar saída
            stdout, stderr = process.communicate()
            
            # Cancelar timer se ainda estiver ativo
            if timer:
                timer.cancel()
            
            # Preencher resultado
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["returncode"] = process.returncode
            result["success"] = process.returncode == 0
            
            # Registrar resultado
            if result["success"]:
                self.logger.debug(f"Comando executado com sucesso: {command}")
            else:
                self.logger.warning(f"Comando falhou com código {result['returncode']}: {command}")
                self.logger.debug(f"Stderr: {stderr}")
            
        except Exception as e:
            result["stderr"] = str(e)
            result["success"] = False
            self.logger.error(f"Erro ao executar comando {command}: {str(e)}")
        
        return result
    
    def _requires_shell(self, command):
        """
        Determina se um comando precisa ser executado em shell.
        
        Args:
            command (str|list): Comando a ser analisado
            
        Returns:
            bool: True se precisa de shell, False caso contrário
        """
        if isinstance(command, list):
            return False
        
        shell_chars = ['|', '>', '<', '&', ';', '*', '?', '~', '$']
        return any(char in command for char in shell_chars)

    def execute_with_live_output(self, command, timeout=DEFAULT_TIMEOUT, cwd=None, env=None, shell=None):
        """
        Executa um comando externo com saída em tempo real.
        
        Args:
            command (str): Comando a ser executado
            timeout (int, optional): Timeout em segundos
            cwd (str, optional): Diretório de trabalho
            env (dict, optional): Variáveis de ambiente
            shell (bool, optional): Se True, executa o comando em um shell
            
        Returns:
            dict: Dicionário com stdout, stderr, returncode e success
        """
        self.logger.debug(f"Executando comando com saída em tempo real: {command}")
        
        # Preparar ambiente
        if env is None:
            env = os.environ.copy()

        # Auto-detectar se precisa de shell
        if shell is None:
            shell = self._requires_shell(command)
        
        # Preparar comando
        if not shell and isinstance(command, str):
            command = shlex.split(command)
        
        self.logger.debug(f"Executando comando (shell={shell}): {command}")
        
        # Inicializar resultado
        result = {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "success": False,
            "timeout": False,
            "command": command
        }
        
        try:
            # Executar comando
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                shell=shell,
                universal_newlines=True,
                bufsize=1
            )
            
            # Configurar timeout
            start_time = time.time()
            
            # Capturar saída em tempo real
            stdout_lines = []
            stderr_lines = []
            
            while process.poll() is None:
                # Verificar timeout
                if timeout and time.time() - start_time > timeout:
                    process.kill()
                    result["timeout"] = True
                    self.logger.warning(f"Timeout excedido para comando: {command}")
                    break
                
                # Ler stdout
                stdout_line = process.stdout.readline()
                if stdout_line:
                    stdout_lines.append(stdout_line)
                    print(stdout_line, end="")
                
                # Ler stderr
                stderr_line = process.stderr.readline()
                if stderr_line:
                    stderr_lines.append(stderr_line)
                    print(stderr_line, end="")
                
                # Pequena pausa para evitar uso excessivo de CPU
                time.sleep(0.01)
            
            # Capturar saída restante
            stdout, stderr = process.communicate()
            if stdout:
                stdout_lines.append(stdout)
                print(stdout, end="")
            if stderr:
                stderr_lines.append(stderr)
                print(stderr, end="")
            
            # Preencher resultado
            result["stdout"] = "".join(stdout_lines)
            result["stderr"] = "".join(stderr_lines)
            result["returncode"] = process.returncode
            result["success"] = process.returncode == 0
            
            # Registrar resultado
            if result["success"]:
                self.logger.debug(f"Comando executado com sucesso: {command}")
            else:
                self.logger.warning(f"Comando falhou com código {result['returncode']}: {command}")
            
        except Exception as e:
            result["stderr"] = str(e)
            result["success"] = False
            self.logger.error(f"Erro ao executar comando {command}: {str(e)}")
        
        return result
    
    def check_command_exists(self, command):
        """
        Verifica se um comando existe no sistema.
        
        Args:
            command (str): Comando a ser verificado
            
        Returns:
            bool: True se o comando existe, False caso contrário
        """
        try:
            result = self.execute(f"which {command}", timeout=5)
            return result["success"] and result["stdout"].strip() != ""
        except:
            return False
