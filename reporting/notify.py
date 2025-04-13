"""
Módulo de notificação para a pipeline de Bug Bounty.
Responsável por enviar notificações sobre o progresso e resultados da pipeline.
"""

import os
import sys
import json
import requests
from datetime import datetime

from core.logger import Logger

class NotifyManager:
    """
    Classe para envio de notificações sobre o progresso e resultados da pipeline.
    """
    def __init__(self, logger=None, config_file=None):
        """
        Inicializa o gerenciador de notificações.
        
        Args:
            logger (Logger, optional): Logger para registrar eventos
            config_file (str, optional): Arquivo de configuração
        """
        self.logger = logger or Logger("notify_manager")
        self.config = {}
        
        # Carregar configuração se fornecida
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        Carrega configurações de notificação de um arquivo.
        
        Args:
            config_file (str): Arquivo de configuração
            
        Returns:
            bool: True se a configuração foi carregada com sucesso, False caso contrário
        """
        try:
            with open(config_file, "r") as f:
                self.config = json.load(f)
            
            self.logger.info(f"Configurações de notificação carregadas de {config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao carregar configurações de notificação: {str(e)}")
            return False
    
    def set_config(self, config):
        """
        Define configurações de notificação.
        
        Args:
            config (dict): Configurações de notificação
        """
        self.config = config
    
    def notify(self, message, title=None, level="info", attachments=None):
        """
        Envia uma notificação.
        
        Args:
            message (str): Mensagem da notificação
            title (str, optional): Título da notificação
            level (str, optional): Nível da notificação (info, success, warning, error)
            attachments (list, optional): Lista de arquivos para anexar
            
        Returns:
            bool: True se a notificação foi enviada com sucesso, False caso contrário
        """
        if not self.config:
            self.logger.warning("Configurações de notificação não definidas")
            return False
        
        # Determinar canais de notificação
        channels = self.config.get("channels", [])
        if not channels:
            self.logger.warning("Nenhum canal de notificação configurado")
            return False
        
        # Formatar título
        if not title:
            title = f"Bug Bounty Pipeline - {level.capitalize()}"
        
        # Formatar mensagem
        formatted_message = f"**{title}**\n\n{message}\n\n*{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        # Enviar para cada canal
        success = True
        for channel in channels:
            channel_type = channel.get("type")
            if not channel_type:
                continue
            
            try:
                if channel_type == "discord":
                    result = self._notify_discord(channel, formatted_message, level, attachments)
                elif channel_type == "slack":
                    result = self._notify_slack(channel, formatted_message, level, attachments)
                elif channel_type == "telegram":
                    result = self._notify_telegram(channel, formatted_message, level, attachments)
                elif channel_type == "email":
                    result = self._notify_email(channel, formatted_message, title, level, attachments)
                else:
                    self.logger.warning(f"Tipo de canal desconhecido: {channel_type}")
                    result = False
                
                if not result:
                    success = False
            except Exception as e:
                self.logger.error(f"Erro ao enviar notificação para {channel_type}: {str(e)}")
                success = False
        
        return success
    
    def _notify_discord(self, channel_config, message, level, attachments=None):
        """
        Envia uma notificação via Discord.
        
        Args:
            channel_config (dict): Configuração do canal
            message (str): Mensagem formatada
            level (str): Nível da notificação
            attachments (list, optional): Lista de arquivos para anexar
            
        Returns:
            bool: True se a notificação foi enviada com sucesso, False caso contrário
        """
        webhook_url = channel_config.get("webhook_url")
        if not webhook_url:
            self.logger.error("URL do webhook do Discord não configurada")
            return False
        
        try:
            # Definir cor com base no nível
            color = {
                "info": 3447003,      # Azul
                "success": 5763719,   # Verde
                "warning": 16776960,  # Amarelo
                "error": 15548997     # Vermelho
            }.get(level, 3447003)
            
            # Criar payload
            payload = {
                "username": channel_config.get("username", "Bug Bounty Bot"),
                "embeds": [{
                    "description": message,
                    "color": color
                }]
            }
            
            # Enviar requisição
            response = requests.post(webhook_url, json=payload)
            
            if response.status_code == 204:
                self.logger.info("Notificação enviada com sucesso para o Discord")
                
                # Enviar anexos separadamente
                if attachments:
                    for attachment in attachments:
                        if os.path.exists(attachment):
                            files = {"file": open(attachment, "rb")}
                            response = requests.post(webhook_url, files=files)
                            files["file"].close()
                            
                            if response.status_code != 204:
                                self.logger.warning(f"Falha ao enviar anexo para o Discord: {response.status_code}")
                
                return True
            else:
                self.logger.error(f"Falha ao enviar notificação para o Discord: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação para o Discord: {str(e)}")
            return False
    
    def _notify_slack(self, channel_config, message, level, attachments=None):
        """
        Envia uma notificação via Slack.
        
        Args:
            channel_config (dict): Configuração do canal
            message (str): Mensagem formatada
            level (str): Nível da notificação
            attachments (list, optional): Lista de arquivos para anexar
            
        Returns:
            bool: True se a notificação foi enviada com sucesso, False caso contrário
        """
        webhook_url = channel_config.get("webhook_url")
        if not webhook_url:
            self.logger.error("URL do webhook do Slack não configurada")
            return False
        
        try:
            # Definir cor com base no nível
            color = {
                "info": "#3498db",    # Azul
                "success": "#2ecc71", # Verde
                "warning": "#f1c40f", # Amarelo
                "error": "#e74c3c"    # Vermelho
            }.get(level, "#3498db")
            
            # Criar payload
            payload = {
                "username": channel_config.get("username", "Bug Bounty Bot"),
                "attachments": [{
                    "text": message,
                    "color": color
                }]
            }
            
            # Enviar requisição
            response = requests.post(webhook_url, json=payload)
            
            if response.status_code == 200:
                self.logger.info("Notificação enviada com sucesso para o Slack")
                
                # Enviar anexos separadamente
                if attachments:
                    for attachment in attachments:
                        if os.path.exists(attachment):
                            files = {"file": open(attachment, "rb")}
                            data = {"token": channel_config.get("token")}
                            response = requests.post("https://slack.com/api/files.upload", files=files, data=data)
                            files["file"].close()
                            
                            if not response.json().get("ok", False):
                                self.logger.warning(f"Falha ao enviar anexo para o Slack: {response.json().get('error')}")
                
                return True
            else:
                self.logger.error(f"Falha ao enviar notificação para o Slack: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação para o Slack: {str(e)}")
            return False
    
    def _notify_telegram(self, channel_config, message, level, attachments=None):
        """
        Envia uma notificação via Telegram.
        
        Args:
            channel_config (dict): Configuração do canal
            message (str): Mensagem formatada
            level (str): Nível da notificação
            attachments (list, optional): Lista de arquivos para anexar
            
        Returns:
            bool: True se a notificação foi enviada com sucesso, False caso contrário
        """
        bot_token = channel_config.get("bot_token")
        chat_id = channel_config.get("chat_id")
        
        if not bot_token or not chat_id:
            self.logger.error("Token do bot ou ID do chat do Telegram não configurados")
            return False
        
        try:
            # Adicionar emoji com base no nível
            emoji = {
                "info": "ℹ️",
                "success": "✅",
                "warning": "⚠️",
                "error": "❌"
            }.get(level, "ℹ️")
            
            # Formatar mensagem com emoji
            formatted_message = f"{emoji} {message}"
            
            # Enviar mensagem
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": formatted_message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=payload)
            
            if response.status_code == 200:
                self.logger.info("Notificação enviada com sucesso para o Telegram")
                
                # Enviar anexos
                if attachments:
                    for attachment in attachments:
                        if not os.path.exists(attachment):
                            continue
                        
                        # Determinar tipo de arquivo
                        file_ext = os.path.splitext(attachment)[1].lower()
                        
                        if file_ext in [".jpg", ".jpeg", ".png", ".gif"]:
                            # Enviar como foto
                            url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                            files = {"photo": open(attachment, "rb")}
                            data = {"chat_id": chat_id}
                        else:
                            # Enviar como documento
                            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                            files = {"document": open(attachment, "rb")}
                            data = {"chat_id": chat_id}
                        
                        response = requests.post(url, data=data, files=files)
                        files["photo"].close() if "photo" in files else files["document"].close()
                        
                        if response.status_code != 200:
                            self.logger.warning(f"Falha ao enviar anexo para o Telegram: {response.status_code}")
                
                return True
            else:
                self.logger.error(f"Falha ao enviar notificação para o Telegram: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação para o Telegram: {str(e)}")
            return False
    
    def _notify_email(self, channel_config, message, title, level, attachments=None):
        """
        Envia uma notificação via email.
        
        Args:
            channel_config (dict): Configuração do canal
            message (str): Mensagem formatada
            title (str): Título da notificação
            level (str): Nível da notificação
            attachments (list, optional): Lista de arquivos para anexar
            
        Returns:
            bool: True se a notificação foi enviada com sucesso, False caso contrário
        """
        smtp_server = channel_config.get("smtp_server")
        smtp_port = channel_config.get("smtp_port", 587)
        smtp_username = channel_config.get("smtp_username")
        smtp_password = channel_config.get("smtp_password")
        sender = channel_config.get("sender")
        recipients = channel_config.get("recipients")
        
        if not all([smtp_server, smtp_username, smtp_password, sender, recipients]):
            self.logger.error("Configurações de email incompletas")
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.application import MIMEApplication
            
            # Criar mensagem
            msg = MIMEMultipart()
            msg["From"] = sender
            msg["To"] = ", ".join(recipients) if isinstance(recipients, list) else recipients
            msg["Subject"] = f"[{level.upper()}] {title}"
            
            # Adicionar corpo da mensagem
            msg.attach(MIMEText(message, "plain"))
            
            # Adicionar anexos
            if attachments:
                for attachment in attachments:
                    if not os.path.exists(attachment):
                        continue
                    
                    with open(attachment, "rb") as f:
                        part = MIMEApplication(f.read(), Name=os.path.basename(attachment))
                    
                    part["Content-Disposition"] = f'attachment; filename="{os.path.basename(attachment)}"'
                    msg.attach(part)
            
            # Enviar email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
            
            self.logger.info("Notificação enviada com sucesso por email")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação por email: {str(e)}")
            return False
