# Imagem base leve com Python
FROM python:3.11-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/tools:${PATH}"
ENV TOOLS_DIR="/app/tools"
ENV WORDLISTS_DIR="/app/wordlists"

# Criar diretório de trabalho
WORKDIR /app

# Copiar tudo para o container
COPY . .

# Permitir execução dos binários
RUN chmod +x tools/*

# Instalar dependências
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Permitir passagem de argumentos ao script
ENTRYPOINT ["python", "bug_bounty_pipeline.py"]
