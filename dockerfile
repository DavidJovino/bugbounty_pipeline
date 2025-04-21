FROM python:3.11-slim

# Variáveis de ambiente para Python e ferramentas
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/tools:$PATH"
ENV TOOLS_DIR="/app/tools"
ENV WORDLISTS_DIR="/app/wordlists"
ENV DEBIAN_FRONTEND=noninteractive

# Define o diretório de trabalho dentro do container
WORKDIR /app
COPY . .

# Instala dependências do sistema
RUN apt update && apt install -y \
    curl git wget unzip jq ruby ruby-dev build-essential python3-pip libpcap-dev

# Instala Go 1.22.3 (necessário para ferramentas mais recentes)
ENV GOLANG_VERSION=1.22.3
RUN curl -LO https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

# Cria a pasta de ferramentas
RUN mkdir -p /app/tools && chmod -R 777 /app/tools

# Instala dependências Python da pipeline
RUN pip install --upgrade pip && pip install -r requirements.txt

# Garante que `python` aponte para `python3`
RUN ln -sf /usr/local/bin/python3 /usr/local/bin/python

# Instala xsrfprobe para testes de CSRF
RUN pip install xsrfprobe

# Clona sqlmap e xsstrike
RUN git clone https://github.com/sqlmapproject/sqlmap.git /app/tools/sqlmap && \
    ln -s /app/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap && chmod +x /usr/local/bin/sqlmap && \
    git clone https://github.com/s0md3v/XSStrike.git /app/tools/XSStrike && \
    pip install -r /app/tools/XSStrike/requirements.txt && \
    chmod +x /app/tools/XSStrike/xsstrike.py && \
    ln -s /app/tools/XSStrike/xsstrike.py /usr/local/bin/xsstrike && chmod +x /usr/local/bin/xsstrike

# Instala feroxbuster
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /app/tools

# Instala amass (via binário)
RUN curl -L https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -o amass.zip && \
    unzip amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_Linux_amd64/amass /app/tools/amass && \
    chmod +x /app/tools/amass && \
    rm -rf amass.zip /tmp/amass

# Instala nikto
RUN git clone https://github.com/sullo/nikto.git /app/tools/nikto && \
    chmod +x /app/tools/nikto/program/nikto.pl && \
    ln -s /app/tools/nikto/program/nikto.pl /usr/local/bin/nikto && chmod +x /usr/local/bin/nikto

# Baixa wordlists da SecLists
RUN git clone --depth=1 https://github.com/danielmiessler/SecLists.git /app/wordlists


# Copia o entrypoint personalizado
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Instala ferramentas Go (em /app/tools)
RUN GOBIN=/app/tools go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/app/tools go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/app/tools go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    GOBIN=/app/tools go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=/app/tools go install github.com/tomnomnom/assetfinder@latest && \
    GOBIN=/app/tools go install github.com/tomnomnom/anew@latest && \
    GOBIN=/app/tools go install github.com/tomnomnom/waybackurls@latest && \
    GOBIN=/app/tools go install github.com/lc/gau/v2/cmd/gau@latest && \
    GOBIN=/app/tools go install github.com/hakluke/hakrawler@latest && \
    GOBIN=/app/tools go install github.com/ffuf/ffuf@latest && \
    GOBIN=/app/tools go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    GOBIN=/app/tools go install github.com/hahwul/dalfox/v2@latest && \
    GOBIN=/app/tools go install github.com/tomnomnom/unfurl@latest

# Usa o script de entrada que executa para cada domínio listado em alvos.txt
ENTRYPOINT ["/app/entrypoint.sh"]
