FROM python:3.11-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/tools:$PATH" \
    TOOLS_DIR="/app/tools" \
    WORDLISTS_DIR="/app/wordlists" \
    DEBIAN_FRONTEND=noninteractive \
    GOPATH=/go \
    GOLANG_VERSION=1.22.3

WORKDIR /app

RUN mkdir -p /app && chmod -R 777 /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
COPY . .

# Instala dependências do sistema
RUN apt update && apt install -y --no-install-recommends \
    curl git wget unzip jq ruby ruby-dev build-essential \
    python3-pip libpcap-dev libssl-dev zlib1g-dev && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Instala Go
RUN curl -LO https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

# Cria estrutura de diretórios
RUN mkdir -p ${TOOLS_DIR} ${WORDLISTS_DIR} && \
    chmod -R 777 ${TOOLS_DIR}

# Instala dependências Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python

# Instala ferramentas Python
RUN pip install --no-cache-dir xsrfprobe

# Instala sqlmap e XSStrike
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ${TOOLS_DIR}/sqlmap && \
    ln -s ${TOOLS_DIR}/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap && \
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git ${TOOLS_DIR}/XSStrike && \
    pip install --no-cache-dir -r ${TOOLS_DIR}/XSStrike/requirements.txt && \
    chmod +x ${TOOLS_DIR}/XSStrike/xsstrike.py && \
    ln -s ${TOOLS_DIR}/XSStrike/xsstrike.py /usr/local/bin/xsstrike

# Instala ferramentas binárias
ENV SKIP_FONTS=1
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s ${TOOLS_DIR} && \
    curl -L https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -o amass.zip && \
    unzip amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_*_amd64/amass ${TOOLS_DIR}/amass && \
    chmod +x ${TOOLS_DIR}/amass && \
    rm -rf amass.zip /tmp/amass

# Instala Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git ${TOOLS_DIR}/nikto && \
    chmod +x ${TOOLS_DIR}/nikto/program/nikto.pl && \
    ln -s ${TOOLS_DIR}/nikto/program/nikto.pl /usr/local/bin/nikto

# Baixa wordlists
RUN git clone --depth=1 https://github.com/danielmiessler/SecLists.git ${WORDLISTS_DIR}

# Instala ferramentas Go (incluindo Nuclei com templates)
RUN GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/assetfinder@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/anew@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/waybackurls@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/lc/gau/v2/cmd/gau@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/hakluke/hakrawler@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/ffuf/ffuf@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/hahwul/dalfox/v2@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/unfurl@latest && \
    # Baixa templates do Nuclei
    nuclei -update-templates && \
    # Limpa cache do Go
    go clean -cache -modcache

# Configura entrypoint
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]