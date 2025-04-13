# 🕵️ Bug Bounty Pipeline - Python Edition

Pipeline automatizada para reconhecimento, enumeração e escaneamento de vulnerabilidades, projetada para auxiliar caçadores de bugs (bug bounty hunters) em suas atividades de análise de segurança ofensiva.

---

## ⚙️ Funcionalidades

- 🔍 Reconhecimento de subdomínios (amass, subfinder, assetfinder)
- 🌐 Enumeração de endpoints e URLs históricas (httpx, gau, katana, hakrawler)
- 📁 Descoberta de diretórios e parâmetros (ffuf, feroxbuster)
- 🚨 Escaneamento de vulnerabilidades (nuclei, sqlmap, nikto, dalfox, naabu)
- 🧪 Testes específicos (como XSRFProbe)
- 📊 Geração de relatórios em Markdown, HTML e JSON
- 🔔 Integração com sistemas de notificação (Slack, Telegram, Discord, e-mail)
- 🧵 Execução paralela com controle de threads e timeouts
- 🧪 Suporte ao modo `--scan-only` para escaneamento isolado

---

## 🏁 Como começar

### 1. Clone o repositório

```bash
git clone https://github.com/DavidJovino/bugbounty_pipeline.git
cd bugbounty_pipeline
```

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

### 3. Instale as ferramentas externas

Você pode usar:

```bash
python3 bug_bounty_pipeline.py --install
```

Ou instalar manualmente: `amass`, `subfinder`, `httpx`, `gau`, `nuclei`, etc.

---

## 🚀 Exemplos de uso

### Pipeline completa:
```bash
python3 bug_bounty_pipeline.py www.vulnweb.com
```

### Apenas enumeração:
```bash
python3 bug_bounty_pipeline.py www.vulnweb.com --enum-only bug_bounty_results/www.vulnweb.com/recon/final_subdomains.txt
```

### Apenas escaneamento:
```bash
python3 bug_bounty_pipeline.py www.vulnweb.com --scan-only bug_bounty_results/www.vulnweb.com/enum/active_endpoints.txt
```

---

## 🧠 Estrutura de pastas esperada

```
bug_bounty_results/
└── www.vulnweb.com/
    ├── recon/
    ├── enum/
    ├── scan/
    └── reports/
```

---

## 🛡️ Requisitos

- Python 3.8+
- Ferramentas externas instaladas (subfinder, httpx, nuclei etc)
- Linux ou WSL recomendado para suporte completo a ferramentas CLI

---

## 🤝 Contribuições

Contribuições são bem-vindas! Crie uma issue, fork ou abra um pull request se quiser colaborar.

---

## 📄 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

---

> Desenvolvido com dedicação por [David Jovino](https://github.com/DavidJovino)