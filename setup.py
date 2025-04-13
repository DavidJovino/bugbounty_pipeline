#!/usr/bin/env python3
"""
Script para instalar as dependências Python necessárias para a pipeline de Bug Bounty.
"""

import os
import sys
import subprocess
import pkg_resources

def check_python_version():
    """
    Verifica se a versão do Python é compatível.
    """
    print("Verificando versão do Python...")
    if sys.version_info < (3, 6):
        print("Erro: Python 3.6 ou superior é necessário.")
        sys.exit(1)
    print(f"OK: Python {sys.version.split()[0]} encontrado.")

def install_requirements():
    """
    Instala as dependências Python necessárias.
    """
    print("Instalando dependências Python...")
    
    # Lista de pacotes necessários
    required_packages = [
        "requests",
        "beautifulsoup4",
        "markdown",
        "jinja2"
    ]
    
    # Verificar pacotes já instalados
    installed_packages = {pkg.key for pkg in pkg_resources.working_set}
    
    # Instalar pacotes faltantes
    missing_packages = [pkg for pkg in required_packages if pkg.lower() not in installed_packages]
    
    if missing_packages:
        print(f"Instalando pacotes: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print("Pacotes instalados com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao instalar pacotes: {e}")
            sys.exit(1)
    else:
        print("Todos os pacotes já estão instalados.")

def create_requirements_file():
    """
    Cria o arquivo requirements.txt.
    """
    print("Criando arquivo requirements.txt...")
    
    requirements = """
requests>=2.25.0
beautifulsoup4>=4.9.3
markdown>=3.3.4
jinja2>=2.11.3
    """.strip()
    
    with open("requirements.txt", "w") as f:
        f.write(requirements)
    
    print("Arquivo requirements.txt criado com sucesso.")

def main():
    """
    Função principal.
    """
    print("=== Instalação de Dependências da Pipeline de Bug Bounty ===")
    
    # Verificar versão do Python
    check_python_version()
    
    # Criar arquivo requirements.txt
    create_requirements_file()
    
    # Instalar dependências
    install_requirements()
    
    print("\nInstalação concluída com sucesso!")
    print("Para verificar as ferramentas externas necessárias, execute:")
    print("  python bug_bounty_pipeline.py --check-only example.com")
    print("\nPara instalar as ferramentas externas faltantes, execute:")
    print("  python bug_bounty_pipeline.py --install example.com")

if __name__ == "__main__":
    main()
