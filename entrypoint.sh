#!/bin/bash

INPUT_FILE="/app/alvos.txt"

if [ ! -f "$INPUT_FILE" ]; then
  echo "❌ Arquivo de domínios não encontrado: $INPUT_FILE"
  exit 1
fi

echo "📄 Lendo alvos de $INPUT_FILE..."

# DEBUG: mostra conteúdo bruto do arquivo
echo "🧾 Conteúdo do alvos.txt:"
cat "$INPUT_FILE"
echo "────────────────────────────"

while IFS= read -r domain || [ -n "$domain" ]; do
  domain=$(echo "$domain" | tr -d '\r' | xargs)
  echo "🔍 DEBUG - Linha lida: '$domain'"

  [ -z "$domain" ] && echo "⚠️ Linha em branco, ignorada" && continue

  echo "▶️ Executando recon para: $domain"
  python bug_bounty_pipeline.py "$domain"
done < "$INPUT_FILE"
