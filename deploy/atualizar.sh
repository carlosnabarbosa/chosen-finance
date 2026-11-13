#!/bin/sh
# Atualização automática no servidor (cron): puxa o fork e, se houver commit novo,
# reconstrói os containers. Se o app não subir, volta para a versão anterior.
set -eu
cd "$(dirname "$0")/.."
exec 9>/tmp/tesouraria-atualizar.lock
flock -n 9 || exit 0

agora() { date '+%F %T'; }
git fetch -q origin main
ANTES=$(git rev-parse HEAD)
[ "$ANTES" = "$(git rev-parse origin/main)" ] && exit 0

echo "$(agora) atualizando $(git rev-parse --short HEAD) -> $(git rev-parse --short origin/main)"
if ! git merge -q --ff-only origin/main; then
  echo "$(agora) ERRO: o servidor tem mudanças locais que divergem do fork; nada foi alterado"
  exit 1
fi

HOST=$(grep '^ALLOWED_HOSTS=' .env | cut -d= -f2 | cut -d, -f1)
no_ar() {
  i=0
  while [ $i -lt 30 ]; do
    curl -fsS -o /dev/null -H "Host: $HOST" "http://$HOST/login" && return 0
    i=$((i + 1)); sleep 2
  done
  return 1
}

if docker compose up -d --build --remove-orphans && no_ar; then
  echo "$(agora) OK: versão $(node -p 'require("./package.json").version' 2>/dev/null || grep -m1 '"version"' package.json) no ar"
  docker image prune -f >/dev/null
else
  echo "$(agora) ERRO: nova versão não subiu, voltando para $ANTES"
  git reset -q --hard "$ANTES"
  docker compose up -d --build --remove-orphans
  exit 1
fi
