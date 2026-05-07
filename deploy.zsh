#!/usr/bin/env zsh
# Deploy capitan-oauth a Cloud Run.
# Requiere un .env local (no versionado) con las variables sensibles.
# Ver .env.example para la lista completa.

set -euo pipefail

SCRIPT_DIR="${0:A:h}"
ENV_FILE="$SCRIPT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE no encontrado. Copiá .env.example y completalo." >&2
  exit 1
fi

# Cargar variables del .env (ignorar comentarios y líneas vacías)
while IFS='=' read -r key value; do
  [[ "$key" =~ '^[[:space:]]*#' || -z "$key" ]] && continue
  key="${key## }"
  key="${key%% }"
  export "$key"="$value"
done < "$ENV_FILE"

# Construir el string de env vars para Cloud Run
ENV_VARS=(
  "ML_CLIENT_ID=${ML_CLIENT_ID:?}"
  "ML_CLIENT_SECRET=${ML_CLIENT_SECRET:?}"
  "ML_REDIRECT_URI=${ML_REDIRECT_URI:?}"
  "MP_CLIENT_ID=${MP_CLIENT_ID:-}"
  "MP_CLIENT_SECRET=${MP_CLIENT_SECRET:-}"
  "MP_REDIRECT_URI=${MP_REDIRECT_URI:-}"
  "WA_ACCESS_TOKEN=${WA_ACCESS_TOKEN:?}"
  "WA_PHONE_NUMBER_ID=${WA_PHONE_NUMBER_ID:?}"
  "BOT_WA_PHONE=${BOT_WA_PHONE:?}"
  "STATE_TTL=${STATE_TTL:-600}"
  "TOKEN_TTL=${TOKEN_TTL:-300}"
)

gcloud run deploy capitan-oauth \
  --source "$SCRIPT_DIR" \
  --region us-east1 \
  --allow-unauthenticated \
  --set-env-vars "$(IFS=','; echo "${ENV_VARS[*]}")"
