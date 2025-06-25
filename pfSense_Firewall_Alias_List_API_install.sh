#!/bin/sh
# update_alias_api.sh — automated installer / updater + alias bootstrap
# Repository : https://github.com/josiaslg/pfSense_Firewall_Alias_List_API
# Author     : Josias L. Gonçalves
# Email      : josiaslg@bsd.com.br and josiaslh@cloudunix.com.br
# License    : BSD-3-Clause

set -e

RAW_BASE="https://raw.githubusercontent.com/josiaslg/pfSense_Firewall_Alias_List_API/main"
FILE="agents_alias_api.php"
DEST="/usr/local/www/${FILE}"
KEYDIR="/usr/local/agent_apikey"
KEYFILE="${KEYDIR}/api_key.txt"
CURL="/usr/local/bin/curl"          # correct path on pfSense

echo "⏬  Downloading ${FILE} from GitHub …"
fetch -o "${DEST}" "${RAW_BASE}/${FILE}?$(date +%s)"   # cache-buster

echo "🔒  Setting perms on PHP file …"
chown root:wheel "${DEST}"
chmod 600       "${DEST}"

echo "📂  Ensuring key directory …"
mkdir -p "${KEYDIR}"
chown root:wheel "${KEYDIR}"
chmod 700       "${KEYDIR}"

if [ ! -f "${KEYFILE}" ]; then
    echo "🔑  Generating new API key …"
    /usr/bin/openssl rand -base64 32 > "${KEYFILE}"
fi
chmod 600 "${KEYFILE}"
API_KEY=$(cat "${KEYFILE}")

##########################################################################
#  Self-test / bootstrap: ensure the alias exists                        #
##########################################################################

PORT=$(awk '/listen [0-9]+ ssl/{print $2; exit}' /var/etc/nginx-webConfigurator.conf | tr -d ';')
if [ -n "${PORT}" ]; then
    echo "🔍  WebGUI HTTPS port detected: ${PORT}"
    LIST_JSON=$(${CURL} -sk \
      -H "Authorization: Bearer ${API_KEY}" \
      "https://127.0.0.1:${PORT}/${FILE}?action=list")

    if echo "${LIST_JSON}" | grep -q '"entries"'; then
        echo "✅  Alias already present."
    else
        echo "➕  Creating empty alias (first run) …"
        ${CURL} -sk -o /dev/null \
          -H "Authorization: Bearer ${API_KEY}" \
          "https://127.0.0.1:${PORT}/${FILE}?action=list"
    fi
else
    echo "⚠️   Could not detect WebGUI port – skipped bootstrap."
fi

echo "✅  Installation finished. Your API key is:"
echo "${API_KEY}"
