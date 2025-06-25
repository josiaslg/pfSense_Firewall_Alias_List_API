# pfSense_Firewall_Alias_List_API
The objective is create a API for add and remove IPs from the black list. A agent in the other side can operate this list. The agent can be general and monitor Windows login operations (failures), IIS, nginx and others services. In Linux/BSD/OmniOS can monitor ssh, nextcloud and other services. The api is open to all kind of agents. 
# pfSense Firewall Alias List API

A **minimal, self‑contained HTTP/JSON API** that lets external agents add, remove, or list single‑host blocks inside one pfSense alias.

* **IPv4 hosts** are stored as `/32`
* **IPv6 hosts** are stored as `/128`
* Duplicate requests return \`\` without touching the list.
* If the alias is missing the API **auto‑creates** it on the very first request.
* Every change is written to `/conf/config.xml`, both cache files (`/tmp/config.cache` & `config.cache.lock`) are purged, and `/rc.filter_configure_sync` reloads tables so blocks take effect instantly.

---

## 1  Requirements

| Item    | Version             | Notes                   |
| ------- | ------------------- | ----------------------- |
| pfSense | ≥ 2.7.x             | Tested on 2.7.2‑RELEASE |
| PHP     | ≥ 8.2               | Stock on pfSense 2.7.x  |
| curl    | /usr/local/bin/curl | Path on pfSense         |

---

## 2  Quick install

```sh
fetch https://raw.githubusercontent.com/josiaslg/pfSense_Firewall_Alias_List_API/main/pfSense_Firewall_Alias_List_API_install.sh
sh pfSense_Firewall_Alias_List_API_install.sh
```

The installer will:

1. Download \`\` to `/usr/local/www/`.
2. Create `/usr/local/agent_apikey/` plus a random API key (if missing).
3. Detect the WebGUI HTTPS port and perform a first `action=list`, which auto‑creates an empty alias.
4. Print the key so you can paste it into your automations.

Keep the key safe – it is the only credential required for the API.

---

## 3  Manual installation

1. Copy `agents_alias_api.php` to `/usr/local/www/` and `chmod 600`.
2. **Generate an API key** exactly as the installer does:

   ```sh
   mkdir -p /usr/local/agent_apikey
   openssl rand -base64 32 > /usr/local/agent_apikey/api_key.txt
   chmod 600 /usr/local/agent_apikey/api_key.txt
   ```
3. Bootstrap the alias with a single curl call (no IP required):

   ```sh
   /usr/local/bin/curl -k -H "Authorization: Bearer $(cat /usr/local/agent_apikey/api_key.txt)" \
     "https://127.0.0.1:<WEBGUI_PORT>/agents_alias_api.php?action=list"
   ```

   Replace `<WEBGUI_PORT>` with the port shown in *System ▸ Advanced ▸ Admin Access* (default 443, e.g. 49476 on pfSense Plus).

---

## 4  Usage examples

Replace `YOUR_TOKEN_HERE` with the key you generated.

### FreeBSD shell (single lines)

```sh
# Add IPv4
curl -k -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     "https://127.0.0.1:<WEBGUI_PORT>/agents_alias_api.php?action=add&ip=198.51.100.77"
# Add IPv6
curl -k -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     "https://127.0.0.1:<WEBGUI_PORT>/agents_alias_api.php?action=add&ip=2001:db8::feed"
# List
curl -k -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     "https://127.0.0.1:<WEBGUI_PORT>/agents_alias_api.php?action=list"
# Delete
curl -k -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     "https://127.0.0.1:<WEBGUI_PORT>/agents_alias_api.php?action=del&ip=198.51.100.77"
```

### Windows CMD (one‑liners)

```cmd
curl -k -H "Authorization: Bearer YOUR_TOKEN_HERE" "https://firewall:<WEBGUI_PORT>/agents_alias_api.php?action=add&ip=2001:db8::feed"
```

---

## 5  Adding the block rule in pfSense

1. **Firewall ▸ Aliases ▸ +Add**

   * **Type**: *Network*
   * **Name**: *Agents_IP_Block_List*
   * Leave *Network(s)* empty (API manages it).
   * Save ➜ Apply.
2. **Firewall ▸ Rules ▸ WAN (or the interface you protect)**

   * +Add rule **at the very top** (pfSense is top‑down).
   * **Action**: *Block*
   * **Protocol**: *Any*
   * **Source**: *Alias* → *Agents_IP_Block_List*
   * **Destination**: *Any*
   * Save ➜ Apply Changes.

---

\## 6  API responses

| Field   | Meaning                             |
| ------- | ----------------------------------- |
| alias   | Always `Agents_IP_Block_List`       |
| count   | Hosts stored after the operation    |
| status  | `ok` · `exists` · `bad action` …    |
| message | Present only when `status = exists` |

---

## 7  Troubleshooting

* **401 / 403** – check the Bearer token.
* **500** – enable *System ▸ Advanced ▸ Admin Access ▸ Enable debug* and tail `/tmp/agents_api_error.log`.
* Alias not in GUI? – reload page (`Ctrl+F5`). The script purges the cache, but browsers may reuse old HTML.


\## 8  License

BSD 3‑Clause.
