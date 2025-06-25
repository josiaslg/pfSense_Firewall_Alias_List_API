<?php
/**
 * Agents Alias API — IPv4 (/32) & IPv6 (/128)
 * ---------------------------------------------------------------------------
 * Author   : Josias L. Gonçalves  ·  josiaslg@bsd.com.br | josiaslg@cloudunix.com.br
 * License  : BSD-3-Clause
 * Updated  : 25-Jun-2025 00:35 BRT
 *
 * WHAT IT DOES
 * ------------
 * • Exposes a tiny HTTP/JSON API (served by pfSense’s PHP-FPM) to manage a
 *   single firewall alias called “Agents_IP_Block_List”.
 * • Supports three actions:  list  ·  add  ·  del
 * • Accepts both IPv4 hosts (forced to /32) and IPv6 hosts (forced to /128).
 * • Prevents duplicates: if you try to add an IP that is already present,
 *   the API replies with status **"exists"** and does not touch the alias.
 * • Persists changes to /conf/config.xml, purges /tmp/config.cache so the
 *   WebGUI reflects the edit instantly, and calls /rc.filter_configure_sync
 *   to reload tables without rebooting any service.
 *
 * SECURITY
 * --------
 * • Access is protected by a Bearer token stored in
 *   /usr/local/agent_apikey/api_key.txt  (600, root:wheel).
 * • All responses are JSON.  Typical replies:
 *
 *   { "alias":"Agents_IP_Block_List","count":4,"status":"ok" }
 *   { "alias":"Agents_IP_Block_List","count":4,"status":"exists",
 *     "message":"IP 2001:db8::feed/128 is already present" }
 *
 * USAGE EXAMPLE (single-line cURL)
 * --------------------------------
 * curl -k -H "Authorization: Bearer <TOKEN>" \
 *      "https://firewall/agents_alias_api.php?action=add&ip=2001:db8::feed" OR
 *      "https://firewall:PORT/agents_alias_api.php?action=add&ip=2001:db8::feed" OR
 * Dont check the SSL, because when you use IP the cert will be only invalid. 
 * But if you want to make it secure, export the certificate from pfsense (used by webconfigurator)
 * and import in yout agent, using DNS to validate the SSL. If you use certbot, it´s ok too.  
 */

declare(strict_types=1);

const CONFIG_PATH = '/conf/config.xml';
const APIKEY_PATH = '/usr/local/agent_apikey/api_key.txt';
const ALIAS_NAME  = 'Agents_IP_Block_List';
const ERRLOG      = '/tmp/agents_api_error.log';

/* ---------- Private error log (writable by www) ------------------------ */
if (!file_exists(ERRLOG)) { touch(ERRLOG); chmod(ERRLOG, 0666); }
ini_set('log_errors', '1');
ini_set('error_log',  ERRLOG);
ini_set('display_errors', '0');

/* ---------- Key existence & perms ------------------------------------- */
$dir = dirname(APIKEY_PATH);
if (!is_dir($dir)) mkdir($dir, 0700, true);
if (!file_exists(APIKEY_PATH)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo '{"error":"API key missing"}';
    exit;
}
chmod(APIKEY_PATH, 0600);

/* ---------- Bearer-token authentication ------------------------------- */
$hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/Bearer\s+(\S+)/', $hdr, $m)) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo '{"error":"Missing token"}';
    exit;
}
if (!hash_equals(trim(file_get_contents(APIKEY_PATH)), trim($m[1]))) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo '{"error":"Bad token"}';
    exit;
}

/* ---------- Always JSON ----------------------------------------------- */
header('Content-Type: application/json');

/* ---------- Parameters ------------------------------------------------- */
$action = $_GET['action'] ?? 'list';   // list | add | del
$ipRaw  = $_GET['ip']     ?? '';
$tsRaw  = $_GET['ts']     ?? '';

/* ---------- Load XML and locate alias --------------------------------- */
$xml = new SimpleXMLElement(file_get_contents(CONFIG_PATH));
$aliases = $xml->aliases ?: null;
if (!$aliases) { http_response_code(500); echo '{"error":"No <aliases>"}'; exit; }

$alias = null;
foreach ($aliases->alias as $a) {
    if ((string)$a->name === ALIAS_NAME) { $alias = $a; break; }
}
if (!$alias) { http_response_code(404); echo '{"error":"Alias not found"}'; exit; }

/* ---------- Split address & detail arrays ----------------------------- */
$addr       = array_filter(preg_split('/\s+/', (string)$alias->address));
$detailNode = $alias->detail ?? $alias->addChild('detail', '');
$det        = array_filter(preg_split('/\s+/', (string)$detailNode));
while (count($det) < count($addr)) $det[] = '-';
while (count($det) > count($addr)) array_pop($det);

/* ---------- LIST ------------------------------------------------------ */
if ($action === 'list') {
    $out=[]; foreach ($addr as $i=>$ip) $out[] = ['ip'=>$ip,'ts'=>$det[$i]??''];
    echo json_encode(['alias'=>ALIAS_NAME,'entries'=>$out], JSON_PRETTY_PRINT);
    exit;
}

/* ---------- Validate IP ------------------------------------------------ */
if ($ipRaw===''){ http_response_code(400); echo '{"error":"ip param required"}'; exit; }
[$ip] = explode('/', $ipRaw, 2);

$ipVersion = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 :
             (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 6 : 0);
if ($ipVersion === 0) { http_response_code(422); echo '{"error":"invalid IP"}'; exit; }

$entry = $ipVersion === 4 ? $ip.'/32' : $ip.'/128';
$stamp = $tsRaw ?: date('c');

/* ---------- ADD / DEL -------------------------------------------------- */
$status = 'ok'; $message = '';

switch ($action) {
    case 'add':
        if (in_array($entry, $addr, true)) {
            $status  = 'exists';
            $message = "IP $entry is already present";
        } else {
            $addr[] = $entry;
            $det[]  = $stamp;
        }
        break;

    case 'del':
        $i = array_search($entry, $addr, true);
        if ($i !== false) {
            unset($addr[$i], $det[$i]);
            $addr = array_values($addr);
            $det  = array_values($det);
        }
        break;

    default:
        http_response_code(400);
        echo '{"error":"bad action"}';
        exit;
}

/* ---------- Persist (only if changed) --------------------------------- */
if ($status === 'ok' && ($action === 'add' || $action === 'del')) {
    $alias->address   = implode(' ', $addr);
    $detailNode[0]    = implode(' ', $det);
    file_put_contents(CONFIG_PATH, $xml->asXML());
    @unlink('/tmp/config.cache');             // force GUI to reload fresh XML
    shell_exec('/rc.filter_configure_sync');  // live firewall reload
}

/* ---------- Final JSON response --------------------------------------- */
$response = ['alias'=>ALIAS_NAME,'count'=>count($addr),'status'=>$status];
if ($message) $response['message'] = $message;
echo json_encode($response);
