<?php
/**
 * Agents Alias API — IPv4 (/32) & IPv6 (/128) with auto-create
 * ---------------------------------------------------------------------------
 * Author   : Josias L. Gonçalves · josiaslg@bsd.com.br | josiaslg@cloudunix.com.br
 * License  : BSD-3-Clause
 * Updated  : 25-Jun-2025 01:10 BRT
 */

declare(strict_types=1);

const CONFIG_PATH = '/conf/config.xml';
const APIKEY_PATH = '/usr/local/agent_apikey/api_key.txt';
const ALIAS_NAME  = 'Agents_IP_Block_List';
const ERRLOG      = '/tmp/agents_api_error.log';

/* ---------- Error log -------------------------------------------------- */
if (!file_exists(ERRLOG)) { touch(ERRLOG); chmod(ERRLOG, 0666); }
ini_set('log_errors', '1');
ini_set('error_log',  ERRLOG);
ini_set('display_errors', '0');

/* ---------- Pre-flight key -------------------------------------------- */
$dir = dirname(APIKEY_PATH);
if (!is_dir($dir)) mkdir($dir, 0700, true);
if (!file_exists(APIKEY_PATH)) { http_response_code(500); header('Content-Type: application/json'); echo '{"error":"API key missing"}'; exit; }
chmod(APIKEY_PATH, 0600);

/* ---------- Bearer authentication ------------------------------------- */
$hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/Bearer\s+(\S+)/', $hdr, $m)) { http_response_code(401); header('Content-Type: application/json'); echo '{"error":"Missing token"}'; exit; }
if (!hash_equals(trim(file_get_contents(APIKEY_PATH)), trim($m[1]))) { http_response_code(403); header('Content-Type: application/json'); echo '{"error":"Bad token"}'; exit; }

/* ---------- Always JSON ------------------------------------------------ */
header('Content-Type: application/json');

/* ---------- Parameters ------------------------------------------------- */
$action = $_GET['action'] ?? 'list';   // list | add | del
$ipRaw  = $_GET['ip'] ?? '';
$tsRaw  = $_GET['ts'] ?? '';

/* ---------- Load XML & locate alias ----------------------------------- */
$xml      = new SimpleXMLElement(file_get_contents(CONFIG_PATH));
$aliases  = $xml->aliases ?: $xml->addChild('aliases');

$alias = null;
foreach ($aliases->alias as $a) {
    if ((string)$a->name === ALIAS_NAME) { $alias = $a; break; }
}

/* ---------- Auto-create alias if missing ------------------------------ */
if (!$alias) {
    $alias = $aliases->addChild('alias');
    $alias->addChild('name',  ALIAS_NAME);
    $alias->addChild('type',  'network');
    $alias->addChild('address', '');
    $alias->addChild('descr',  '');
    $alias->addChild('detail', '');
    file_put_contents(CONFIG_PATH, $xml->asXML());
    @unlink('/tmp/config.cache');
    shell_exec('/rc.filter_configure_sync');   // <-- new: load empty alias
}

/* ---------- Split address / detail ------------------------------------ */
$addr       = array_filter(preg_split('/\s+/', (string)$alias->address));
$detailNode = $alias->detail ?? $alias->addChild('detail', '');
$det        = array_filter(preg_split('/\s+/', (string)$detailNode));
while (count($det) < count($addr)) $det[]='-';
while (count($det) > count($addr)) array_pop($det);

/* ---------- LIST ------------------------------------------------------ */
if ($action === 'list') {
    $out=[]; foreach($addr as $i=>$ip) $out[]=['ip'=>$ip,'ts'=>$det[$i]??''];
    echo json_encode(['alias'=>ALIAS_NAME,'entries'=>$out], JSON_PRETTY_PRINT);
    exit;
}

/* ---------- Validate IP (v4/v6) -------------------------------------- */
if ($ipRaw===''){ http_response_code(400); echo '{"error":"ip param required"}'; exit; }
[$ip] = explode('/', $ipRaw, 2);
$ipVersion = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 :
             (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 6 : 0);
if ($ipVersion === 0){ http_response_code(422); echo '{"error":"invalid IP"}'; exit; }

$entry = $ipVersion === 4 ? $ip.'/32' : $ip.'/128';
$stamp = $tsRaw ?: date('c');

/* ---------- ADD / DEL ------------------------------------------------- */
$status='ok'; $message='';
switch($action){
 case 'add':
     if(in_array($entry,$addr,true)){
         $status='exists';
         $message="IP $entry is already present";
     }else{
         $addr[]=$entry; $det[]=$stamp;
     }
     break;

 case 'del':
     $i=array_search($entry,$addr,true);
     if($i!==false){ unset($addr[$i],$det[$i]); $addr=array_values($addr); $det=array_values($det); }
     break;

 default:
     http_response_code(400); echo '{"error":"bad action"}'; exit;
}

/* ---------- Save only if changed ------------------------------------- */
if($status==='ok' && ($action==='add'||$action==='del')){
    $alias->address   = implode(' ', $addr);
    $detailNode[0]    = implode(' ', $det);
    file_put_contents(CONFIG_PATH, $xml->asXML());
    @unlink('/tmp/config.cache');
    shell_exec('/rc.filter_configure_sync');
}

/* ---------- Response -------------------------------------------------- */
$response=['alias'=>ALIAS_NAME,'count'=>count($addr),'status'=>$status];
if($message) $response['message']=$message;
echo json_encode($response);
