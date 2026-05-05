<?php
declare(strict_types=1);

// ---- CONFIG ----
$config = require __DIR__ . '/../config/config.php';

$cacheDir = $config['cryptodb_cache'];


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function bad(int $code, string $msg): void {
  http_response_code($code);
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_UNICODE);
  exit;
}

$term = trim((string)($_GET['term'] ?? ''));
if ($term === '') bad(400, 'Missing term.');
if (mb_strlen($term, 'UTF-8') < 2) echo json_encode(['ok'=>true,'items'=>[]]) and exit;

// allow basic name chars only (avoid weird abuse)
if (!preg_match('/^[\p{L}\p{M}\p{N}\s\.\'\-]+$/u', $term)) {
  bad(400, 'Invalid term.');
}

@mkdir($cacheDir, 0775, true);

// cache key: normalize to lowercase ascii-ish filename
$key = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $term));
$cacheFile = $cacheDir . '/' . $key . '.json';
$ttl = 3600 * 12; // 12 hours

if (is_file($cacheFile) && (time() - filemtime($cacheFile) < $ttl)) {
  $raw = file_get_contents($cacheFile);
  if ($raw !== false) {
    echo json_encode(['ok'=>true,'cached'=>true,'items'=>json_decode($raw, true)], JSON_UNESCAPED_UNICODE);
    exit;
  }
}

$url = 'https://www.iacr.org/cryptodb/data/jquery/query.php?term=' . rawurlencode($term);

$ch = curl_init($url);
curl_setopt_array($ch, [
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_FOLLOWLOCATION => true,
  CURLOPT_CONNECTTIMEOUT => 3,
  CURLOPT_TIMEOUT => 5,
  CURLOPT_USERAGENT => 'CHES-reviewer-form/1.0',
]);

$raw = curl_exec($ch);
$http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
$err  = curl_error($ch);
curl_close($ch);

if ($raw === false || $http < 200 || $http >= 300) {
  bad(502, 'CryptoDB request failed' . ($err ? (": $err") : ''));
}

$data = json_decode($raw, true);
if (!is_array($data)) bad(502, 'CryptoDB returned invalid JSON.');

// store raw JSON array in cache
file_put_contents($cacheFile, json_encode($data, JSON_UNESCAPED_UNICODE));

echo json_encode(['ok'=>true,'cached'=>false,'items'=>$data], JSON_UNESCAPED_UNICODE);

