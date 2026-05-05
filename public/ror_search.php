<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

function norm(string $s): string {
  $s = mb_strtolower($s, 'UTF-8');
  if (class_exists('Transliterator')) {
    $tr = Transliterator::create('NFD; [:Nonspacing Mark:] Remove; NFC');
    if ($tr) $s = $tr->transliterate($s);
  }
  $s = preg_replace('/[^\p{L}\p{N}]+/u', ' ', $s);
  $s = preg_replace('/\s+/u', ' ', trim($s));
  return $s;
}

$q = (string)($_GET['q'] ?? '');
$q = trim($q);

if (mb_strlen($q, 'UTF-8') < 3) {
  echo json_encode(['ok' => true, 'results' => []]);
  exit;
}

$bucketLen = 3;
$idxDir = __DIR__ . '/ror_idx';

$k = norm($q);
if ($k === '') {
  echo json_encode(['ok' => true, 'results' => []]);
  exit;
}

$bk = mb_substr($k, 0, $bucketLen, 'UTF-8');
if ($bk === '') {
  echo json_encode(['ok' => true, 'results' => []]);
  exit;
}

$path = $idxDir . '/' . $bk . '.json';
if (!is_file($path)) {
  echo json_encode(['ok' => true, 'results' => []]);
  exit;
}

$list = json_decode(file_get_contents($path), true);
if (!is_array($list)) $list = [];

// Score: prefer exact > prefix > substring
$results = [];
foreach ($list as $e) {
  $ek = (string)($e['k'] ?? '');
  if ($ek === '') continue;

  $pos = strpos($ek, $k);
  if ($pos === false) continue;

  if ($ek === $k) {
    $score = -5;        // exact match best
  } elseif ($pos === 0) {
    $score = 0;         // prefix
  } else {
    $score = 10;        // substring
  }

  // tie-break: shorter key is often closer
  $score += min(50, max(0, mb_strlen($ek, 'UTF-8') - mb_strlen($k, 'UTF-8')));

  $results[] = [$score, $e];
}

// sort by score, then name
usort($results, function($a, $b) {
  if ($a[0] !== $b[0]) return $a[0] <=> $b[0];
  return strcmp($a[1]['name'] ?? '', $b[1]['name'] ?? '');
});

// de-dupe by id (aliases create duplicates)
$out = [];
$seen = [];
foreach ($results as $pair) {
  $e = $pair[1];
  $id = (string)($e['id'] ?? '');
  if ($id === '' || isset($seen[$id])) continue;
  $seen[$id] = true;

  $out[] = [
    'id' => $id,
    'name' => (string)($e['name'] ?? ''),
    'country' => (string)($e['country'] ?? ''),
    'city' => (string)($e['city'] ?? ''),
  ];
  if (count($out) >= 10) break;
}

echo json_encode(['ok' => true, 'results' => $out], JSON_UNESCAPED_UNICODE);

