<?php
declare(strict_types=1);

/**
 * build_ror_index.php
 *
 * Build a bucketed local search index from a ROR JSON dump.
 *
 * Key points:
 * - We do NOT drop orgs just because they have non-English / non-ASCII names.
 * - We create MATCH KEYS by transliterating *any* name to ASCII (Any-Latin; Latin-ASCII; ...).
 * - We ONLY generate bucket files whose bucket prefix is ASCII [a-z0-9]{bucketLen}.
 * - For display in UI, we prefer an English display name if present; else use any ror_display/label.
 *
 * Usage:
 *   php build_ror_index.php /path/to/ror_data.json [out_dir] [bucketLen=3]
 */

function norm_ascii(string $s): string {
  $s = mb_strtolower($s, 'UTF-8');

  // Transliterate any script -> Latin -> ASCII, then strip diacritics
  if (class_exists('Transliterator')) {
    $tr = Transliterator::create('Any-Latin; Latin-ASCII; NFD; [:Nonspacing Mark:] Remove; NFC');
    if ($tr) $s = $tr->transliterate($s);
  }

  // Keep only ASCII letters/digits/spaces
  $s = preg_replace('/[^a-z0-9]+/', ' ', $s);
  $s = preg_replace('/\s+/', ' ', trim($s));
  return $s;
}

function short_ror_id(string $id): string {
  if (preg_match('~ror\.org/([a-z0-9]+)~i', $id, $m)) return strtolower($m[1]);
  return strtolower(trim($id));
}

function usage_and_exit(string $msg = ''): void {
  if ($msg !== '') fwrite(STDERR, $msg . "\n");
  fwrite(STDERR, "Usage: php build_ror_index.php /path/to/ror_data.json [out_dir] [bucketLen=3]\n");
  exit(1);
}

function ascii_bucket_key(string $k, int $bucketLen): string {
  if ($k === '') return '';
  $bk = substr($k, 0, $bucketLen);
  if ($bk === '') return '';
  if (!preg_match('/^[a-z0-9]{' . $bucketLen . '}$/', $bk)) return '';
  return $bk;
}

function choose_display_name(array $names): string {
  // Prefer: (lang=en) ror_display, then (lang=en) label
  // Then: any ror_display, then any label
  // Then: first non-empty value
  $first = '';

  $bestEnRor = '';
  $bestEnLabel = '';
  $bestAnyRor = '';
  $bestAnyLabel = '';

  foreach ($names as $n) {
    if (!is_array($n)) continue;
    $val = trim((string)($n['value'] ?? ''));
    if ($val === '') continue;

    if ($first === '') $first = $val;

    $lang = $n['lang'] ?? null;
    $types = $n['types'] ?? [];
    if (!is_array($types)) $types = [];

    $isRorDisplay = in_array('ror_display', $types, true);
    $isLabel      = in_array('label', $types, true);

    if ($lang === 'en') {
      if ($bestEnRor === '' && $isRorDisplay) $bestEnRor = $val;
      if ($bestEnLabel === '' && $isLabel)   $bestEnLabel = $val;
    }
    if ($bestAnyRor === '' && $isRorDisplay) $bestAnyRor = $val;
    if ($bestAnyLabel === '' && $isLabel)    $bestAnyLabel = $val;
  }

  return $bestEnRor
      ?: $bestEnLabel
      ?: $bestAnyRor
      ?: $bestAnyLabel
      ?: $first;
}

function collect_all_name_values(array $names): array {
  $out = [];
  foreach ($names as $n) {
    if (!is_array($n)) continue;
    $val = trim((string)($n['value'] ?? ''));
    if ($val !== '') $out[] = $val;
  }
  return $out;
}

$src = $argv[1] ?? '';
$outDir = $argv[2] ?? (__DIR__ . '/public/ror_idx');
$bucketLen = (int)($argv[3] ?? 3);

if ($src === '' || !is_file($src)) usage_and_exit("Missing or invalid JSON file.");
if ($bucketLen < 2 || $bucketLen > 4) usage_and_exit("bucketLen must be 2..4");

@mkdir($outDir, 0775, true);
if (!is_dir($outDir)) usage_and_exit("Could not create output directory: $outDir");

$raw = file_get_contents($src);
if ($raw === false) usage_and_exit("Failed to read: $src");

$data = json_decode($raw, true);
if (!is_array($data)) usage_and_exit("Failed to parse JSON (is it valid JSON?)");

$items = $data['items'] ?? $data['data'] ?? $data;
if (!is_array($items)) usage_and_exit("Could not find list of org items in JSON");

// bucketKey => [dedupeKey => entry]
$buckets = [];

function add_entry(array &$buckets, string $bucketKey, array $entry): void {
  if (!isset($buckets[$bucketKey])) $buckets[$bucketKey] = [];
  $dk = $entry['id'] . '|' . $entry['k'];
  $buckets[$bucketKey][$dk] = $entry;
}

$orgCount = 0;
$entryCount = 0;
$skippedNoNames = 0;
$skippedNoKey = 0;
$skippedNoAsciiBucket = 0;

foreach ($items as $org) {
  if (!is_array($org)) continue;

  $idFull = (string)($org['id'] ?? $org['ror_id'] ?? '');
  if ($idFull === '') continue;

  $id = short_ror_id($idFull);
  if ($id === '') continue;

  $names = $org['names'] ?? [];
  if (!is_array($names) || count($names) === 0) { $skippedNoNames++; continue; }

  // Display name for UI (prefer English if present)
  $display = choose_display_name($names);
  if ($display === '') { $skippedNoNames++; continue; }

  // All name values used for matching (aliases, local language, acronyms, etc.)
  $allNames = collect_all_name_values($names);

  // Location (optional)
  $country = '';
  $city = '';
  $gd = $org['locations'][0]['geonames_details'] ?? null;
  if (is_array($gd)) {
    $country = (string)($gd['country_name'] ?? '');
    $city    = (string)($gd['name'] ?? $gd['city_name'] ?? '');
  }

  // Build entries from ALL names (including display) but bucket filenames only ASCII
  $seenKeys = [];

  foreach ($allNames as $nm) {
    $k = norm_ascii($nm);
    if ($k === '') { continue; }

    // de-dupe keys per org
    if (isset($seenKeys[$k])) continue;
    $seenKeys[$k] = true;

    $bk = ascii_bucket_key($k, $bucketLen);
    if ($bk === '') { $skippedNoAsciiBucket++; continue; }

    add_entry($buckets, $bk, [
      'k' => $k,         // ASCII match key
      'id' => $id,       // short ror id
      'name' => $display, // UI display name (prefer EN)
      'country' => $country,
      'city' => $city,
    ]);
    $entryCount++;
  }

  // Ensure at least one entry from the chosen display itself
  $dk = norm_ascii($display);
  if ($dk !== '' && !isset($seenKeys[$dk])) {
    $bk = ascii_bucket_key($dk, $bucketLen);
    if ($bk !== '') {
      add_entry($buckets, $bk, [
        'k' => $dk,
        'id' => $id,
        'name' => $display,
        'country' => $country,
        'city' => $city,
      ]);
      $entryCount++;
    } else {
      $skippedNoAsciiBucket++;
    }
  }

  $orgCount++;
}

// Write buckets
ksort($buckets);
foreach ($buckets as $bk => $map) {
  $list = array_values($map);
  usort($list, fn($a, $b) => strcmp((string)$a['k'], (string)$b['k']));
  $path = $outDir . '/' . $bk . '.json';
  file_put_contents($path, json_encode($list, JSON_UNESCAPED_UNICODE));
}

echo "Wrote " . count($buckets) . " ASCII bucket files into $outDir\n";
echo "Orgs processed: $orgCount\n";
echo "Index entries written (pre-dedupe accounting): $entryCount\n";
echo "Skipped: no_names=$skippedNoNames, no_key=$skippedNoKey, no_ascii_bucket=$skippedNoAsciiBucket\n";
