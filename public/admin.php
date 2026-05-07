<?php
declare(strict_types=1);

session_start();

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function deny(string $msg): void {
  http_response_code(403);
  echo "<!doctype html><meta charset='utf-8'><title>Forbidden</title><h1>Forbidden</h1><p>" . h($msg) . "</p>";
  exit;
}

function safe_equals(string $a, string $b): bool {
  if (function_exists('hash_equals')) return hash_equals($a, $b);
  if (strlen($a) !== strlen($b)) return false;
  $res = 0;
  for ($i=0; $i<strlen($a); $i++) $res |= ord($a[$i]) ^ ord($b[$i]);
  return $res === 0;
}

// ---- CONFIG ----
$config = require __DIR__ . '/../config/config.php';

$secrets_file = $config['secrets'];

$secrets = require $secrets_file;

$dbPath = $config['db_path'];
$auditLogPath = $config['audit_log_path'];

$ADMIN_KEY = getenv('CHES_ADMIN_KEY') ?: ($secrets['admin_key'] ?? '');

if (trim((string)$ADMIN_KEY) === '') {
  http_response_code(500);
  die('Server misconfiguration: admin key is not set.');
}

// Gap threshold for expertise
$GAP_THRESHOLD = 3;

$EXPERTISE_TAXONOMY = $config['expertise_taxonomy'] ?? [];


require_once __DIR__ . '/territories.php';

if (!isset($territories) || !is_array($territories)) {
  die("territories.php did not provide \$territories");
}


// ---- Access control ----
$k = $_GET['k'] ?? '';

// already logged in?
if (!empty($_SESSION['admin_ok'])) {
  // ok
} else {
  // allow "login" via ?k=...
  if (!hash_equals($ADMIN_KEY, $k)) {
    http_response_code(403);
    die("Forbidden.");
  }
  $_SESSION['admin_ok'] = true;

  // redirect to clean URL (no k)
  header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
  exit;
}

function db(string $dbPath): PDO {
  static $pdo = null;
  if ($pdo === null) {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
  }
  return $pdo;
}


// ---- Headers (basic hardening) ----
$csp_nonce = base64_encode(random_bytes(16));
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$csp_nonce'; style-src 'self' 'nonce-$csp_nonce'; frame-ancestors 'none'; base-uri 'none';");

function pct(int $count, int $total): string {
  if ($total <= 0) return "0.0%";
  return number_format(($count / $total) * 100.0, 1) . "%";
}


$pdo = db($dbPath);

$stmt = $pdo->query("
  SELECT
    token,
    invite_email,
    review_email,
    given_names,
    family_name,
    affiliation,
    country,
    status,
    updated_at,
    expertise,
    cryptodb_mode,
    cryptodb_id
  FROM reviewers
  ORDER BY family_name COLLATE NOCASE, given_names COLLATE NOCASE, invite_email COLLATE NOCASE
");

$rows = $stmt->fetchAll();

$statusCounts = [
  "invited" => 0,    // open invitation (not accepted/declined)
  "opened" => 0,     // optional if you track it
  "accepted" => 0,
  "registered" => 0,
  "declined" => 0,
  "invalid_email" => 0,
  "unknown" => 0,
];

$expertiseCounts = [];
foreach ($EXPERTISE_TAXONOMY as $cat => $topics) {
  foreach ($topics as $topic) {
    $expertiseCounts[$topic] = 0;
  }
}

$affiliationCounts = [];

$total = 0;
$withExpertise = 0;

$mostRecentUpdate = "";
$mostRecentToken = "";


function canonical_country_name(string $country): string {
  $c = trim($country);

  // normalize whitespace
  $c = preg_replace('/\s+/', ' ', $c);

  // alias table (case-insensitive keys)
  static $aliases = [
    'the netherlands' => 'Netherlands',
    'deutschland' => 'Germany',
    'u.s.' => 'United States',
  ];

  $k = mb_strtolower($c, 'UTF-8');

  return $aliases[$k] ?? $c;
}


foreach ($rows as $r) {
  $total++;

  $status = strtolower(trim((string)($r["status"] ?? "")));
  if ($status === "") $status = "invited";
  if (!isset($statusCounts[$status])) $status = "unknown";
  $statusCounts[$status]++;

  $updated = trim((string)($r["updated_at"] ?? ""));
  if ($updated !== "" && ($mostRecentUpdate === "" || $updated > $mostRecentUpdate)) {
    $mostRecentUpdate = $updated;
    $mostRecentToken = trim((string)($r["token"] ?? ""));
  }

  $expertise = trim((string)($r["expertise"] ?? ""));

  if ($expertise !== "") {
    $withExpertise++;
    foreach (explode("|", $expertise) as $tag) {
      $tag = trim($tag);
      if ($tag === "") continue;

      if (array_key_exists($tag, $expertiseCounts)) {
        $expertiseCounts[$tag]++;
      }
    }
  }

  $affiliationRaw = trim((string)($r["affiliation"] ?? ""));
  
  if ($affiliationRaw !== "") {
    $seenAffiliations = [];
  
    foreach (explode("|", $affiliationRaw) as $a) {
      $a = trim($a);
      if ($a === "") continue;
  
      // Deduplicate per reviewer, case-insensitive
      $key = mb_strtolower($a, "UTF-8");
      if (isset($seenAffiliations[$key])) continue;
  
      $seenAffiliations[$key] = $a;
    }
  
    if (count($seenAffiliations) > 0) {
      foreach ($seenAffiliations as $a) {
        $affiliationCounts[$a] = ($affiliationCounts[$a] ?? 0) + 1;
      }
    }
  }
}

arsort($expertiseCounts);
arsort($affiliationCounts);

$totalAffiliationEntries = array_sum($affiliationCounts);
$totalExpertiseSelections = array_sum($expertiseCounts);


$countryCounts = [];

foreach ($rows as $r) {
  $seenCountries = [];

  foreach (explode("|", (string)($r["country"] ?? "")) as $c) {
    $c = canonical_country_name(trim($c));
    if ($c === "") continue;

    $key = mb_strtolower($c, "UTF-8");
    if (isset($seenCountries[$key])) continue;

    $seenCountries[$key] = $c;
  }

  foreach ($seenCountries as $c) {
    $countryCounts[$c] = ($countryCounts[$c] ?? 0) + 1;
  }
}

arsort($countryCounts);
$totalCountryEntries = array_sum($countryCounts);


$countryAffiliations = [];

foreach ($rows as $r) {
  $countryParts = array_map("trim", explode("|", (string)($r["country"] ?? "")));
  $affParts     = array_map("trim", explode("|", (string)($r["affiliation"] ?? "")));

  $n = max(count($countryParts), count($affParts));
  $seenPairs = [];

  for ($i = 0; $i < $n; $i++) {
    $country = canonical_country_name($countryParts[$i] ?? "");
    $aff = trim($affParts[$i] ?? "");

    if ($country === "" || $aff === "") continue;

    $pairKey = mb_strtolower($country . "||" . $aff, "UTF-8");
    if (isset($seenPairs[$pairKey])) continue;
    $seenPairs[$pairKey] = true;

    $countryAffiliations[$country][$aff] =
      ($countryAffiliations[$country][$aff] ?? 0) + 1;
  }
}


$geoTree = [];

foreach ($countryCounts as $country => $countryCnt) {
  $t = $territories[$country] ?? null;

  $continent = $t["continent"] ?? "Unknown";
  $sub       = $t["subcontinent"] ?? "Unknown";

  if (!isset($geoTree[$continent])) {
    $geoTree[$continent] = [
      "total" => 0,
      "subs" => [],
    ];
  }

  if (!isset($geoTree[$continent]["subs"][$sub])) {
    $geoTree[$continent]["subs"][$sub] = [
      "total" => 0,
      "countries" => [],
    ];
  }

  $geoTree[$continent]["total"] += $countryCnt;
  $geoTree[$continent]["subs"][$sub]["total"] += $countryCnt;

  $geoTree[$continent]["subs"][$sub]["countries"][$country] = [
    "total" => $countryCnt,
    "affiliations" => $countryAffiliations[$country] ?? [],
  ];
}


$gaps = [];
foreach ($expertiseCounts as $tag => $cnt) {
  if ($cnt <= $GAP_THRESHOLD) $gaps[$tag] = $cnt;
}
asort($gaps);

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reviewer Admin</title>
  <style nonce="<?= h($csp_nonce) ?>">
    body { font-family: system-ui, Arial, sans-serif; max-width: 980px; margin: 40px auto; padding: 0 16px; }
    h1 { margin: 0 0 12px; }
    h2 { margin: 0 0 10px; }
    .card { border: 1px solid #ddd; border-radius: 14px; padding: 16px; margin: 14px 0; background: #fafafa; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #ddd; border-radius: 10px; overflow: hidden; margin-top:10px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; font-weight: 700; }
    tr:last-child td { border-bottom: none; }
    .muted { color: #555; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .small { font-size: 13px; }
    .btnrow { display:flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
    button { padding: 10px 14px; font-size: 16px; cursor:pointer; }
    .primary { font-weight: 700; }

.geo-toggle {
  cursor: pointer;
  user-select: none;
}

.geo-toggle:hover {
  text-decoration: underline;
}

.geo-continent-row {
  font-weight: 700;
  background: #f3f3f3;
}

.geo-subcontinent-row {
  font-weight: 600;
}

.geo-subcontinent-row td:first-child {
  padding-left: 24px;
}

.geo-country-row td:first-child {
  padding-left: 48px;
  color: #555;
}

.geo-hidden {
  display: none;
}

.geo-arrow {
  display: inline-block;
  width: 1.2em;
}

.geo-affiliation-row {
  padding-left: 72px;
  color: #666;
  font-size: 0.95em;
}

  </style>
</head>
<body>

<h1>Reviewer Admin</h1>
<div class="muted small">Data source: <span class="mono"><?= h(basename($dbPath)) ?></span></div>

<div class="grid">
  <div class="card">
    <h2>Invitation status</h2>
    <table>
      <tr><th>Status</th><th>Count</th><th>Share</th></tr>
      <tr><td>Open (invited)</td><td><?= (int)$statusCounts["invited"] ?></td><td><?= h(pct((int)$statusCounts["invited"], $total)) ?></td></tr>
<!--
      <tr><td>Opened (optional)</td><td><?= (int)$statusCounts["opened"] ?></td><td><?= h(pct((int)$statusCounts["opened"], $total)) ?></td></tr>
-->
      <tr><td>Accepted</td><td><?= (int)$statusCounts["accepted"] ?></td><td><?= h(pct((int)$statusCounts["accepted"], $total)) ?></td></tr>
      <tr><td>Registered (saved details)</td><td><?= (int)$statusCounts["registered"] ?></td><td><?= h(pct((int)$statusCounts["registered"], $total)) ?></td></tr>
      <tr><td>Declined</td><td><?= (int)$statusCounts["declined"] ?></td><td><?= h(pct((int)$statusCounts["declined"], $total)) ?></td></tr>
      <tr><td>Invalid email</td><td><?= (int)$statusCounts["invalid_email"] ?></td><td><?= h(pct((int)$statusCounts["invalid_email"], $total)) ?></td></tr>
      <tr><td>Unknown/other</td><td><?= (int)$statusCounts["unknown"] ?></td><td><?= h(pct((int)$statusCounts["unknown"], $total)) ?></td></tr>
      <tr><th>Total</th><th><?= (int)$total ?></th><th><?= h(pct($total, $total)) ?></th></tr>
    </table>

    <div class="muted small">
      <?php if ($mostRecentUpdate !== ""): ?>
        Most recent update: <b><?= h($mostRecentUpdate) ?></b>
        <span class="muted">(token: <span class="mono"><?= h($mostRecentToken) ?></span>)</span>
      <?php else: ?>
        No updates recorded yet.
      <?php endif; ?>
    </div>
  </div>

  <div class="card">
    <h2>Expertise overview</h2>
    <div class="muted small">Reviewers with at least one expertise tag: <b><?= (int)$withExpertise ?></b> / <?= (int)$total ?></div>
    <div class="muted small">Gap threshold: ≤ <?= (int)$GAP_THRESHOLD ?></div>
    <div class="muted small">Distinct expertise tags used: <b><?= (int)count($expertiseCounts) ?></b></div>
  </div>
</div>

<div class="card">
  <h2>Structured expertise coverage</h2>
  <table>
    <tr><th>Expertise</th><th>Count</th><th>Share</th></tr>
    <?php if (count($expertiseCounts) === 0): ?>
      <tr><td colspan="3" class="muted">No expertise selections recorded yet.</td></tr>
    <?php else: ?>
      <?php foreach ($expertiseCounts as $tag => $cnt): ?>
        <tr>
          <td><?= h($tag) ?></td>
          <td><?= (int)$cnt ?></td>
          <td><?= h(pct((int)$cnt, $totalExpertiseSelections)) ?></td>
        </tr>
      <?php endforeach; ?>
    <?php endif; ?>
  </table>
</div>

<div class="card">
  <h2>Potential gaps (≤ <?= (int)$GAP_THRESHOLD ?>)</h2>
  <table>
    <tr><th>Expertise</th><th>Count</th></tr>
    <?php if (count($gaps) === 0): ?>
      <tr><td colspan="2" class="muted">No gaps detected at this threshold.</td></tr>
    <?php else: ?>
      <?php foreach ($gaps as $tag => $cnt): ?>
        <tr><td><?= h($tag) ?></td><td><?= (int)$cnt ?></td></tr>
      <?php endforeach; ?>
    <?php endif; ?>
  </table>
</div>

<div class="card">
  <h2>Country overview</h2>

  <table>
    <tr><th>Country</th><th>Count</th><th>Share</th></tr>

    <?php if (count($countryCounts) === 0): ?>
      <tr><td colspan="3" class="muted">No countries recorded yet.</td></tr>
    <?php else: ?>
      <?php foreach ($countryCounts as $country => $cnt): ?>
        <tr>
          <td><?= h($country) ?></td>
          <td><?= (int)$cnt ?></td>
          <td><?= h(pct((int)$cnt, $totalCountryEntries)) ?></td>
        </tr>
      <?php endforeach; ?>
    <?php endif; ?>
  </table>
</div>

<div class="card">
  <h2>Geographic overview</h2>

  <table>
    <tr>
      <th>Region</th>
      <th>Count</th>
      <th>Share</th>
    </tr>

    <?php $ci = 0; ?>
    <?php foreach ($geoTree as $continent => $continentData): ?>
      <?php
        $continentId = "geo-cont-" . (++$ci);
        $si = 0;
      ?>
    
      <tr class="geo-continent-row geo-toggle"
          data-toggle-prefix="<?= h($continentId) ?>">
        <td>
          <span class="geo-arrow">▸</span><?= h($continent) ?>
        </td>
        <td><?= (int)$continentData["total"] ?></td>
        <td><?= h(pct((int)$continentData["total"], $totalCountryEntries)) ?></td>
      </tr>
    
      <?php foreach ($continentData["subs"] as $sub => $subData): ?>
        <?php $subId = $continentId . "-sub-" . (++$si); ?>
    
        <tr class="geo-subcontinent-row geo-toggle geo-hidden"
            data-group="<?= h($continentId) ?>"
            data-toggle-prefix="<?= h($subId) ?>">
          <td>
            <span class="geo-arrow">▸</span><?= h($sub) ?>
          </td>
          <td><?= (int)$subData["total"] ?></td>
          <td><?= h(pct((int)$subData["total"], $totalCountryEntries)) ?></td>
        </tr>
    
        <?php foreach ($subData["countries"] as $country => $countryData): ?>
          <?php
            $countryId = $subId . '-country-' . (++$countryIdx);
            $countryCnt = (int)($countryData["total"] ?? 0);
          ?>
 
          <tr class="geo-country-row geo-toggle geo-hidden"
              data-group="<?= h($subId) ?>"
              data-toggle-prefix="<?= h($countryId) ?>">
            <td><span class="geo-arrow">▸</span><?= h($country) ?></td>
            <td><?= $countryCnt ?></td>
            <td><?= h(pct($countryCnt, $totalCountryEntries)) ?></td>
          </tr>
        
          <?php foreach (($countryData["affiliations"] ?? []) as $aff => $affCnt): ?>
            <tr class="geo-affiliation-row geo-hidden"
                data-group="<?= h($countryId) ?>">
              <td class="geo-affiliation-row">
                ↳ <?= h($aff) ?>
              </td>
              <td><?= (int)$affCnt ?></td>
              <td><?= h(pct((int)$affCnt, $totalAffiliationEntries)) ?></td>
            </tr>
          <?php endforeach; ?>

        <?php endforeach; ?>
      <?php endforeach; ?>
    <?php endforeach; ?>
  </table>
</div>

<div class="card">
  <h2>Affiliation overview</h2>

  <table>
    <tr><th>Affiliation</th><th>Count</th><th>Share</th></tr>

    <?php if (count($affiliationCounts) === 0): ?>
      <tr><td colspan="3" class="muted">No affiliations recorded yet.</td></tr>
    <?php else: ?>
      <?php foreach ($affiliationCounts as $affiliation => $cnt): ?>
        <tr>
          <td><?= h($affiliation) ?></td>
          <td><?= (int)$cnt ?></td>
          <td><?= h(pct((int)$cnt, $totalAffiliationEntries)) ?></td>
        </tr>
      <?php endforeach; ?>
    <?php endif; ?>
  </table>
</div>

<?php if (false) : ?>
  <div class="btnrow">
    <form method="get" class="nomargin">
      <input type="hidden" name="download">
      <button type="submit" class="primary">
        Download CSV
      </button>
    </form>
  </div>
<?php endif; ?>

<script nonce="<?= h($csp_nonce) ?>">
  document.addEventListener("click", (e) => {
    const row = e.target.closest(".geo-toggle");
    if (!row) return;
  
    const prefix = row.dataset.togglePrefix;
    if (!prefix) return;
  
    const children = document.querySelectorAll(`[data-group="${CSS.escape(prefix)}"]`);
    const expanding = [...children].some(el => el.classList.contains("geo-hidden"));
  
    function setArrow(el, open) {
      const arrow = el.querySelector(".geo-arrow");
      if (arrow) arrow.textContent = open ? "▾" : "▸";
    }
  
    function collapseDescendants(parentPrefix) {
      const kids = document.querySelectorAll(`[data-group="${CSS.escape(parentPrefix)}"]`);
  
      kids.forEach(kid => {
        kid.classList.add("geo-hidden");
  
        if (kid.classList.contains("geo-toggle")) {
          setArrow(kid, false);
  
          const childPrefix = kid.dataset.togglePrefix;
          if (childPrefix) collapseDescendants(childPrefix);
        }
      });
    }
  
    if (expanding) {
      // Show immediate children only
      children.forEach(el => el.classList.remove("geo-hidden"));
      setArrow(row, true);
    } else {
      // Hide all descendants recursively
      collapseDescendants(prefix);
      setArrow(row, false);
    }
  });
</script>

</body>
</html>

