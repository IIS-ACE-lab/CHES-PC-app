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
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'nonce-$csp_nonce'; frame-ancestors 'none'; base-uri 'none';");

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
  "unknown" => 0,
];

$expertiseCounts = [];
foreach ($EXPERTISE_TAXONOMY as $cat => $topics) {
  foreach ($topics as $topic) {
    $expertiseCounts[$topic] = 0;
  }
}

$total = 0;
$withExpertise = 0;

$mostRecentUpdate = "";
$mostRecentToken = "";

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
}

arsort($expertiseCounts);

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
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #ddd; border-radius: 10px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; font-weight: 700; }
    tr:last-child td { border-bottom: none; }
    .muted { color: #555; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .small { font-size: 13px; }
    .btnrow { display:flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
    button { padding: 10px 14px; font-size: 16px; cursor:pointer; }
    .primary { font-weight: 700; }
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
      <tr><td>Opened (optional)</td><td><?= (int)$statusCounts["opened"] ?></td><td><?= h(pct((int)$statusCounts["opened"], $total)) ?></td></tr>
      <tr><td>Accepted</td><td><?= (int)$statusCounts["accepted"] ?></td><td><?= h(pct((int)$statusCounts["accepted"], $total)) ?></td></tr>
      <tr><td>Registered (saved details)</td><td><?= (int)$statusCounts["registered"] ?></td><td><?= h(pct((int)$statusCounts["registered"], $total)) ?></td></tr>
      <tr><td>Declined</td><td><?= (int)$statusCounts["declined"] ?></td><td><?= h(pct((int)$statusCounts["declined"], $total)) ?></td></tr>
      <tr><td>Unknown/other</td><td><?= (int)$statusCounts["unknown"] ?></td><td><?= h(pct((int)$statusCounts["unknown"], $total)) ?></td></tr>
      <tr><th>Total</th><th><?= (int)$total ?></th><th><?= h(pct($total, $total)) ?></th></tr>
    </table>

    <div class="muted small" style="margin-top:10px;">
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
          <td><?= h(pct((int)$cnt, $total)) ?></td>
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

</body>
</html>

