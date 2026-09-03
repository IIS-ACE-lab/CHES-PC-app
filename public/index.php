<?php
declare(strict_types=1);
session_start();

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function bad_request(string $msg): void {
  http_response_code(400);

  $csp_nonce = base64_encode(random_bytes(16));
  header("Content-Security-Policy: default-src 'self'; style-src 'self' 'nonce-$csp_nonce'; frame-ancestors 'none'; base-uri 'none';");

  echo '<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Registration link problem</title>
<style nonce="' . $csp_nonce . '">
  body {
    font-family: system-ui, Arial, sans-serif;
    max-width: 720px;
    margin: 60px auto;
    padding: 0 16px;
  }
  .card {
    border: 1px solid #ddd;
    border-radius: 16px;
    padding: 24px;
    background: #fafafa;
  }
  h1 {
    margin-top: 0;
  }
  .error {
    color: #b00020;
    margin-top: 12px;
  }
</style>
</head>
<body>
  <div class="card">
    <h1>Registration link problem</h1>
    <p class="error">' . h($msg) . '</p>
    <p>Please check that you used the full link from the invitation email.</p>
    <p>Please contact the <a href="mailto:ches2027programchairs@iacr.org?subject=CHES%202027%20registration%20link%20problem">CHES 2027 Program Chairs</a> if you encounter any issues.</p>
  </div>
</body>
</html>';

  exit;
}


function csv_safe(string $s): string {
  $s = trim($s);
  if ($s !== '' && preg_match('/^[=\+\-@]/', $s)) return "'" . $s;
  return $s;
}

// ---- CONFIG ----
$config = require __DIR__ . '/../config/config.php';

$dbPath = $config['db_path'];
$auditLogPath = $config['audit_log_path'];
$suggestionPath = $config['suggestion_path'];


// Token format (match your generator)
$TOKEN_REGEX = '/^[a-f0-9]{32}$/'; // change to '/^[a-f0-9]{64}$/' if using 64-hex tokens

// Field limits
$MAX_EMAIL = 254;
$MAX_NAME  = 120;
$MAX_AFF   = 160;
$MAX_CTRY  = 80;
$MAX_CRYPTODB_ID = 12;

// CSP nonces
$csp_nonce = base64_encode(random_bytes(16));
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$csp_nonce'; style-src 'self' 'nonce-$csp_nonce'; frame-ancestors 'none'; base-uri 'none';");


function db(string $dbPath): PDO {
  static $pdo = null;

  if ($pdo === null) {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec("PRAGMA journal_mode = WAL;");
    $pdo->exec("PRAGMA synchronous = FULL;");
    $pdo->exec("PRAGMA foreign_keys = ON;");
  }

  return $pdo;
}

function init_db(PDO $pdo): void {
  $pdo->exec("
    CREATE TABLE IF NOT EXISTS reviewers (
      token TEXT PRIMARY KEY,
      invite_email TEXT NOT NULL UNIQUE,
      review_email TEXT,
      given_names TEXT,
      family_name TEXT,
      affiliation TEXT,
      ror_id TEXT,
      country TEXT,
      status TEXT NOT NULL DEFAULT 'invited',
      created_at TEXT,
      updated_at TEXT,
      expertise TEXT,
      cryptodb_mode TEXT,
      cryptodb_id TEXT
    );
  ");

  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_reviewers_status ON reviewers(status);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_reviewers_invite_email ON reviewers(invite_email);");
}

function append_audit_log_file(string $path, array $data): void {
  $dir = dirname($path);
  if (!is_dir($dir)) @mkdir($dir, 0775, true);

  $fh = fopen($path, "ab");
  if (!$fh) return;

  if (flock($fh, LOCK_EX)) {
    fwrite($fh, json_encode([
      "ts" => gmdate("c"),
      "data" => $data,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
    fflush($fh);
    flock($fh, LOCK_UN);
  }

  fclose($fh);
}

function append_reviewer_suggestions(
    string $path,
    string $inviteEmail,
    array $suggestions
): bool {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);

    $fh = fopen($path, "ab");
    if (!$fh) return false;

    $ok = false;

    if (flock($fh, LOCK_EX)) {
        $line = json_encode([
            "ts" => gmdate("c"),
            "invite_email" => $inviteEmail,
            "suggestions" => $suggestions,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

        $ok = fwrite($fh, $line) !== false;
        fflush($fh);
        flock($fh, LOCK_UN);
    }

    fclose($fh);
    return $ok;
}

function load_reviewer(PDO $pdo, string $token): ?array {
  $stmt = $pdo->prepare("SELECT * FROM reviewers WHERE token = ?");
  $stmt->execute([$token]);
  $row = $stmt->fetch();
  return $row ?: null;
}

function save_reviewer(PDO $pdo, string $auditLogPath, array $row): void {
  $token = (string)($row["token"] ?? "");
  if ($token === "") {
    http_response_code(500);
    die("Missing token");
  }

  $opId = bin2hex(random_bytes(8));

  $old = load_reviewer($pdo, $token);

  append_audit_log_file($auditLogPath, [
    "event" => "row_update_begin",
    "op_id" => $opId,
    "token" => $token,
    "old_row" => $old,
    "new_row" => $row,
  ]);

  try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare("
      INSERT INTO reviewers (
        token, invite_email, review_email,
        given_names, family_name,
        affiliation, ror_id, country,
        status, created_at, updated_at,
        expertise,
        cryptodb_mode, cryptodb_id
      ) VALUES (
        :token, :invite_email, :review_email,
        :given_names, :family_name,
        :affiliation, :ror_id, :country,
        :status, :created_at, :updated_at,
        :expertise,
        :cryptodb_mode, :cryptodb_id
      )
      ON CONFLICT(token) DO UPDATE SET
        invite_email = excluded.invite_email,
        review_email = excluded.review_email,
        given_names = excluded.given_names,
        family_name = excluded.family_name,
        affiliation = excluded.affiliation,
        ror_id = excluded.ror_id,
        country = excluded.country,
        status = excluded.status,
        created_at = COALESCE(reviewers.created_at, excluded.created_at),
        updated_at = excluded.updated_at,
        expertise = excluded.expertise,
        cryptodb_mode = excluded.cryptodb_mode,
        cryptodb_id = excluded.cryptodb_id
    ");

    $stmt->execute([
      ":token" => $row["token"] ?? "",
      ":invite_email" => $row["invite_email"] ?? "",
      ":review_email" => $row["review_email"] ?? "",
      ":given_names" => $row["given_names"] ?? "",
      ":family_name" => $row["family_name"] ?? "",
      ":affiliation" => $row["affiliation"] ?? "",
      ":ror_id" => $row["ror_id"] ?? "",
      ":country" => $row["country"] ?? "",
      ":status" => $row["status"] ?? "invited",
      ":created_at" => $row["created_at"] ?? "",
      ":updated_at" => $row["updated_at"] ?? "",
      ":expertise" => $row["expertise"] ?? "",
      ":cryptodb_mode" => $row["cryptodb_mode"] ?? "",
      ":cryptodb_id" => $row["cryptodb_id"] ?? "",
    ]);

    $pdo->commit();

    append_audit_log_file($auditLogPath, [
      "event" => "row_update_commit",
      "op_id" => $opId,
      "token" => $token,
      "status" => $row["status"] ?? "",
    ]);
  } catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();

    append_audit_log_file($auditLogPath, [
      "event" => "row_update_fail",
      "op_id" => $opId,
      "token" => $token,
      "error" => $e->getMessage(),
    ]);

    http_response_code(500);
    die("Database update failed.");
  }
}

$pdo = db($dbPath);
init_db($pdo);

// CSRF
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

// Token from URL
$token = $_GET['t'] ?? '';
if (!preg_match($TOKEN_REGEX, $token)) {
  bad_request("Invalid or missing token.");
}

$saved = ($_GET['saved'] ?? '') === '1';

// Load record
$row = load_reviewer($pdo, $token);
if (!$row) bad_request("This registration link was not found.");


$invite_email = $row["invite_email"];
$review_email = $row["review_email"] !== "" ? $row["review_email"] : $invite_email;
$given_names  = $row["given_names"] ?? "";
$family_name  = $row["family_name"] ?? "";
$affiliation  = $row["affiliation"];
$ror_id       = $row["ror_id"] ?? "";
$country      = $row["country"];
$cryptodb_id   = $row["cryptodb_id"] ?? "";
$cryptodb_mode = trim((string)($row["cryptodb_mode"] ?? ""));
$status       = strtolower(trim($row["status"] ?: "invited"));
$created_at   = $row["created_at"];
$updated_at   = $row["updated_at"];
$expertise_raw   = trim($row["expertise"] ?? "");

if (!in_array($cryptodb_mode, ["auto","manual","none", ""], true)) {
  $cryptodb_mode = ($cryptodb_id !== "") ? "auto" : "none";
}

$EXPERTISE_TAXONOMY = $config['expertise_taxonomy'] ?? [];

$expertise_set = [];
if ($expertise_raw !== "") {
  foreach (explode("|", $expertise_raw) as $tag) {
    $tag = trim($tag);
    if ($tag !== "") $expertise_set[$tag] = true;
  }
}

$errors = [];
$mode = "gate"; // gate (accept/decline) or form
if ($status === "accepted" || $status === "registered") $mode = "form";
if ($status === "declined") $mode = "gate";

$suggestion_saved = false;

// ---- POST handler ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $posted_csrf = $_POST['csrf'] ?? '';
  if (!hash_equals($_SESSION['csrf'], $posted_csrf)) {
    bad_request("Security check failed. Please reload and try again.");
  }

  $action = $_POST['action'] ?? '';

  if ($status === 'registered' && ($action === 'accept' || $action === 'decline')) {
    bad_request("This invitation is already registered and cannot be changed here.");
  }

  // Gate actions
  if ($action === 'accept') {
    $now = gmdate("c");
    $newRow = [
      "token"           => $token,
      "invite_email"    => $invite_email,
      "review_email"    => csv_safe($review_email),
      "given_names"     => csv_safe($given_names),
      "family_name"     => csv_safe($family_name),
      "affiliation"     => csv_safe($affiliation),
      "ror_id"          => csv_safe($ror_id),
      "cryptodb_id"     => csv_safe($cryptodb_id),
      "cryptodb_mode"   => csv_safe($cryptodb_mode),
      "country"         => csv_safe($country),
      "status"          => "accepted",
      "created_at"      => $created_at ?: $now,
      "updated_at"      => $now,
      "expertise"       => csv_safe($expertise_raw ?? ""),
    ];
    //rewrite_csv_with_row_update($csvPath, $newRow);
    save_reviewer($pdo, $auditLogPath, $newRow);

    // reload in-memory state for rendering
    $status = "accepted";
    $updated_at = $now;
    $mode = "form";
  }
  elseif ($action === 'decline') {
    $now = gmdate("c");
    $newRow = [
      "token"           => $token,
      "invite_email"    => $invite_email,
      "review_email"    => csv_safe($review_email),
      "given_names"     => csv_safe($given_names),
      "family_name"     => csv_safe($family_name),
      "affiliation"     => csv_safe($affiliation),
      "ror_id"          => csv_safe($ror_id),
      "cryptodb_id"     => csv_safe($cryptodb_id),
      "cryptodb_mode"   => csv_safe($cryptodb_mode),
      "country"         => csv_safe($country),
      "status"          => "declined",
      "created_at"      => $created_at ?: $now,
      "updated_at"      => $now,
      "expertise"       => csv_safe($expertise_raw ?? ""),
    ];
    //rewrite_csv_with_row_update($csvPath, $newRow);
    save_reviewer($pdo, $auditLogPath, $newRow);

    $status = "declined";
    $updated_at = $now;
    $mode = "declined";
  }
  elseif ($action === 'suggest') {
      if ($status !== 'declined') {
          bad_request("Reviewer suggestions can only be submitted after declining.");
      }
  
      $names = $_POST['suggestion_name'] ?? [];
      $emails = $_POST['suggestion_email'] ?? [];
      $affiliations = $_POST['suggestion_affiliation'] ?? [];
  
      if (!is_array($names) ||
          !is_array($emails) ||
          !is_array($affiliations)) {
          bad_request("Invalid reviewer suggestion.");
      }
  
      $suggestions = [];
      $n = max(count($names), count($emails), count($affiliations));
  
      for ($i = 0; $i < $n; $i++) {
          $name = trim((string)($names[$i] ?? ''));
          $email = trim((string)($emails[$i] ?? ''));
          $affiliation = trim((string)($affiliations[$i] ?? ''));
  
          // Ignore the automatically generated empty row.
          if ($name === '' && $email === '' && $affiliation === '') {
              continue;
          }
  
          if ($name === '') {
              $errors[] = "Please enter a name for each suggested reviewer.";
              continue;
          }
  
          if ($email !== '' &&
              !filter_var($email, FILTER_VALIDATE_EMAIL)) {
              $errors[] = "Invalid email address for suggested reviewer: " . $name;
              continue;
          }
  
          $suggestions[] = [
              "name" => $name,
              "email" => $email,
              "affiliation" => $affiliation,
          ];
      }
  
      if (!$suggestions && !$errors) {
          $errors[] = "Please enter at least one reviewer suggestion.";
      }
  
      if (!$errors) {
          if (!append_reviewer_suggestions(
              $suggestionPath,
              $invite_email,
              $suggestions
          )) {
              http_response_code(500);
              die("Could not save reviewer suggestions.");
          }
  
          $suggestion_saved = true;
      }
  
      $mode = "declined";
  }
  // Form save
  elseif ($action === 'save') {
    // If someone declined, don't allow editing (simple policy)
    if ($status === "declined") {
      echo "<h2>Invitation declined</h2><p>This invitation was declined. If this is a mistake, please contact the PC Chairs.</p>";
      exit;
    }

    $review_email = trim((string)($_POST['review_email'] ?? ''));
    $given_names = trim((string)($_POST['given_names'] ?? ''));
    $family_name = trim((string)($_POST['family_name'] ?? ''));
    $affiliation  = trim((string)($_POST['affiliation'] ?? ''));
    $ror_id = trim((string)($_POST['ror_id'] ?? ''));
    $country      = trim((string)($_POST['country'] ?? ''));


    // ---- CryptoDB radio selection ----
    $cryptodb_mode_post = trim((string)($_POST["cryptodb_mode"] ?? ""));
    $cryptodb_id_post   = trim((string)($_POST["cryptodb_id"] ?? ""));       // hidden field set by JS (auto)
    $cryptodb_manual    = trim((string)($_POST["cryptodb_manual"] ?? ""));   // manual input
    
    // digits-only sanitizer
    $only_digits = function(string $s): string {
      return preg_replace('/\D+/', '', $s) ?? '';
    };
    
    $cryptodb_mode = "none";
    $cryptodb_id   = "";
    
    // Decide based on radio selection
    if ($cryptodb_mode_post === "auto") {
      $id = $only_digits($cryptodb_id_post);
      if ($id !== "" && strlen($id) <= $MAX_CRYPTODB_ID) {
        $cryptodb_mode = "auto";
        $cryptodb_id = $id;
      } else {
        // If auto selected but nothing usable -> treat as none (or make it an error if you prefer)
        $cryptodb_mode = "none";
        $cryptodb_id = "";
      }
    }
    elseif ($cryptodb_mode_post === "manual") {
      $id = $only_digits($cryptodb_manual);
      if (strlen($id) > $MAX_CRYPTODB_ID) {
        $errors[] = "CryptoDB author ID is too long.";
      } else {
        $cryptodb_mode = "manual";
        $cryptodb_id = $id;
      }
    }
    else {
      // No selection => none
      $cryptodb_mode = "none";
      $cryptodb_id = "";
    }


    $ALLOWED_TOPICS = [];
    foreach ($EXPERTISE_TAXONOMY as $cat => $topics) {
      foreach ($topics as $t) $ALLOWED_TOPICS[$t] = true;
    }
    
    $expertise_post = $_POST["expertise"] ?? [];
    if (!is_array($expertise_post)) $expertise_post = [];
    
    $tmp = [];
    foreach ($expertise_post as $x) {
      $x = trim((string)$x);
      if ($x === "") continue;
      if (isset($ALLOWED_TOPICS[$x])) $tmp[$x] = true;
    }
    
    $keys = array_keys($tmp);
    sort($keys, SORT_STRING);          // stable ordering for diffs
    $expertise_raw = implode("|", $keys);


    // Rebuild set so checkboxes reflect POSTed values even if we show errors
    $expertise_set = [];
    if ($expertise_raw !== "") {
      foreach (explode("|", $expertise_raw) as $tag) {
        $tag = trim($tag);
        if ($tag !== "") $expertise_set[$tag] = true;
      }
    }
    
    if ($review_email === '') {
      $errors[] = "Please enter the email address you want us to use for reviewing.";
    } elseif (strlen($review_email) > $MAX_EMAIL) {
      $errors[] = "Email address is too long (max {$MAX_EMAIL} characters).";
    } elseif (!filter_var($review_email, FILTER_VALIDATE_EMAIL)) {
      $errors[] = "Please enter a valid email address.";
    }

    if ($given_names === '') {
      $errors[] = "Please enter your given name(s).";
    } elseif (strlen($given_names) > 120) {
      $errors[] = "Given name(s) is too long (max 120 characters).";
    }
    
    if ($family_name === '') {
      $errors[] = "Please enter your family name (surname).";
    } elseif (strlen($family_name) > 120) {
      $errors[] = "Family name is too long (max 120 characters).";
    }

    if ($affiliation === '') {
      $errors[] = "Please enter your affiliation.";
    } elseif (strlen($affiliation) > $MAX_AFF) {
      $errors[] = "Affiliation is too long (max {$MAX_AFF} characters).";
    }

    if ($country === '') {
      $errors[] = "Please enter your country.";
    } elseif (strlen($country) > $MAX_CTRY) {
      $errors[] = "Country is too long (max {$MAX_CTRY} characters).";
    }

    if (!$errors) {
      $now = gmdate("c");
      $newRow = [
        "token"           => $token,
        "invite_email"    => $invite_email,                 // immutable anchor
        "review_email"    => csv_safe($review_email),        // editable
        "given_names"     => csv_safe($given_names),
        "family_name"     => csv_safe($family_name),
        "affiliation"     => csv_safe($affiliation),
        "ror_id"          => csv_safe($ror_id),
        "country"         => csv_safe($country),
        "cryptodb_id"     => csv_safe($cryptodb_id),
        "cryptodb_mode"   => csv_safe($cryptodb_mode),
        "status"          => "registered",                  // after saving details
        "created_at"      => $created_at ?: $now,
        "updated_at"      => $now,
        "expertise"       => csv_safe($expertise_raw ?? ""),
      ];
      //rewrite_csv_with_row_update($csvPath, $newRow);
      save_reviewer($pdo, $auditLogPath, $newRow);

      header("Location: ?t=" . urlencode($token) . "&saved=1");
      exit;
    }

    // show form again with errors
    $mode = "form";
  }
  else {
    bad_request("Unknown action.");
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Reviewer Invitation</title>
  <style nonce="<?= h($csp_nonce) ?>">
    body { font-family: system-ui, Arial, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }
    .card { border: 1px solid #ddd; border-radius: 14px; padding: 16px; margin-top: 14px; }
    label { display:block; margin-top: 14px; font-weight: 600; }
    input { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; }
    .btnrow { display:flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
    button { padding: 10px 14px; font-size: 16px; cursor:pointer; }
    .primary { font-weight: 700; min-width: 160px; }
    .error { background: #ffecec; border: 1px solid #ffb3b3; padding: 10px; margin-top: 16px; border-radius: 10px; }
    .hint { color: #444; font-size: 14px; margin-top: 6px; }
    .meta { color: #333; font-size: 14px; line-height: 1.4; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 6px; }
    /* highlight required fields that are empty */
    .req-empty { border: 2px solid #c33; background: #fff3f3; }
    .req-empty:focus { outline: none; }
    label.req::after { content: " *"; color: #c33; font-weight: 700; }
    legend.req::after { content: " *"; color: #c33; font-weight: 700; }
    *, *::before, *::after { box-sizing: border-box; }

.hint-secondary {
  font-size: 13.5px;
  color: #666;
}

.overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.25);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
}

.overlay-card {
  background: #fff;
  border-radius: 16px;
  padding: 22px;
  display: flex;
  gap: 14px;
  align-items: flex-start;
  box-shadow: 0 12px 35px rgba(0,0,0,0.2);
  max-width: 480px;
  width: calc(100% - 32px);
}

.check {
  width: 36px;
  height: 36px;
  border-radius: 999px;
  background: #e9f7ef;
  display: grid;
  place-items: center;
  font-size: 20px;
  font-weight: 800;
}

.overlay-title {
  font-weight: 800;
  font-size: 18px;
}

.overlay-text {
  margin-top: 6px;
  color: #333;
  font-size: 14px;
  line-height: 1.5;
}

.overlay-actions {
  margin-top: 22px;
}

.hidden { display: none; }

.suggest {
  margin-top: 6px;
  border: 1px solid #ddd;
  border-radius: 10px;
  background: #fff;
  overflow: hidden;
}

.suggest .item {
  padding: 10px 12px;
  cursor: pointer;
  font-size: 14px;
}

.suggest .item:hover {
  background: #f5f5f5;
}

.suggest .sub {
  display: block;
  color: #666;
  font-size: 12px;
  margin-top: 2px;
}

.suggest .item.active {
  background: #eaeaea;
}

.expertise-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 18px;
  margin-top: 10px;
}
.expertise-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-weight: 500;
  margin-top: 0;
}
.expertise-item input {
  width: auto;
  margin-top: 2px;
}

.expertise-cats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px 14px;
  margin-top: 10px;
}

@media (max-width: 720px) {
  .expertise-cats { grid-template-columns: 1fr; }
}

.expertise-cat {
  border: 1px solid #ddd;
  border-radius: 12px;
  padding: 10px 12px;
  background: #fff;
}

.expertise-cat-title {
  font-weight: 700;
  margin: 0 0 8px 0;
}

.expertise-items {
  display: grid;
  grid-template-columns: 1fr;
  gap: 6px;
}

.expertise-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-weight: 500;
  margin: 0;
}
.expertise-item input {
  width: auto;
  margin-top: 2px;
}

.expertise-cats > .expertise-cat:last-of-type {
  grid-column: 1 / -1;
}

.sticky-save {
  position: sticky;
  bottom: 0;
  background: rgba(255,255,255,0.95);
  backdrop-filter: blur(6px);
  border-top: 1px solid #ddd;
  padding: 12px 0;
  margin-top: 20px;
}

.sticky-save .btnrow {
  margin-top: 0;
}

/*form {
  padding-bottom: 80px;
}*/

.rows { margin-top: 8px; display: grid; gap: 10px; }
.row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 10px;
}
.row input { width: 100%; }
.row .smallhint { font-size: 12px; color: #666; margin-top: 4px; }

.name-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

@media (max-width: 720px) {
  .name-row {
    grid-template-columns: 1fr;
  }
}

/* optional: keep labels from adding extra top margin inside the row */
.name-row label { margin-top: 14px; }
.name-row > div:first-child label { margin-top: 14px; }

.cryptodb-choice {
  display: grid;
  gap: 0px;              /* 0px looks cramped; 4–6px feels better */
  margin-top: 10px;
}

.cryptodb-radio {
  display: flex;
  gap: 10px;
  align-items: center;
  margin: 0;
  line-height: 1.3;      /* slightly tighter */
}

.cryptodb-radio span {
  display: flex;
  align-items: center;
  gap: 8px;
}

.cryptodb-id-link {
  font-weight: 600;
  text-decoration: underline;
  color: #5a2ca0;   /* subtle academic purple */
}

.cryptodb-id-link:hover {
  text-decoration: none;
}

.cryptodb-radio input[type="radio"] { width: auto; margin-top: -1px; }
.cryptodb-manual { width: 260px; max-width: 100%; }

fieldset.mt {
  padding: 5px 16px 14px 16px;
  border-radius: 8px;
}

legend {
  font-weight: 600;
  padding: 0 6px;
}

.nomargin { margin: 0; }

.mb { margin-bottom: 7.5pt; }
.mt { margin-top: 20pt; }
.mt10 { margin-top: 10pt; }
.mt5 { margin-top: 5pt; }
.mt0 { margin-top: 0pt; }

.hidden {
  display: none;
}

.reviewer-suggestion-rows {
  display: grid;
  gap: 8px;
  margin-top: 12px;
}

.reviewer-suggestion-header,
.reviewer-suggestion-row {
  display: grid;
  grid-template-columns: 1.2fr 1.4fr 1.4fr;
  gap: 10px;
}

.reviewer-suggestion-header {
  font-weight: 600;
  font-size: 14px;
}

.reviewer-suggestion-row input {
  margin-top: 0;
}

@media (max-width: 720px) {
  .reviewer-suggestion-header {
    display: none;
  }

  .reviewer-suggestion-row {
    grid-template-columns: 1fr;
  }
}

  </style>
</head>
<body>
  <h1>CHES 2027</h1>


<?php if (false) : ?>
  <h2>Reviewer Invitation</h2>

  <div class="card">
    <div class="meta">
      Invitation email sent to: <code><?= h($invite_email) ?></code><br/>
      Status: <code><?= h($status) ?></code><br/>
      <!--Created: <code><?= h($created_at) ?></code><br/>-->
      <?php if ($updated_at !== ""): ?>
        Last updated:
        <code><span id="lastUpdated" data-ts="<?= h($updated_at) ?>"><?= h($updated_at) ?></span></code>
      <?php else: ?>
        Last updated: <code>(not yet)</code>
      <?php endif; ?>
    </div>
  </div>
<?php endif; ?>

  <?php if ($mode === "gate"): ?>
    <div class="card">
     <?php
       $parts = array_filter([$given_names, $family_name], fn($x) => trim($x) !== "");
       $display_name = implode(" ", $parts);
     ?>
     
     <?php if ($display_name !== ""): ?>
       <h3>Dear <?= h($display_name) ?>,</h3>
     <?php endif; ?>

     <?php if ($status === "declined"): ?>
        <p><strong>You previously declined.</strong> If you changed your mind, you can accept below.</p>
      <?php else: ?>
        <p>Do you accept this invitation to serve as a reviewer?</p>
      <?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>" />
        <div class="btnrow">
          <button class="primary" type="submit" name="action" value="accept">Accept invitation</button>
          <button type="submit" name="action" value="decline">Decline invitation</button>
        </div>
      </form>

      <p class="hint">If you accept, you will be asked to confirm your details on the next page.</p>
    </div>

  <?php elseif ($mode === "declined"): ?>
    <div class="card">
      <h2>Invitation declined</h2>
  
      <p>
        Thank you for letting us know.
        If this was a mistake, please <a href="?t=<?= h($token) ?>">click here</a>.
      </p>
  
      <?php if ($suggestion_saved): ?>
  
        <p><strong>Thank you for the reviewer suggestion.</strong></p>
  
      <?php else: ?>

        <p>
          If you would like to suggest other potential reviewers, you can
          enter their details below. Only the name is required.
        </p>
        
        <form method="post" id="reviewerSuggestionForm">
          <input type="hidden"
                 name="csrf"
                 value="<?= h($_SESSION['csrf']) ?>">
        
          <input type="hidden"
                 name="action"
                 value="suggest">
        
          <div id="reviewerSuggestionRows" class="reviewer-suggestion-rows">
          </div>
        
          <div class="hint">
            Additional rows appear automatically as you enter suggestions.
          </div>
        
          <div class="btnrow">
            <button type="submit">Submit suggestion(s)</button>
          </div>
        </form>
 
      <?php endif; ?>
    </div>

  <?php else: /* form */ ?>
    <div class="card">
      <h2 class="mt0">Reviewer details</h2>
      <p>Please confirm or edit your details, then save.</p>
      <p class="hint">Fields marked with * are required.</p>

      <?php if ($errors): ?>
        <div class="error">
          <strong>Please fix the following:</strong>
          <ul>
            <?php foreach ($errors as $e): ?>
              <li><?= h($e) ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <form method="post" autocomplete="on">
        <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>" />
        <input type="hidden" name="action" value="save" />

        <fieldset class="mt">
          <legend>Name and email address:</legend>

          <label class="req" for="review_email">Email address for reviewing:</label>
          <input id="review_email" name="review_email" type="email" required maxlength="<?= h((string)$MAX_EMAIL) ?>"
                 value="<?= h($review_email) ?>" />
          <div class="hint">We will use this email address for all reviewer-related communication and for your account in the review system.</div>

          <div class="name-row">
            <div>
              <label class="req" for="given_names">Given name(s):</label>
              <input id="given_names" name="given_names" required maxlength="<?= h((string)$MAX_GIVEN) ?>"
                     value="<?= h($given_names) ?>" autocomplete="given-name" />
            </div>
          
            <div>
              <label class="req" for="family_name">Family name:</label>
              <input id="family_name" name="family_name" required maxlength="<?= h((string)$MAX_FAMILY) ?>"
                     value="<?= h($family_name) ?>" autocomplete="family-name" />
            </div>
          </div>
          
          <div class="hint">
            Please enter your name exactly as it should appear on the conference website.
          </div>
          <div class="hint hint-secondary">
            Format: Given name(s) followed by family name.
          </div>
          
          <?php
            $preview_name = trim(($given_names ?? '') . ' ' . ($family_name ?? ''));
          ?>
          <div id="namePreviewWrap" class="hint hint-secondary<?= $preview_name === '' ? ' hidden' : '' ?>">
            Preview: <strong id="namePreviewText"><?= h($preview_name) ?></strong>
          </div>
        </fieldset>


        <fieldset class="mt">
          <legend class="req">Affiliation(s) with country:</legend>
       
          <div id="affCountryRows" class="rows"></div>
          
          <!-- Keep your original inputs as hidden fields so backend stays unchanged -->
          <input type="hidden" id="affiliation" name="affiliation" value="<?= h($affiliation) ?>" />
          <input type="hidden" id="country" name="country" value="<?= h($country) ?>" />

          <div id="aff_suggest" class="suggest hidden"></div>
          <div id="country_suggest" class="suggest hidden"></div>
          
          <div class="hint-secondary mt5 mb">
            Add multiple entries &mdash; a new row appears automatically.
          </div>

          <div class="hint">Enter your university or company name (not department/lab/address).</div>
          <div class="hint mb">Countries are used only for statistics.</div>
        </fieldset>
 

        <fieldset class="mt">
          <legend>CryptoDB author ID:</legend>

          <div class="cryptodb-choice">
            <label class="cryptodb-radio">
              <input type="radio" name="cryptodb_mode" id="cryptodb_mode_auto" value="auto">
              <span>
                Use auto-detected ID:
                <span id="cryptodb_auto_wrap">
                  <!-- JS will fill either a link or “not found” -->
                  <span id="cryptodb_auto_missing" class="cryptodb-id-missing">Not found</span>
                </span>
              </span>
            </label>
          
            <label class="cryptodb-radio">
              <input type="radio" name="cryptodb_mode" id="cryptodb_mode_manual" value="manual">
              <span>
                Enter ID manually:
                <input id="cryptodb_manual" name="cryptodb_manual" type="text" inputmode="numeric"
                       placeholder="Digits only" class="cryptodb-manual" disabled>
              </span>
            </label>

            <label class="cryptodb-radio">
              <input type="radio" name="cryptodb_mode" id="cryptodb_mode_none" value="none">
              <span>Leave blank</span>
            </label>
          </div>

          <div class="hint mt10">
           The CryptoDB author ID links your PC service to your record in
           <a href="https://iacr.org/cryptodb/" target="_blank" rel="noopener noreferrer">IACR's CryptoDB</a>.</br>
           If you do not yet have one, you may leave this blank.
          </div>
 
          <div class="hint hint-secondary">
             You can look up an existing author ID <a href="https://iacr.org/cryptodb/doc/suggest.php" target="_blank" rel="noopener noreferrer">here</a>.
          </div>
          
          
          <input type="hidden" id="cryptodb_id_saved" name="cryptodb_id" value="<?= h($cryptodb_id) ?>">
          <input type="hidden" id="cryptodb_mode_saved" value="<?= h($cryptodb_mode) ?>">
        </fieldset>
       

        <fieldset class="mt">
          <legend>Areas of expertise (optional):</legend>

          <div class="expertise-cats">
            <?php foreach ($EXPERTISE_TAXONOMY as $cat => $topics): ?>
              <div class="expertise-cat">
                <div class="expertise-cat-title"><?= h($cat) ?></div>
        
                <div class="expertise-items">
                  <?php foreach ($topics as $opt): ?>
                    <label class="expertise-item">
                      <input type="checkbox"
                             name="expertise[]"
                             value="<?= h($opt) ?>"
                             <?= isset($expertise_set[$opt]) ? "checked" : "" ?>>
                      <?= h($opt) ?>
                    </label>
                  <?php endforeach; ?>
                </div>
              </div>
            <?php endforeach; ?>
          </div>

          <div class="hint mt5">
            Select areas where you feel comfortable reviewing CHES-level submissions.
          </div>

          <div class="hint-secondary mt5">
            Used internally by the PC Chairs to assess expertise coverage.
          </div>
        </fieldset>

        <p>
          The submitted information will only be used for conference organization purposes and will not be shared outside the organizing committee.
        </p>

        <div class="sticky-save">
          <div class="btnrow">
            <button class="primary" type="submit">Save details</button>
          </div>
        </div>

      </form>
    </div>

    <?php if ($saved): ?>
      <div id="savedOverlay" class="overlay" role="dialog" aria-modal="true">
        <div class="overlay-card">
          <div class="check">✓</div>
    
          <div class="overlay-body">
            <div class="overlay-title">Details saved</div>
            <div class="overlay-text">
              Your reviewer details have been successfully updated.
              <br><br>
              You can close this page if you are finished.
            </div>
    
            <div class="overlay-actions">
            <form method="get" class="nomargin">
              <input type="hidden" name="t" value="<?= h($token) ?>">
              <button class="primary" type="submit">Return to form</button>
            </form>
            </div>
          </div>
        </div>
      </div>
    <?php endif; ?>

  <?php endif; ?>

  <script nonce="<?= h($csp_nonce) ?>" src="countries.js"></script>

  <script nonce="<?= h($csp_nonce) ?>">
    const el = document.getElementById("lastUpdated");
    if (el) {
      const ts = el.getAttribute("data-ts");
      if (ts) {
        const d = new Date(ts);
        if (!isNaN(d.getTime())) el.textContent = d.toLocaleString();
      }
    }

    function sanitizePipeInput(el) {
      if (!el) return;
      //el.value = (el.value || "").replaceAll("|", "/");
    }

    (function () {
      const requiredFields = document.querySelectorAll("input[required]");
      let submitting = false;
    
      // Any submit anywhere on the page counts as a real submit
      document.addEventListener("submit", () => {
        submitting = true;
      }, true);
    
      function hasEmptyRequiredFields() {
        for (const el of requiredFields) {
          if (!el.value.trim()) return true;
        }
        return false;
      }
    
      window.addEventListener("beforeunload", (e) => {
        if (submitting) return;
        if (!hasEmptyRequiredFields()) return;
    
        e.preventDefault();
        e.returnValue = "";
      });
    })();

    (function () {
      // Only target inputs that are required
      const inputs = document.querySelectorAll("input[required]");
    
      function update(el) {
        const empty = !el.value || !el.value.trim();
        el.classList.toggle("req-empty", empty);
      }
    
      // On page load, mark empties
      inputs.forEach((el) => {
        update(el);
        // Update live as user types/changes
        el.addEventListener("input", () => update(el));
        el.addEventListener("blur",  () => update(el));
      });
    })();

    (function () {
      const given = document.getElementById("given_names");
      const family = document.getElementById("family_name");
      const wrap = document.getElementById("namePreviewWrap");
      const text = document.getElementById("namePreviewText");
      if (!given || !family || !wrap || !text) return;
    
      function update() {
        const g = (given.value || "").trim();
        const f = (family.value || "").trim();
        const v = (g + " " + f).trim();
    
        if (!v) {
          wrap.classList.add("hidden");
          text.textContent = "";
          return;
        }
        wrap.classList.remove("hidden");
        text.textContent = v;
      }
    
      given.addEventListener("input", update);
      family.addEventListener("input", update);
      update(); // initial
    })();
   
    (function () {
      const rowsEl = document.getElementById("affCountryRows");
      const affHidden = document.getElementById("affiliation"); // hidden field (CSV)
      const ctryHidden = document.getElementById("country");    // hidden field (CSV)
      if (!rowsEl || !affHidden || !ctryHidden) return;

      function splitPipe(s) {
        if (!s) return [];
      
        const out = [];
        let cur = "";
        let escaping = false;
      
        for (let i = 0; i < s.length; i++) {
          const ch = s[i];
      
          if (escaping) {
            cur += ch;          // literal char after "\"
            escaping = false;
          } else if (ch === "\\") {
            escaping = true;
          } else if (ch === "|") {
            out.push(cur.trim());  // KEEP empties
            cur = "";
          } else {
            cur += ch;
          }
        }
        out.push(cur.trim());
      
        // drop trailing empty fields only
        while (out.length && out[out.length - 1] === "") out.pop();
      
        return out;
      }

      function escapePipeField(s) {
        return String(s ?? "")
          .replaceAll("\\", "\\\\")  // escape backslash first
          .replaceAll("|", "\\|");   // then escape pipe
      }
      
      function joinPipe(arr) {
        const parts = (arr || []).map(x => String(x ?? "").trim());
      
        // drop trailing empties only
        while (parts.length && parts[parts.length - 1] === "") parts.pop();
      
        return parts.map(escapePipeField).join(" | ");
      }
    
      function readPairsFromHidden() {
        const affs = splitPipe(affHidden.value);
        const ctrys = splitPipe(ctryHidden.value);
        const n = Math.max(affs.length, ctrys.length);
    
        const pairs = [];
        for (let i = 0; i < n; i++) {
          pairs.push({
            aff: affs[i] || "",
            ctry: ctrys[i] || ""
          });
        }
        return pairs;
      }
    
      function writeHiddenFromRows() {
        const rows = [...rowsEl.querySelectorAll(".row")];
      
        // find last row that has ANY content (aff or country)
        let lastUsed = -1;
        for (let i = 0; i < rows.length; i++) {
          const a = rows[i].querySelector('input[data-kind="aff"]')?.value.trim() || "";
          const c = rows[i].querySelector('input[data-kind="ctry"]')?.value.trim() || "";
          if (a !== "" || c !== "") lastUsed = i;
        }
      
        const affs = [];
        const ctrys = [];
      
        for (let i = 0; i <= lastUsed; i++) {
          const row = rows[i];
          const a = row.querySelector('input[data-kind="aff"]')?.value.trim() || "";
          const c = row.querySelector('input[data-kind="ctry"]')?.value.trim() || "";
          affs.push(a);     // KEEP empties
          ctrys.push(c);    // KEEP empties
        }
      
        affHidden.value = joinPipe(affs);
        ctryHidden.value = joinPipe(ctrys);
      }
    
      function makeRow(affVal, ctryVal) {
        const row = document.createElement("div");
        row.className = "row";
    
        const aff = document.createElement("input");
        aff.type = "text";
        aff.placeholder = "Affiliation (e.g., University of X)";
        aff.value = affVal || "";
        aff.dataset.kind = "aff";
        aff.autocomplete = "off";
        aff.classList.add("aff-input");

        const ctry = document.createElement("input");
        ctry.type = "text";
        ctry.placeholder = "Country";
        ctry.value = ctryVal || "";
        ctry.dataset.kind = "ctry";
        ctry.autocomplete = "off";
        ctry.classList.add("country-input"); 
    
        function onEdit() {
          writeHiddenFromRows();
          ensureTrailingEmptyRow();
          // trigger your existing required-field highlighter logic
          affHidden.dispatchEvent(new Event("input"));
          ctryHidden.dispatchEvent(new Event("input"));
        }
    
        aff.addEventListener("input", onEdit);
        ctry.addEventListener("input", onEdit);
    
        row.appendChild(aff);
        row.appendChild(ctry);
        return row;
      }
    
      function ensureTrailingEmptyRow() {
        const rows = [...rowsEl.querySelectorAll(".row")];
        if (rows.length === 0) {
          rowsEl.appendChild(makeRow("", ""));
          return;
        }
        const last = rows[rows.length - 1];
        const a = last.querySelector('input[data-kind="aff"]')?.value.trim() || "";
        const c = last.querySelector('input[data-kind="ctry"]')?.value.trim() || "";
        if (a !== "" || c !== "") {
          rowsEl.appendChild(makeRow("", ""));
        }
      }
    
      function renderInitial() {
        rowsEl.innerHTML = "";
        const pairs = readPairsFromHidden();
        if (pairs.length === 0) {
          rowsEl.appendChild(makeRow("", ""));
        } else {
          for (const p of pairs) rowsEl.appendChild(makeRow(p.aff, p.ctry));
          ensureTrailingEmptyRow();
        }
        writeHiddenFromRows();
      }
    
      renderInitial();
    })();

    (function () {
      const box = document.getElementById("aff_suggest");
      const rorHidden = document.getElementById("ror_id"); // still hidden; keep if you want
      if (!box) return;
    
      let activeInput = null;     // the focused affiliation input (per-row)
      let timer = null;
      let activeIndex = -1;
      let currentResults = [];
    
      function clearSuggestions() {
        box.classList.add("hidden");
        box.innerHTML = "";
        activeIndex = -1;
        currentResults = [];
      }
    
      function updateActive() {
        const items = box.querySelectorAll(".item");
        items.forEach((el, i) => el.classList.toggle("active", i === activeIndex));
      }
    
      function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, c => (
          { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;" }[c]
        ));
      }
    
      async function search(q) {
        const res = await fetch(`ror_search.php?q=${encodeURIComponent(q)}`);
        if (!res.ok) return null;
        return await res.json();
      }
    
      function positionBoxUnderInput(input) {
        // Put the suggestion box right below the active input
        const r = input.getBoundingClientRect();
        box.style.position = "absolute";
        box.style.left = (window.scrollX + r.left) + "px";
        box.style.top  = (window.scrollY + r.bottom + 6) + "px";
        box.style.width = r.width + "px";
      }
    
      function render(results, queryLower) {
        box.innerHTML = "";
        currentResults = results || [];
        activeIndex = -1;
    
        if (!results || results.length === 0) { clearSuggestions(); return; }
    
        // hide only if exactly 1 match and equals query
        if (results.length === 1) {
          const n = (results[0].name || "").trim().toLowerCase();
          if (n === queryLower) { clearSuggestions(); return; }
        }
    
        for (let i = 0; i < results.length; i++) {
          const r = results[i];
          const div = document.createElement("div");
          div.className = "item";
          div.innerHTML = `
            <strong>${escapeHtml(r.name || "")}</strong>
            ${r.country ? `<span class="sub">${escapeHtml(r.country)}</span>` : ""}
          `;
    
          div.addEventListener("mouseenter", () => {
            activeIndex = i;
            updateActive();
          });
          div.addEventListener("click", () => selectResult(r));
    
          box.appendChild(div);
        }
    
        box.classList.remove("hidden");
      }
    
      function selectResult(r) {
        if (!activeInput) return;
    
        // Fill the affiliation cell (this row)
        activeInput.value = (r.name || "").trim();
        activeInput.dispatchEvent(new Event("input"));
    
        // If you keep ror_id at all, it’s ambiguous with multiple rows.
        // Easiest: clear it.
        if (rorHidden) rorHidden.value = "";
    
        // Fill country in *same row*:
        const row = activeInput.closest(".row");
        const countryInput = row ? row.querySelector(".country-input") : null;
        if (countryInput && r.country) {
          const c = r.country.trim();
          if (c) {
            const existing = countryInput.value.trim();
            if (!existing) {
              countryInput.value = c;
            }
            countryInput.dispatchEvent(new Event("input"));
          }
        }
    
        clearSuggestions();
        activeInput.focus();
      }
    
      // Event delegation: focus/input/keydown for any .aff-input
      document.addEventListener("focusin", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("aff-input")) return;
    
        activeInput = t;
        clearSuggestions(); // switch context to new row
      });
    
      document.addEventListener("input", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("aff-input")) return;

        sanitizePipeInput(t);
    
        activeInput = t;
        const q = t.value.trim();
        if (q.length < 3) { clearSuggestions(); return; }
    
        positionBoxUnderInput(t);
        clearTimeout(timer);
        timer = setTimeout(async () => {
          try {
            const data = await search(q);
            if (!data || !data.ok) { clearSuggestions(); return; }
            render(data.results || [], q.toLowerCase());
          } catch {
            clearSuggestions();
          }
        }, 200);
      });
    
      document.addEventListener("keydown", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("aff-input")) return;
    
        if (box.classList.contains("hidden") || currentResults.length === 0) return;
    
        if (e.key === "ArrowDown") {
          e.preventDefault();
          activeIndex = (activeIndex + 1) % currentResults.length;
          updateActive();
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          activeIndex = (activeIndex - 1 + currentResults.length) % currentResults.length;
          updateActive();
        } else if (e.key === "Enter") {
          if (activeIndex >= 0) {
            e.preventDefault();
            e.stopPropagation(); // IMPORTANT: prevents other handlers from seeing Enter
            selectResult(currentResults[activeIndex]);
          }
        } else if (e.key === "Escape") {
          clearSuggestions();
        }
      }, true);
    
      // Hide when clicking elsewhere
      document.addEventListener("click", (e) => {
        if (activeInput && (e.target === activeInput || box.contains(e.target))) return;
        clearSuggestions();
      });
    })();

    (function () {
      const box = document.getElementById("country_suggest");
      if (!box) return;
    
      const COUNTRIES = window.COUNTRIES || [];
    
      let activeInput = null;
      let activeIndex = -1;
      let currentResults = [];
    
      function clearSuggestions() {
        box.classList.add("hidden");
        box.innerHTML = "";
        activeIndex = -1;
        currentResults = [];
      }
    
      function updateActive() {
        const items = box.querySelectorAll(".item");
        items.forEach((el, i) => el.classList.toggle("active", i === activeIndex));
      }
    
      function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, c => (
          { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;" }[c]
        ));
      }
    
      function positionBoxUnderInput(input) {
        const r = input.getBoundingClientRect();
        box.style.position = "absolute";
        box.style.left = (window.scrollX + r.left) + "px";
        box.style.top  = (window.scrollY + r.bottom + 6) + "px";
        box.style.width = r.width + "px";
      }
    
      function searchCountries(q) {
        const qq = q.trim().toLowerCase();
        if (!qq) return [];
        return COUNTRIES.filter(c => c.toLowerCase().includes(qq)).slice(0, 10);
      }
    
      function render(list, qLower) {
        box.innerHTML = "";
        currentResults = list || [];
        activeIndex = -1;
    
        if (!list || list.length === 0) { clearSuggestions(); return; }
    
        // hide only if exactly 1 and exactly equals input
        if (list.length === 1 && list[0].trim().toLowerCase() === qLower) {
          clearSuggestions();
          return;
        }
    
        list.forEach((name, i) => {
          const div = document.createElement("div");
          div.className = "item";
          div.innerHTML = `<strong>${escapeHtml(name)}</strong>`;
    
          div.addEventListener("mouseenter", () => {
            activeIndex = i;
            updateActive();
          });
          div.addEventListener("click", () => selectCountry(name));
    
          box.appendChild(div);
        });
    
        box.classList.remove("hidden");
      }
    
      function selectCountry(name) {
        if (!activeInput) return;
        activeInput.value = name;
        activeInput.dispatchEvent(new Event("input"));
        clearSuggestions();
        activeInput.focus();
      }
    
      document.addEventListener("focusin", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("country-input")) return;
    
        activeInput = t;
        clearSuggestions();
      });
    
      document.addEventListener("input", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("country-input")) return;
    
        sanitizePipeInput(t);

        activeInput = t;
        const q = t.value.trim();
        if (!q) { clearSuggestions(); return; }
    
        const matches = searchCountries(q);
        const qLower = q.toLowerCase();
    
        positionBoxUnderInput(t);
        render(matches, qLower);
      });
    
      document.addEventListener("keydown", (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement)) return;
        if (!t.classList.contains("country-input")) return;
    
        if (box.classList.contains("hidden") || currentResults.length === 0) return;
    
        if (e.key === "ArrowDown") {
          e.preventDefault();
          activeIndex = (activeIndex + 1) % currentResults.length;
          updateActive();
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          activeIndex = (activeIndex - 1 + currentResults.length) % currentResults.length;
          updateActive();
        } else if (e.key === "Enter") {
          if (activeIndex >= 0) {
            e.preventDefault();
            e.stopPropagation();
            selectCountry(currentResults[activeIndex]);
          }
        } else if (e.key === "Escape") {
          clearSuggestions();
        }
      }, true);
    
      document.addEventListener("click", (e) => {
        if (activeInput && (e.target === activeInput || box.contains(e.target))) return;
        clearSuggestions();
      });
    })();


    (function () {
      const given = document.getElementById("given_names");
      const family = document.getElementById("family_name");
    
      const autoWrap = document.getElementById("cryptodb_auto_wrap");
      const autoMissing = document.getElementById("cryptodb_auto_missing");
    
      const rAuto = document.getElementById("cryptodb_mode_auto");
      const rManual = document.getElementById("cryptodb_mode_manual");
      const rNone = document.getElementById("cryptodb_mode_none");
    
      const manual = document.getElementById("cryptodb_manual");
      const idHidden = document.getElementById("cryptodb_id_saved");
      const modeHidden = document.getElementById("cryptodb_mode_saved");
    
      if (!given || !family || !autoWrap || !rAuto || !rManual || !rNone || !manual || !idHidden) return;
    
      let autoId = "";         // current detected ID
      let timer = null;
      let lastKey = "";
    
      function setAutoNotFound() {
        autoId = "";
        autoWrap.innerHTML = `<span id="cryptodb_auto_missing" class="cryptodb-id-missing">Not found</span>`;
        rAuto.disabled = true;
    
        // If user had "auto" selected and it becomes unavailable, switch to manual (or none)
        if (rAuto.checked) {
          rManual.checked = true;
          manual.disabled = false;
          manual.focus();
        }
        syncHidden();
      }
    
      function setAutoFound(id) {
        autoId = String(id || "");
        autoWrap.innerHTML = `
          <a class="cryptodb-id-link"
             href="https://iacr.org/cryptodb/data/author.php?authorkey=${encodeURIComponent(autoId)}"
             target="_blank" rel="noopener noreferrer">${autoId}</a>
        `;
        rAuto.disabled = false;
    
        // Default behavior: if user hasn't chosen yet, preselect auto
        if ((modeHidden.value == "auto") || (!rAuto.checked && rManual.checked && manual.value == "") || (modeHidden.value == "")) {
          rAuto.checked = true;
          manual.disabled = true;
        }
        syncHidden();
      }
    
      function sanitizeManual() {
        // keep digits only (or allow empty)
        manual.value = (manual.value || "").replace(/[^\d]/g, "");
      }
    
      function syncHidden() {
        if (rAuto.checked && autoId) {
          idHidden.value = autoId;
          manual.disabled = true;
        } else if (rManual.checked) {
          manual.disabled = false;
          sanitizeManual();
          idHidden.value = manual.value.trim();
        } else {
          // none selected
          idHidden.value = "";
          manual.disabled = true;
        }
      }
    
      // --- your existing lookup helpers ---
      function normBasic(s) {
        return String(s || "")
          .toLowerCase()
          .normalize("NFKD")
          .replace(/[\u0300-\u036f]/g, "")
          .replace(/[^a-z0-9]+/g, " ")
          .trim()
          .replace(/\s+/g, " ");
      }
    
      async function fetchByLastName(last) {
        const url = `cryptodb_proxy.php?term=${encodeURIComponent(last)}`;
        const res = await fetch(url, { method: "GET" });
        if (!res.ok) return null;
        const j = await res.json();
        return (j && j.ok) ? (j.items || []) : [];
      }
    
      function pickUniqueExact(items, givenNames, familyName) {
        const f = normBasic(familyName);
        if (!f) return null;
    
        const full1 = normBasic(`${givenNames} ${familyName}`);
        const full2 = normBasic(`${familyName} ${givenNames}`);
    
        const exact = [];
        for (const it of (items || [])) {
          if (!it || typeof it !== "object") continue;
          const val = normBasic(it.value || "");
          const ln = normBasic(it.lastname || "");
          if (!(ln === f || ln.includes(f) || f.includes(ln))) continue;
          if (val === full1 || val === full2) exact.push(it);
        }
        return exact.length === 1 ? exact[0] : null;
      }
    
      async function refresh() {
        const g = given.value.trim();
        const f = family.value.trim();
        const key = `${g}|||${f}`;
        if (key === lastKey) return;
        lastKey = key;
    
        // If name changed, don’t force a choice reset, but update availability.
        if (!f || f.length < 2) {
          setAutoNotFound();
          return;
        }
    
        try {
          const items = await fetchByLastName(f);
          const best = pickUniqueExact(items, g, f);
          if (!best || !best.id) {
            setAutoNotFound();
            return;
          }
          setAutoFound(best.id);
        } catch {
          setAutoNotFound();
        }
      }
    
      function scheduleRefresh() {
        clearTimeout(timer);
        timer = setTimeout(refresh, 250);
      }
    
      // radio + manual changes
      rAuto.addEventListener("change", syncHidden);
      rManual.addEventListener("change", syncHidden);
      manual.addEventListener("input", () => { sanitizeManual(); syncHidden(); });
    
      // name changes trigger lookup
      given.addEventListener("input", scheduleRefresh);
      family.addEventListener("input", scheduleRefresh);
    
      // initial
      if (modeHidden.value == "manual") {
        refresh();
        rManual.checked = true;
        manual.value = idHidden.value;
        manual.disabled = false;
      }
      else if (modeHidden.value == "auto") {
        setAutoFound(idHidden.value);
      }
      else if (modeHidden.value == "none") {
        refresh();
        rNone.checked = true;
      }
      else {
        refresh();
        rManual.checked = true;
        manual.value = idHidden.value;
        manual.disabled = false;
      }
    })();

    (function () {
      const container = document.getElementById("reviewerSuggestionRows");
      if (!container) return;
    
      const header = document.createElement("div");
      header.className = "reviewer-suggestion-header";
    
      for (const text of ["Name", "Email", "Affiliation"]) {
        const el = document.createElement("div");
        el.textContent = text;
        header.appendChild(el);
      }
    
      container.appendChild(header);
    
      function makeRow() {
        const row = document.createElement("div");
        row.className = "reviewer-suggestion-row";
    
        const name = document.createElement("input");
        name.type = "text";
        name.name = "suggestion_name[]";
        name.placeholder = "Name";
        name.maxLength = 240;
    
        const email = document.createElement("input");
        email.type = "email";
        email.name = "suggestion_email[]";
        email.placeholder = "Email";
        email.maxLength = 254;
    
        const affiliation = document.createElement("input");
        affiliation.type = "text";
        affiliation.name = "suggestion_affiliation[]";
        affiliation.placeholder = "Affiliation";
        affiliation.maxLength = 240;
    
        for (const input of [name, email, affiliation]) {
          input.addEventListener("input", ensureTrailingEmptyRow);
        }
    
        row.append(name, email, affiliation);
        return row;
      }
    
      function rowIsEmpty(row) {
        return [...row.querySelectorAll("input")]
          .every(input => input.value.trim() === "");
      }
    
      function ensureTrailingEmptyRow() {
        const rows = [
          ...container.querySelectorAll(".reviewer-suggestion-row")
        ];
    
        if (rows.length === 0 || !rowIsEmpty(rows[rows.length - 1])) {
          container.appendChild(makeRow());
        }
      }
    
      ensureTrailingEmptyRow();
    })();

  </script>

</body>
</html>

