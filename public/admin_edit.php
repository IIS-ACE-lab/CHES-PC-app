<?php
declare(strict_types=1);

session_start();

function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function fail(int $code, string $msg): void {
  http_response_code($code);
  die(h($msg));
}

// ---- CONFIG ----
$config = require __DIR__ . '/../config/config.php';

$dbPath = $config['db_path'] ?? '';
$auditLogPath = $config['audit_log_path'] ?? '';

if ($dbPath === '') fail(500, 'Server misconfiguration: db_path missing.');

// ---- AUTH ----
if (empty($_SESSION['admin_ok'])) {
  fail(403, 'Forbidden.');
}

// ---- DB ----
function db(string $dbPath): PDO {
  static $pdo = null;

  if ($pdo === null) {
    $pdo = new PDO("sqlite:" . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec("PRAGMA busy_timeout = 5000;");
  }

  return $pdo;
}

function append_audit_log_file(string $path, array $data): void {
  if ($path === '') return;

  $dir = dirname($path);
  if (!is_dir($dir)) @mkdir($dir, 0775, true);

  $fh = fopen($path, 'ab');
  if (!$fh) return;

  if (flock($fh, LOCK_EX)) {
    fwrite($fh, json_encode([
      'ts' => gmdate('c'),
      'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
      'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
      'data' => $data,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");

    fflush($fh);
    flock($fh, LOCK_UN);
  }

  fclose($fh);
}

function post_or_row(string $key, array $row): string {
  return (string)($_POST[$key] ?? $row[$key] ?? '');
}

$pdo = db($dbPath);

$inviteEmail = trim((string)($_GET['invite_email'] ?? $_POST['invite_email'] ?? ''));

if ($inviteEmail === '') {
  fail(400, 'Missing invite_email.');
}

$stmt = $pdo->prepare("SELECT * FROM reviewers WHERE invite_email = ?");
$stmt->execute([$inviteEmail]);
$row = $stmt->fetch();

if (!$row) {
  fail(404, 'Reviewer not found.');
}

$errors = [];
$currentRow = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $review_email = trim((string)($_POST['review_email'] ?? ''));
  $given_names  = trim((string)($_POST['given_names'] ?? ''));
  $family_name  = trim((string)($_POST['family_name'] ?? ''));
  $affiliation  = trim((string)($_POST['affiliation'] ?? ''));
  $country      = trim((string)($_POST['country'] ?? ''));
  $cryptodb_id  = trim((string)($_POST['cryptodb_id'] ?? ''));
  $status       = trim((string)($_POST['status'] ?? ''));
  $loadedUpdatedAt = trim((string)($_POST['loaded_updated_at'] ?? ''));

  if ($review_email === '') {
    $errors[] = 'Review email required.';
  } elseif (!filter_var($review_email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Invalid review email.';
  }

  $allowedStatus = ['invited', 'accepted', 'registered', 'declined', 'invalid_email'];
  if (!in_array($status, $allowedStatus, true)) {
    $errors[] = 'Invalid status.';
  }

  $cryptodb_id = preg_replace('/\D+/', '', $cryptodb_id) ?? '';

  $oldCryptodbId   = trim((string)($row['cryptodb_id'] ?? ''));
  $oldCryptodbMode = trim((string)($row['cryptodb_mode'] ?? ''));
  
  if ($cryptodb_id === '') {
    $cryptodb_mode = 'none';
  } elseif ($cryptodb_id === $oldCryptodbId) {
    $cryptodb_mode = $oldCryptodbMode !== '' ? $oldCryptodbMode : 'manual';
  } else {
    $cryptodb_mode = 'admin';
  }

  if ($given_names === '') {
    $errors[] = 'Given name(s) required.';
  }

  if ($family_name === '') {
    $errors[] = 'Family name required.';
  }

  if (!$errors) {
    $oldRow = $row;
    $opId = bin2hex(random_bytes(8));
    $newUpdatedAt = gmdate('c');

    append_audit_log_file($auditLogPath, [
      'event' => 'admin_update_begin',
      'op_id' => $opId,
      'invite_email' => $inviteEmail,
      'old_row' => $oldRow,
      'new_fields' => [
        'review_email' => $review_email,
        'given_names' => $given_names,
        'family_name' => $family_name,
        'affiliation' => $affiliation,
        'country' => $country,
        'cryptodb_id' => $cryptodb_id,
        'cryptodb_mode' => $cryptodb_mode,
        'status' => $status,
      ],
    ]);

    try {
      $pdo->beginTransaction();

      $stmt = $pdo->prepare("
        UPDATE reviewers
        SET
          review_email = ?,
          given_names = ?,
          family_name = ?,
          affiliation = ?,
          country = ?,
          cryptodb_id = ?,
          cryptodb_mode = ?,
          status = ?,
          updated_at = ?
        WHERE invite_email = ?
          AND updated_at = ?
      ");

      $stmt->execute([
        $review_email,
        $given_names,
        $family_name,
        $affiliation,
        $country,
        $cryptodb_id,
        $cryptodb_mode,
        $status,
        $newUpdatedAt,
        $inviteEmail,
        $loadedUpdatedAt,
      ]);

      if ($stmt->rowCount() !== 1) {
        $pdo->rollBack();

        $errors[] = 'Reviewer data changed meanwhile. Please compare below. Saving again will overwrite the current database values with your submitted values.';

        $stmt2 = $pdo->prepare("SELECT * FROM reviewers WHERE invite_email = ?");
        $stmt2->execute([$inviteEmail]);
        $currentRow = $stmt2->fetch();

        append_audit_log_file($auditLogPath, [
          'event' => 'admin_update_conflict',
          'op_id' => $opId,
          'invite_email' => $inviteEmail,
          'loaded_updated_at' => $loadedUpdatedAt,
          'current_updated_at' => $currentRow['updated_at'] ?? '',
        ]);

      } else {
        $pdo->commit();

        append_audit_log_file($auditLogPath, [
          'event' => 'admin_update_commit',
          'op_id' => $opId,
          'invite_email' => $inviteEmail,
        ]);

        header('Location: admin_edit.php?invite_email=' . rawurlencode($inviteEmail) . '&saved=1');
        exit;
      }

    } catch (Throwable $e) {
      if ($pdo->inTransaction()) $pdo->rollBack();

      append_audit_log_file($auditLogPath, [
        'event' => 'admin_update_fail',
        'op_id' => $opId,
        'invite_email' => $inviteEmail,
        'error' => $e->getMessage(),
      ]);

      fail(500, 'Database update failed.');
    }
  }
}

$saved = false;
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['saved'] ?? '') === '1') {
  $saved = true;
}

$effectiveUpdatedAt = (string)($currentRow['updated_at'] ?? $row['updated_at'] ?? '');

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Edit reviewer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<style>
body {
  font-family: system-ui, Arial, sans-serif;
  max-width: 900px;
  margin: 40px auto;
  padding: 0 16px;
}

.card {
  border: 1px solid #ddd;
  border-radius: 14px;
  padding: 16px;
  background: #fafafa;
}

label {
  display: block;
  margin-top: 14px;
  font-weight: 600;
}

input,
textarea,
select {
  width: 100%;
  padding: 10px;
  font-size: 16px;
  margin-top: 6px;
  box-sizing: border-box;
}

textarea {
  min-height: 80px;
}

.btnrow {
  display: flex;
  gap: 10px;
  margin-top: 18px;
  flex-wrap: wrap;
  align-items: center;
}

button {
  padding: 10px 14px;
  font-size: 16px;
  cursor: pointer;
}

.primary {
  font-weight: 700;
}

.muted {
  color: #555;
}

.small {
  font-size: 13px;
  margin-top: 2px;
}

.ok {
  background: #eaf8ea;
  border: 1px solid #b7ddb7;
  padding: 10px;
  border-radius: 10px;
  margin-top: 14px;
}

.err {
  background: #fff0f0;
  border: 1px solid #e0b4b4;
  padding: 10px;
  border-radius: 10px;
  margin-top: 14px;
}

.diff {
  margin-top: 14px;
  overflow-x: auto;
}

.diff table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
}

.diff th,
.diff td {
  border: 1px solid #ddd;
  padding: 8px;
  vertical-align: top;
  text-align: left;
}

.diff th {
  background: #f5f5f5;
}

.diff-row {
  background: #fff6d8;
}

code {
  background: #f0f0f0;
  padding: 2px 5px;
  border-radius: 5px;
}

.preish {
  white-space: pre-wrap;
}
</style>
</head>

<body>

<div class="card">
  <h1>Edit reviewer</h1>

  <div class="muted small">
    Invite email: <code><?= h($inviteEmail) ?></code><br>
    Current DB updated_at:
    <code><?= h((string)($currentRow['updated_at'] ?? $row['updated_at'] ?? '')) ?></code>
  </div>

  <?php if ($saved): ?>
    <div class="ok">Reviewer data saved.</div>
  <?php endif; ?>

  <?php if ($errors): ?>
    <div class="err">
      <strong>Please fix:</strong>
      <ul>
        <?php foreach ($errors as $e): ?>
          <li><?= h($e) ?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <?php if ($currentRow): ?>
    <div class="diff">
      <h2>Conflict comparison</h2>
      <table>
        <tr>
          <th>Field</th>
          <th>Your submitted value</th>
          <th>Current database value</th>
        </tr>

        <?php
          $compareFields = [
            'review_email' => 'Review email',
            'given_names' => 'Given name(s)',
            'family_name' => 'Family name',
            'status' => 'Status',
            'affiliation' => 'Affiliation(s)',
            'country' => 'Country / countries',
            'cryptodb_id' => 'CryptoDB ID',
          ];
        ?>

        <?php foreach ($compareFields as $key => $label): ?>
          <?php
            $submitted = (string)($_POST[$key] ?? '');
            if ($key === 'cryptodb_id') {
              $submitted = preg_replace('/\D+/', '', $submitted) ?? '';
            }
            $current = (string)($currentRow[$key] ?? '');
            $changed = ($submitted !== $current);
          ?>
          <tr class="<?= $changed ? 'diff-row' : '' ?>">
            <td><?= h($label) ?></td>
            <td class="preish"><?= h($submitted) ?></td>
            <td class="preish"><?= h($current) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  <?php endif; ?>

  <form method="post">
    <input type="hidden" name="invite_email" value="<?= h($inviteEmail) ?>">

    <input type="hidden"
           name="loaded_updated_at"
           value="<?= h($effectiveUpdatedAt) ?>">

    <label for="review_email">Review email</label>
    <input id="review_email"
           name="review_email"
           type="email"
           required
           value="<?= h(post_or_row('review_email', $row)) ?>">

    <label for="given_names">Given name(s)</label>
    <input id="given_names"
           name="given_names"
           required
           value="<?= h(post_or_row('given_names', $row)) ?>">

    <label for="family_name">Family name</label>
    <input id="family_name"
           name="family_name"
           required
           value="<?= h(post_or_row('family_name', $row)) ?>">

    <label for="status">Status</label>
    <select id="status" name="status">
      <?php
        $currentStatus = (string)($_POST['status'] ?? $row['status'] ?? 'invited');
        $statuses = [
          'invited' => 'invited',
          'accepted' => 'accepted',
          'registered' => 'registered',
          'declined' => 'declined',
          'invalid_email' => 'invalid_email',
        ];
      ?>
      <?php foreach ($statuses as $value => $label): ?>
        <option value="<?= h($value) ?>" <?= $currentStatus === $value ? 'selected' : '' ?>>
          <?= h($label) ?>
        </option>
      <?php endforeach; ?>
    </select>

    <label for="affiliation">Affiliation(s)</label>
    <textarea id="affiliation"
              name="affiliation"><?= h(post_or_row('affiliation', $row)) ?></textarea>
    <div class="muted small">Use <code>|</code> between multiple affiliations.</div>

    <label for="country">Country / countries</label>
    <textarea id="country"
              name="country"><?= h(post_or_row('country', $row)) ?></textarea>
    <div class="muted small">Use <code>|</code> between corresponding countries.</div>

    <label for="cryptodb_id">CryptoDB author ID</label>
    <input id="cryptodb_id"
           name="cryptodb_id"
           inputmode="numeric"
           value="<?= h(post_or_row('cryptodb_id', $row)) ?>">
    <div class="muted small">Digits only. Leave empty if unknown.</div>

    <div class="btnrow">
      <button class="primary" type="submit">Save changes</button>
      <a href="admin.php#reviewers">Back to admin overview</a>
    </div>
  </form>
</div>

</body>
</html>

