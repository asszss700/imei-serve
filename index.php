<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// قاعدة البيانات SQLite
$db = new SQLite3('/tmp/imei_server.db');

// إنشاء الجداول
$db->exec('CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    expire_date TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)');

$db->exec('CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    device_id TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)');

// إنشاء مستخدم admin افتراضي
$admin = $db->querySingle("SELECT id FROM users WHERE username='admin'");
if (!$admin) {
    $pass = password_hash('admin123', PASSWORD_DEFAULT);
    $expire = date('Y-m-d', strtotime('+30 days'));
    $db->exec("INSERT INTO users (username, password, expire_date) VALUES ('admin', '$pass', '$expire')");
}

// قراءة الطلب
$action = isset($_GET['action']) ? $_GET['action'] : '';
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) $input = $_POST;

// ═══════════════════════════════
// تسجيل الدخول
// ═══════════════════════════════
if ($action === 'login') {
    $username  = isset($input['username'])  ? trim($input['username'])  : '';
    $password  = isset($input['password'])  ? trim($input['password'])  : '';
    $device_id = isset($input['device_id']) ? trim($input['device_id']) : '';

    if (!$username || !$password || !$device_id) {
        echo json_encode(['success' => false, 'message' => 'بيانات ناقصة']);
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM users WHERE username = :u");
    $stmt->bindValue(':u', $username);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$row || !password_verify($password, $row['password'])) {
        echo json_encode(['success' => false, 'message' => 'اسم المستخدم أو كلمة المرور خاطئة']);
        exit;
    }

    // التحقق من انتهاء الصلاحية
    if (strtotime($row['expire_date']) < time()) {
        echo json_encode(['success' => false, 'message' => 'انتهت صلاحية الحساب']);
        exit;
    }

    // التحقق من الجهاز — هل هذا المستخدم مسجّل على جهاز آخر؟
    $existingToken = $db->querySingle(
        "SELECT device_id FROM tokens WHERE user_id = {$row['id']} ORDER BY id DESC LIMIT 1", true
    );
    if ($existingToken && $existingToken['device_id'] !== $device_id) {
        echo json_encode(['success' => false, 'message' => 'هذا الحساب مسجّل على جهاز آخر']);
        exit;
    }

    // حذف التوكن القديم وإنشاء جديد
    $db->exec("DELETE FROM tokens WHERE user_id = {$row['id']}");
    $token = bin2hex(random_bytes(32));
    $stmt2 = $db->prepare("INSERT INTO tokens (user_id, token, device_id) VALUES (:uid, :tok, :did)");
    $stmt2->bindValue(':uid', $row['id']);
    $stmt2->bindValue(':tok', $token);
    $stmt2->bindValue(':did', $device_id);
    $stmt2->execute();

    echo json_encode([
        'success'     => true,
        'token'       => $token,
        'username'    => $row['username'],
        'expire_date' => $row['expire_date'],
        'message'     => 'تم تسجيل الدخول بنجاح'
    ]);
    exit;
}

// ═══════════════════════════════
// التحقق من التوكن
// ═══════════════════════════════
if ($action === 'verify') {
    $token     = isset($input['token'])     ? trim($input['token'])     : '';
    $device_id = isset($input['device_id']) ? trim($input['device_id']) : '';

    if (!$token || !$device_id) {
        echo json_encode(['success' => false, 'message' => 'بيانات ناقصة']);
        exit;
    }

    $stmt = $db->prepare("SELECT t.*, u.username, u.expire_date FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = :tok AND t.device_id = :did");
    $stmt->bindValue(':tok', $token);
    $stmt->bindValue(':did', $device_id);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        echo json_encode(['success' => false, 'message' => 'توكن غير صالح أو جهاز مختلف']);
        exit;
    }

    if (strtotime($row['expire_date']) < time()) {
        echo json_encode(['success' => false, 'message' => 'انتهت صلاحية الحساب']);
        exit;
    }

    echo json_encode([
        'success'     => true,
        'username'    => $row['username'],
        'expire_date' => $row['expire_date'],
        'message'     => 'التوكن صالح'
    ]);
    exit;
}

// ═══════════════════════════════
// إنشاء مستخدم جديد (admin فقط)
// ═══════════════════════════════
if ($action === 'create_user') {
    $admin_token = isset($input['admin_token']) ? trim($input['admin_token']) : '';
    $new_user    = isset($input['username'])    ? trim($input['username'])    : '';
    $new_pass    = isset($input['password'])    ? trim($input['password'])    : '';
    $days        = isset($input['days'])        ? intval($input['days'])      : 30;

    // التحقق من صلاحية المسؤول
    $tokenRow = $db->querySingle("SELECT t.user_id, u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = '$admin_token'", true);
    if (!$tokenRow || $tokenRow['username'] !== 'admin') {
        echo json_encode(['success' => false, 'message' => 'غير مصرح']);
        exit;
    }

    if (!$new_user || !$new_pass) {
        echo json_encode(['success' => false, 'message' => 'بيانات ناقصة']);
        exit;
    }

    $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
    $expire = date('Y-m-d', strtotime("+$days days"));

    try {
        $stmt = $db->prepare("INSERT INTO users (username, password, expire_date) VALUES (:u, :p, :e)");
        $stmt->bindValue(':u', $new_user);
        $stmt->bindValue(':p', $hashed);
        $stmt->bindValue(':e', $expire);
        $stmt->execute();
        echo json_encode(['success' => true, 'message' => "تم إنشاء المستخدم $new_user بصلاحية $days يوم"]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'اسم المستخدم موجود مسبقاً']);
    }
    exit;
}

// ═══════════════════════════════
// تسجيل الخروج
// ═══════════════════════════════
if ($action === 'logout') {
    $token = isset($input['token']) ? trim($input['token']) : '';
    $db->exec("DELETE FROM tokens WHERE token = '$token'");
    echo json_encode(['success' => true, 'message' => 'تم تسجيل الخروج']);
    exit;
}

// الصفحة الرئيسية
echo json_encode(['success' => true, 'message' => 'Fard Server is  running', 'version' => '1.0']);

