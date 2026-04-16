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
    credits INTEGER DEFAULT 0,
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

// جدول سجل المعاملات
$db->exec('CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)');

// أسعار الخدمات
$SERVICE_PRICES = [
    'check_fard' => 1,
    'check_kg'   => 2,
    'check_imei' => 1,
];

// إنشاء مستخدم admin افتراضي
$admin = $db->querySingle("SELECT id FROM users WHERE username='admin'");
if (!$admin) {
    $pass   = password_hash('admin123', PASSWORD_DEFAULT);
    $expire = date('Y-m-d', strtotime('+30 days'));
    $db->exec("INSERT INTO users (username, password, expire_date, credits) VALUES ('admin', '$pass', '$expire', 100)");
}

// قراءة الطلب
$action = isset($_GET['action']) ? $_GET['action'] : '';
$input  = json_decode(file_get_contents('php://input'), true);
if (!$input) $input = $_POST;

// ═══════════════════════════════
// دالة مساعدة: التحقق من التوكن
// ═══════════════════════════════
function getAuthUser($db, $input) {
    $token     = isset($input['token'])     ? trim($input['token'])     : '';
    $device_id = isset($input['device_id']) ? trim($input['device_id']) : '';
    if (!$token || !$device_id) return null;
    $stmt = $db->prepare("SELECT t.*, u.id as uid, u.username, u.expire_date, u.credits FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = :tok AND t.device_id = :did");
    $stmt->bindValue(':tok', $token);
    $stmt->bindValue(':did', $device_id);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$row) return null;
    if (strtotime($row['expire_date']) < time()) return null;
    return $row;
}

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

    if (strtotime($row['expire_date']) < time()) {
        echo json_encode(['success' => false, 'message' => 'انتهت صلاحية الحساب']);
        exit;
    }

    // التحقق من الجهاز
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
        'credits'     => (int)$row['credits'],   // ← الرصيد
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

    $stmt = $db->prepare("SELECT t.*, u.username, u.expire_date, u.credits FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = :tok AND t.device_id = :did");
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
        'credits'     => (int)$row['credits'],   // ← الرصيد
        'message'     => 'التوكن صالح'
    ]);
    exit;
}

// ═══════════════════════════════
// جلب الرصيد ★ جديد
// ═══════════════════════════════
if ($action === 'get_balance') {
    $user = getAuthUser($db, $input);
    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'غير مصرح']);
        exit;
    }
    echo json_encode([
        'success' => true,
        'credits' => (int)$user['credits'],
        'username'=> $user['username']
    ]);
    exit;
}

// ═══════════════════════════════
// خصم الكريدت ★ جديد
// ═══════════════════════════════
if ($action === 'deduct_credit') {
    global $SERVICE_PRICES;
    $user    = getAuthUser($db, $input);
    $service = isset($input['service']) ? trim($input['service']) : '';

    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'غير مصرح']);
        exit;
    }

    if (!$service || !isset($SERVICE_PRICES[$service])) {
        echo json_encode(['success' => false, 'message' => 'خدمة غير معروفة']);
        exit;
    }

    $price = $SERVICE_PRICES[$service];

    if ((int)$user['credits'] < $price) {
        echo json_encode([
            'success'  => false,
            'message'  => 'رصيدك غير كافٍ',
            'credits'  => (int)$user['credits'],
            'required' => $price
        ]);
        exit;
    }

    // خصم الرصيد
    $db->exec("UPDATE users SET credits = credits - $price WHERE id = {$user['uid']}");

    // تسجيل المعاملة
    $stmt = $db->prepare("INSERT INTO transactions (user_id, amount, type, description) VALUES (:uid, :amt, 'deduct', :desc)");
    $stmt->bindValue(':uid',  $user['uid']);
    $stmt->bindValue(':amt',  -$price);
    $stmt->bindValue(':desc', $service);
    $stmt->execute();

    $newCredits = (int)$user['credits'] - $price;

    echo json_encode([
        'success'    => true,
        'credits'    => $newCredits,
        'deducted'   => $price,
        'message'    => "تم خصم $price كريدت"
    ]);
    exit;
}

// ═══════════════════════════════
// إضافة رصيد (admin فقط) ★ جديد
// ═══════════════════════════════
if ($action === 'add_credits') {
    $admin_token = isset($input['admin_token']) ? trim($input['admin_token']) : '';
    $target_user = isset($input['username'])    ? trim($input['username'])    : '';
    $amount      = isset($input['amount'])      ? intval($input['amount'])    : 0;

    $tokenRow = $db->querySingle("SELECT t.user_id, u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = '$admin_token'", true);
    if (!$tokenRow || $tokenRow['username'] !== 'admin') {
        echo json_encode(['success' => false, 'message' => 'غير مصرح']);
        exit;
    }

    if (!$target_user || $amount <= 0) {
        echo json_encode(['success' => false, 'message' => 'بيانات ناقصة']);
        exit;
    }

    $targetRow = $db->querySingle("SELECT id, credits FROM users WHERE username = '$target_user'", true);
    if (!$targetRow) {
        echo json_encode(['success' => false, 'message' => 'المستخدم غير موجود']);
        exit;
    }

    $db->exec("UPDATE users SET credits = credits + $amount WHERE username = '$target_user'");

    // تسجيل المعاملة
    $stmt = $db->prepare("INSERT INTO transactions (user_id, amount, type, description) VALUES (:uid, :amt, 'add', 'admin_add')");
    $stmt->bindValue(':uid', $targetRow['id']);
    $stmt->bindValue(':amt', $amount);
    $stmt->execute();

    $newBalance = (int)$targetRow['credits'] + $amount;
    echo json_encode([
        'success' => true,
        'message' => "تم إضافة $amount كريدت لـ $target_user",
        'credits' => $newBalance
    ]);
    exit;
}

// ═══════════════════════════════
// سجل المعاملات ★ جديد
// ═══════════════════════════════
if ($action === 'transactions') {
    $user = getAuthUser($db, $input);
    if (!$user) {
        echo json_encode(['success' => false, 'message' => 'غير مصرح']);
        exit;
    }

    $rows = [];
    $result = $db->query("SELECT * FROM transactions WHERE user_id = {$user['uid']} ORDER BY id DESC LIMIT 20");
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $rows[] = $row;
    }

    echo json_encode([
        'success'      => true,
        'transactions' => $rows,
        'credits'      => (int)$user['credits']
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
    $credits     = isset($input['credits'])     ? intval($input['credits'])   : 0;

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
        $stmt = $db->prepare("INSERT INTO users (username, password, expire_date, credits) VALUES (:u, :p, :e, :c)");
        $stmt->bindValue(':u', $new_user);
        $stmt->bindValue(':p', $hashed);
        $stmt->bindValue(':e', $expire);
        $stmt->bindValue(':c', $credits);
        $stmt->execute();
        echo json_encode(['success' => true, 'message' => "تم إنشاء $new_user بصلاحية $days يوم ورصيد $credits كريدت"]);
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
echo json_encode(['success' => true, 'message' => 'IMEI Server is running', 'version' => '2.0']);
