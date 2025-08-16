<?php
/**
 * TechEmir Contact Submissions Admin Panel
 * View and manage contact form submissions from Supabase
 *
 */

session_start();
require_once '../config.php';

$admin_email = TechEmirConfig::get('ADMIN_EMAIL');

// Supabase Configuration
$supabase_url = TechEmirConfig::get('SUPABASE_URL');
$supabase_anon_key = TechEmirConfig::get('SUPABASE_ANON_KEY');
$supabase_service_key = TechEmirConfig::get('SUPABASE_SERVICE_KEY');

// Database configuration for direct PostgreSQL connection
$database_host = TechEmirConfig::get('DB_HOST');
$database_name = TechEmirConfig::get('DB_NAME');
$database_user = TechEmirConfig::get('DB_USER');
$database_pass = TechEmirConfig::get('DB_PASS');
$database_port = TechEmirConfig::get('DB_PORT');

/**
 * Authenticate user with Supabase Auth
 */
function authenticateWithSupabase($email, $password) {
    $url = $supabase_url . '/auth/v1/token?grant_type=password';

    $data = json_encode([
        'email' => $email,
        'password' => $password
    ]);

    $headers = [
        'Content-Type: application/json',
        'apikey: ' . $supabase_anon_key
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $data,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 10,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code === 200) {
        $auth_data = json_decode($response, true);
        return $auth_data;
    }

    return false;
}

/**
 * Verify admin privileges (check if user has admin role)
 */
function verifyAdminRole($access_token) {
    $url = $supabase_url . '/auth/v1/user';

    $headers = [
        'Authorization: Bearer ' . $access_token,
        'apikey: ' . $supabase_anon_key
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 10,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code === 200) {
        $user_data = json_decode($response, true);

        // Check if user has admin role in user_metadata or app_metadata
        $is_admin = false;

        if (isset($user_data['user_metadata']['role']) && $user_data['user_metadata']['role'] === 'admin') {
            $is_admin = true;
        }

        if (isset($user_data['app_metadata']['role']) && $user_data['app_metadata']['role'] === 'admin') {
            $is_admin = true;
        }

        // For initial setup, allow specific email addresses
        $admin_emails = ['admin@techemir.co.uk', 'info@techemir.co.uk']; // Add your admin emails
        if (in_array($user_data['email'], $admin_emails)) {
            $is_admin = true;
        }

        return $is_admin ? $user_data : false;
    }

    return false;
}

// Handle login
if (isset($_POST['login'])) {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($email && $password) {
        $auth_result = authenticateWithSupabase($email, $password);

        if ($auth_result && isset($auth_result['access_token'])) {
            $admin_user = verifyAdminRole($auth_result['access_token']);

            if ($admin_user) {
                $_SESSION['supabase_token'] = $auth_result['access_token'];
                $_SESSION['admin_user'] = $admin_user;
                $_SESSION['admin_logged_in'] = true;
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                $login_error = 'Access denied. Admin privileges required.';
            }
        } else {
            $login_error = 'Invalid email or password.';
        }
    } else {
        $login_error = 'Please enter both email and password.';
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    // Optional: Revoke token with Supabase
    if (isset($_SESSION['supabase_token'])) {
        $url = $supabase_url . '/auth/v1/logout';
        $headers = [
            'Authorization: Bearer ' . $_SESSION['supabase_token'],
            'apikey: ' . $supabase_anon_key
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        curl_exec($ch);
        curl_close($ch);
    }

    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check if user is logged in
if (!isset($_SESSION['admin_logged_in']) || !isset($_SESSION['supabase_token'])) {
    // Show Supabase Auth login form
    ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TechEmir Supabase Admin Login</title>
            <style>
                body { font-family: Arial, sans-serif; background: #0a0a0a; color: white; margin: 0; padding: 50px; }
                .login-container { max-width: 450px; margin: 100px auto; background: #1a1a1a; padding: 40px; border-radius: 12px; border: 1px solid #ff3366; }
                .logo { text-align: center; font-size: 2rem; color: #ff3366; margin-bottom: 10px; font-family: monospace; }
                .subtitle { text-align: center; color: #64ffda; margin-bottom: 30px; font-size: 0.9rem; }
                .auth-info { background: rgba(100, 255, 218, 0.1); border: 1px solid rgba(100, 255, 218, 0.3); border-radius: 8px; padding: 15px; margin-bottom: 25px; }
                .auth-info h4 { color: #64ffda; margin-bottom: 10px; font-size: 1rem; }
                .auth-info p { color: #ccc; margin: 5px 0; font-size: 0.9rem; }
                .form-group { margin-bottom: 20px; }
                label { display: block; margin-bottom: 5px; color: #ccc; }
                input { width: 100%; padding: 12px; background: #333; border: 1px solid #555; border-radius: 6px; color: white; font-size: 16px; }
                input:focus { border-color: #ff3366; outline: none; }
                button { width: 100%; padding: 12px; background: #ff3366; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
                button:hover { background: #e02955; }
                .error { color: #ff6b6b; margin-top: 15px; text-align: center; padding: 10px; background: rgba(255, 107, 107, 0.1); border-radius: 6px; }
                .setup-instructions { background: rgba(255, 193, 7, 0.1); border: 1px solid rgba(255, 193, 7, 0.3); border-radius: 8px; padding: 15px; margin-top: 20px; }
                .setup-instructions h4 { color: #ffc107; margin-bottom: 10px; }
                .setup-instructions p { color: #ccc; margin: 5px 0; font-size: 0.85rem; }
                .supabase-badge { background: #64ffda; color: #0a0a0a; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; }
            </style>
        </head>
        <body>
                <div class="login-container">
                    <div class="logo">{ TechEmir }</div>
                    <div class="subtitle">
                        Admin Panel <span class="supabase-badge">Supabase Auth</span>
                    </div>

                    <div class="auth-info">
                        <h4>🔐 Supabase Authentication</h4>
                        <p>This admin panel uses Supabase Auth for secure login.</p>
                        <p>Only users with admin privileges can access this panel.</p>
                    </div>

                    <h2 style="text-align: center; margin-bottom: 30px;">Admin Login</h2>

                    <form method="POST">
                        <div class="form-group">
                            <label>Email Address:</label>
                            <input type="email" name="email" required placeholder="admin@techemir.co.uk">
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" name="password" required placeholder="Your Supabase password">
                        </div>
                        <button type="submit" name="login">Login with Supabase</button>

                        <?php if (isset($login_error)): ?>
                            <div class="error"><?php echo htmlspecialchars($login_error); ?></div>
                        <?php endif; ?>
                    </form>

                    <div class="setup-instructions">
                        <h4>⚙️ First Time Setup:</h4>
                        <p>1. Create a user in your Supabase dashboard</p>
                        <p>2. Add your email to the admin_emails array in this file</p>
                        <p>3. Or set user_metadata.role = 'admin' in Supabase</p>
                        <p>4. Use your Supabase email/password to login</p>
                    </div>
                </div>
            </body>
        </html>
        <?php
        exit;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: contact-submissions.php');
    exit;
}

/**
 * Get Supabase database connection
 */
function getSupabaseConnection() {
    global $database_host, $database_port, $database_name, $database_user, $database_pass;

    try {
        $dsn = "pgsql:host=" . $database_host . ";port=" . $database_port . ";dbname=" . $database_name;
        $pdo = new PDO($dsn, $database_user, $database_pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $pdo;
    } catch(PDOException $e) {
        error_log("Supabase connection failed: " . $e->getMessage());
        throw new Exception("Database connection failed");
    }
}

/**
 * Alternative: Use Supabase REST API for operations
 */
function updateViaSupabaseAPI($id, $data) {
    $url = SUPABASE_URL . '/rest/v1/contact_submissions?id=eq.' . $id;

    $headers = [
        'Content-Type: application/json',
        'apikey: ' . $supabase_service_key,
        'Authorization: Bearer ' . $supabase_service_key,
        'Prefer: return=minimal'
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => 'PATCH',
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $http_code === 204;
}

function deleteViaSupabaseAPI($id) {
    $url = $supabase_url . '/rest/v1/contact_submissions?id=eq.' . $id;

    $headers = [
        'apikey: ' . $supabase_service_key,
        'Authorization: Bearer ' . $supabase_service_key
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => 'DELETE',
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $http_code === 204;
}

// Database connection
$pdo = getSupabaseConnection();

// Handle actions
if (isset($_POST['action'])) {
    try {
        switch ($_POST['action']) {
            case 'mark_read':
                $stmt = $pdo->prepare("UPDATE contact_submissions SET status = 'read' WHERE id = ?");
                $stmt->execute([$_POST['id']]);
                break;

            case 'mark_unread':
                updateViaSupabaseAPI($_POST['id'], ['status' => 'unread']);
                break;
            case 'delete':
                deleteViaSupabaseAPI($_POST['id']);
                break;
            case 'add_note':
                updateViaSupabaseAPI($_POST['id'], ['admin_notes' => $_POST['note']]);
                break;
        }
    }

    header('Location: contact-submissions.php');
    exit;
}

// Pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$per_page = 20;
$offset = ($page - 1) * $per_page;

// Filters
$status_filter = isset($_GET['status']) ? $_GET['status'] : '';
$service_filter = isset($_GET['service']) ? $_GET['service'] : '';

// Build query (PostgreSQL syntax)
$where_conditions = [];
$params = [];

if ($status_filter) {
    $where_conditions[] = "status = ?";
    $params[] = $status_filter;
}

if ($service_filter) {
    $where_conditions[] = "service = ?";
    $params[] = $service_filter;
}

$where_clause = !empty($where_conditions) ? "WHERE " . implode(" AND ", $where_conditions) : "";

// Get total count
$count_sql = "SELECT COUNT(*) FROM contact_submissions $where_clause";
$count_stmt = $pdo->prepare($count_sql);
$count_stmt->execute($params);
$total_records = $count_stmt->fetchColumn();
$total_pages = ceil($total_records / $per_page);

// Get submissions (PostgreSQL LIMIT/OFFSET syntax)
$sql = "SELECT * FROM contact_submissions $where_clause ORDER BY submitted_at DESC LIMIT $per_page OFFSET $offset";
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$submissions = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get statistics
$stats_sql = "SELECT
    COUNT(*) as total,
    SUM(CASE WHEN status = 'unread' THEN 1 ELSE 0 END) as unread,
    SUM(CASE WHEN status = 'read' THEN 1 ELSE 0 END) as read,
    SUM(CASE WHEN DATE(submitted_at) = CURRENT_DATE THEN 1 ELSE 0 END) as today
    FROM contact_submissions";
$stats = $pdo->query($stats_sql)->fetch(PDO::FETCH_ASSOC);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Submissions - TechEmir Supabase Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: white; line-height: 1.6; }

        .header { background: #1a1a1a; padding: 20px; border-bottom: 2px solid #ff3366; }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.5rem; color: #ff3366; font-family: monospace; font-weight: bold; }
        .supabase-badge { background: #64ffda; color: #0a0a0a; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; }
        .logout-btn { background: #ff3366; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; }

        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        .supabase-info { background: rgba(100, 255, 218, 0.1); border: 1px solid rgba(100, 255, 218, 0.3); border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .supabase-info h4 { color: #64ffda; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; }
        .supabase-info p { color: #ccc; margin: 5px 0; }
        .supabase-link { color: #64ffda; text-decoration: none; }
        .supabase-link:hover { text-decoration: underline; }

        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a1a; padding: 20px; border-radius: 8px; border: 1px solid #333; text-align: center; position: relative; }
        .stat-card.supabase-powered::after { content: '⚡ Supabase'; position: absolute; top: 5px; right: 5px; font-size: 0.7rem; color: #64ffda; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #ff3366; }
        .stat-label { color: #ccc; margin-top: 5px; }

        .filters { background: #1a1a1a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; }
        .filter-row { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
        .filter-group label { margin-right: 10px; color: #ccc; }
        .filter-group select { background: #333; color: white; border: 1px solid #555; padding: 8px; border-radius: 4px; }
        .filter-btn { background: #ff3366; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }

        .submissions-table { background: #1a1a1a; border-radius: 8px; overflow: hidden; border: 1px solid #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #2a2a2a; color: #ff3366; font-weight: 600; }

        .status-unread { background: rgba(255, 51, 102, 0.1); }
        .status-read { background: rgba(100, 255, 218, 0.1); }

        .action-btn { padding: 4px 8px; border: none; border-radius: 4px; cursor: pointer; margin: 2px; font-size: 12px; }
        .btn-read { background: #64ffda; color: #0a0a0a; }
        .btn-unread { background: #ff3366; color: white; }
        .btn-delete { background: #ff6b6b; color: white; }
        .btn-view { background: #0066ff; color: white; }

        .pagination { margin: 20px 0; text-align: center; }
        .pagination a { display: inline-block; padding: 8px 12px; margin: 0 4px; background: #333; color: white; text-decoration: none; border-radius: 4px; }
        .pagination a.current { background: #ff3366; }
        .pagination a:hover { background: #555; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; }
        .modal-content { background: #1a1a1a; margin: 5% auto; padding: 20px; width: 80%; max-width: 600px; border-radius: 8px; border: 1px solid #ff3366; }
        .close { float: right; font-size: 28px; cursor: pointer; color: #ff3366; }

        .submission-details { line-height: 1.8; }
        .submission-details strong { color: #ff3366; }

        textarea { width: 100%; background: #333; color: white; border: 1px solid #555; padding: 10px; border-radius: 4px; margin: 10px 0; }

        .realtime-indicator { background: rgba(100, 255, 218, 0.2); padding: 10px; border-radius: 4px; margin-bottom: 20px; text-align: center; }
        .realtime-indicator.active { animation: pulse 2s infinite; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        @media (max-width: 768px) {
            .filter-row { flex-direction: column; align-items: stretch; }
            .stats { grid-template-columns: repeat(2, 1fr); }
            table { font-size: 14px; }
            th, td { padding: 8px; }
            .header-content { flex-direction: column; gap: 10px; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <span class="logo">{ TechEmir } Admin</span>
                <span class="supabase-badge">Powered by Supabase</span>
            </div>
            <a href="?logout=1" class="logout-btn">Logout</a>
        </div>
    </div>

    <div class="container">
        <h1>Contact Form Submissions</h1>

        <!-- Supabase Integration Info -->
        <div class="supabase-info">
            <h4>🚀 Supabase Integration Active</h4>
            <p><strong>Database:</strong> PostgreSQL on Supabase</p>
            <p><strong>Real-time sync:</strong> Enabled with Row Level Security</p>
            <p><strong>Supabase Dashboard:</strong> <a href="<?php echo SUPABASE_URL; ?>/project/default/editor" target="_blank" class="supabase-link">View in Supabase</a></p>
        </div>

        <!-- Real-time indicator -->
        <div class="realtime-indicator" id="realtimeIndicator">
            📡 Real-time updates enabled - New submissions will appear automatically
        </div>

        <!-- Statistics -->
        <div class="stats">
            <div class="stat-card supabase-powered">
                <div class="stat-number"><?php echo $stats['total']; ?></div>
                <div class="stat-label">Total Submissions</div>
            </div>
            <div class="stat-card supabase-powered">
                <div class="stat-number"><?php echo $stats['unread']; ?></div>
                <div class="stat-label">Unread</div>
            </div>
            <div class="stat-card supabase-powered">
                <div class="stat-number"><?php echo $stats['read']; ?></div>
                <div class="stat-label">Read</div>
            </div>
            <div class="stat-card supabase-powered">
                <div class="stat-number"><?php echo $stats['today']; ?></div>
                <div class="stat-label">Today</div>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters">
            <form method="GET" class="filter-row">
                <div class="filter-group">
                    <label>Status:</label>
                    <select name="status">
                        <option value="">All</option>
                        <option value="unread" <?php echo $status_filter === 'unread' ? 'selected' : ''; ?>>Unread</option>
                        <option value="read" <?php echo $status_filter === 'read' ? 'selected' : ''; ?>>Read</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Service:</label>
                    <select name="service">
                        <option value="">All Services</option>
                        <option value="automation" <?php echo $service_filter === 'automation' ? 'selected' : ''; ?>>Automation</option>
                        <option value="office-relocation" <?php echo $service_filter === 'office-relocation' ? 'selected' : ''; ?>>Office Relocation</option>
                        <option value="it-infrastructure" <?php echo $service_filter === 'it-infrastructure' ? 'selected' : ''; ?>>IT Infrastructure</option>
                        <option value="security" <?php echo $service_filter === 'security' ? 'selected' : ''; ?>>Security</option>
                        <option value="it-support" <?php echo $service_filter === 'it-support' ? 'selected' : ''; ?>>IT Support</option>
                        <option value="device-lifecycle" <?php echo $service_filter === 'device-lifecycle' ? 'selected' : ''; ?>>Device Lifecycle</option>
                    </select>
                </div>
                <button type="submit" class="filter-btn">Filter</button>
                <a href="contact-submissions.php" class="filter-btn" style="background: #666;">Clear</a>
                <a href="<?php echo SUPABASE_URL; ?>/project/default/editor" target="_blank" class="filter-btn" style="background: #64ffda; color: #0a0a0a;">🔗 Open Supabase</a>
            </form>
        </div>

        <!-- Submissions Table -->
        <div class="submissions-table">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Date</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Service</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($submissions as $submission): ?>
                    <tr class="<?php echo $submission['status'] === 'unread' ? 'status-unread' : 'status-read'; ?>">
                        <td><?php echo $submission['id']; ?></td>
                        <td><?php echo date('M j, Y H:i', strtotime($submission['submitted_at'])); ?></td>
                        <td><?php echo htmlspecialchars($submission['name']); ?></td>
                        <td><?php echo htmlspecialchars($submission['email']); ?></td>
                        <td><?php echo ucfirst(str_replace('-', ' ', $submission['service'])); ?></td>
                        <td>
                            <span style="color: <?php echo $submission['status'] === 'unread' ? '#ff3366' : '#64ffda'; ?>">
                                <?php echo ucfirst($submission['status']); ?>
                            </span>
                        </td>
                        <td>
                            <button class="action-btn btn-view" onclick="viewSubmission(<?php echo $submission['id']; ?>)">View</button>
                            <?php if ($submission['status'] === 'unread'): ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="mark_read">
                                    <input type="hidden" name="id" value="<?php echo $submission['id']; ?>">
                                    <button type="submit" class="action-btn btn-read">Mark Read</button>
                                </form>
                            <?php else: ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="mark_unread">
                                    <input type="hidden" name="id" value="<?php echo $submission['id']; ?>">
                                    <button type="submit" class="action-btn btn-unread">Mark Unread</button>
                                </form>
                            <?php endif; ?>
                            <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this submission?');">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="id" value="<?php echo $submission['id']; ?>">
                                <button type="submit" class="action-btn btn-delete">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>

                    <?php if (empty($submissions)): ?>
                    <tr>
                        <td colspan="7" style="text-align: center; color: #ccc; padding: 40px;">
                            No submissions found. Check your Supabase connection or create some test data.
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Pagination -->
        <?php if ($total_pages > 1): ?>
        <div class="pagination">
            <?php if ($page > 1): ?>
                <a href="?page=<?php echo $page - 1; ?>&status=<?php echo $status_filter; ?>&service=<?php echo $service_filter; ?>">&laquo; Previous</a>
            <?php endif; ?>

            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                <a href="?page=<?php echo $i; ?>&status=<?php echo $status_filter; ?>&service=<?php echo $service_filter; ?>"
                   class="<?php echo $i === $page ? 'current' : ''; ?>">
                    <?php echo $i; ?>
                </a>
            <?php endfor; ?>

            <?php if ($page < $total_pages): ?>
                <a href="?page=<?php echo $page + 1; ?>&status=<?php echo $status_filter; ?>&service=<?php echo $service_filter; ?>">Next &raquo;</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Modal for viewing submission details -->
    <div id="submissionModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <div id="submissionDetails"></div>
        </div>
    </div>

    <script>
        // Store submission data for modal
        const submissions = <?php echo json_encode($submissions); ?>;

        function viewSubmission(id) {
            const submission = submissions.find(s => s.id == id);
            if (!submission) return;

            const details = `
                <h2>Submission Details <span style="color: #64ffda; font-size: 0.8em;">[Supabase ID: ${submission.id}]</span></h2>
                <div class="submission-details">
                    <p><strong>Date:</strong> ${new Date(submission.submitted_at).toLocaleString()}</p>
                    <p><strong>Name:</strong> ${submission.name}</p>
                    <p><strong>Email:</strong> <a href="mailto:${submission.email}" style="color: #64ffda;">${submission.email}</a></p>
                    <p><strong>Phone:</strong> ${submission.phone || 'Not provided'}</p>
                    <p><strong>Client Type:</strong> ${submission.client_type || 'Not specified'}</p>
                    <p><strong>Service:</strong> ${submission.service.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}</p>
                    <p><strong>IP Address:</strong> ${submission.ip_address}</p>
                    <p><strong>User Agent:</strong> ${submission.user_agent}</p>
                    <p><strong>Status:</strong> <span style="color: ${submission.status === 'unread' ? '#ff3366' : '#64ffda'}">${submission.status.toUpperCase()}</span></p>

                    <h3 style="margin-top: 20px; color: #ff3366;">Project Details:</h3>
                    <div style="background: #333; padding: 15px; border-radius: 4px; white-space: pre-wrap;">${submission.message}</div>

                    <h3 style="margin-top: 20px; color: #ff3366;">Admin Notes:</h3>
                    <form method="POST" style="margin-top: 10px;">
                        <input type="hidden" name="action" value="add_note">
                        <input type="hidden" name="id" value="${submission.id}">
                        <textarea name="note" rows="4" placeholder="Add admin notes...">${submission.admin_notes || ''}</textarea>
                        <button type="submit" class="filter-btn">💾 Save Notes to Supabase</button>
                    </form>

                    <div style="margin-top: 20px; padding: 10px; background: rgba(100, 255, 218, 0.1); border-radius: 4px;">
                        <small style="color: #64ffda;">
                            💡 <strong>Supabase Tip:</strong> You can also view and edit this data directly in your
                            <a href="<?php echo SUPABASE_URL; ?>/project/default/editor" target="_blank" style="color: #64ffda;">Supabase Dashboard</a>
                        </small>
                    </div>
                </div>
            `;

            document.getElementById('submissionDetails').innerHTML = details;
            document.getElementById('submissionModal').style.display = 'block';
        }

        function closeModal() {
            document.getElementById('submissionModal').style.display = 'none';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('submissionModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }

        // Auto-refresh with Supabase indicator
        let refreshCount = 0;
        setInterval(function() {
            const indicator = document.getElementById('realtimeIndicator');

            // Only refresh if we're on the first page with no filters
            const urlParams = new URLSearchParams(window.location.search);
            if (!urlParams.get('page') && !urlParams.get('status') && !urlParams.get('service')) {
                refreshCount++;
                indicator.classList.add('active');
                indicator.textContent = `📡 Checking for new submissions... (${refreshCount})`;

                setTimeout(() => {
                    location.reload();
                }, 1000);
            }
        }, 30000);

        // Supabase connection test on page load
        document.addEventListener('DOMContentLoaded', function() {
            console.log('🚀 TechEmir Admin Panel powered by Supabase');
            console.log('📊 Database: PostgreSQL with Row Level Security');
            console.log('🔗 Supabase URL: <?php echo SUPABASE_URL; ?>');
        });
    </script>
</body>
</html>
