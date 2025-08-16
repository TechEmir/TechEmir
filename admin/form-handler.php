<?php
/**
 * TechEmir Contact Form Handler - Supabase Version
 * Handles form submissions with reCAPTCHA verification using Supabase PostgreSQL
 *
 */

// Start session and enable error reporting for development
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once '../config.php';

// Configuration
$recaptcha_secret_key = TechEmirConfig::get('RECAPTCHA_SECRET_KEY');
$admin_email = TechEmirConfig::get('ADMIN_EMAIL');
$from_email = TechEmirConfig::get('FROM_EMAIL');
$company_name = TechEmirConfig::get('COMPANY_NAME');

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
 * Alternative: Use Supabase REST API (if you prefer API over direct DB connection)
 */
function insertViaSupabaseAPI($data) {
    $url = $supabase_url . '/rest/v1/contact_submissions';

    $payload = json_encode([
        'name' => $data['name'],
        'email' => $data['email'],
        'phone' => $data['phone'],
        'client_type' => $data['client_type'],
        'service' => $data['service'],
        'message' => $data['message'],
        'ip_address' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'status' => 'unread'
    ]);

    $headers = [
        'Content-Type: application/json',
        'apikey: ' . $supabase_anon_key,
        'Authorization: Bearer ' . $supabase_anon_key,
        'Prefer: return=representation'
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 30,
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code === 201) {
        $result = json_decode($response, true);
        return $result[0]['id'] ?? true;
    } else {
        error_log("Supabase API error: HTTP $http_code - $response");
        throw new Exception("Failed to save submission");
    }
}

/**
 * Verify reCAPTCHA response
 */
function verifyRecaptcha($recaptcha_response) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $recaptcha_secret_key,
        'response' => $recaptcha_response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];

    $options = [
        'http' => [
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result);

    return $response->success ?? false;
}

/**
 * Sanitize input data
 */
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

/**
 * Validate email format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

/**
 * Save submission to Supabase database
 */
function saveToSupabase($data) {
    try {
        $pdo = getSupabaseConnection();

        $sql = "INSERT INTO contact_submissions (name, email, phone, client_type, service, message, ip_address, user_agent, status, submitted_at)
                VALUES (:name, :email, :phone, :client_type, :service, :message, :ip_address, :user_agent, 'unread', NOW())
                RETURNING id";

        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([
            ':name' => $data['name'],
            ':email' => $data['email'],
            ':phone' => $data['phone'],
            ':client_type' => $data['client_type'],
            ':service' => $data['service'],
            ':message' => $data['message'],
            ':ip_address' => $_SERVER['REMOTE_ADDR'],
            ':user_agent' => $_SERVER['HTTP_USER_AGENT']
        ]);

        if ($result) {
            $row = $stmt->fetch();
            return $row['id'];
        }

        return false;
    } catch(PDOException $e) {
        error_log("Supabase database error: " . $e->getMessage());

        // Fallback to API method if direct connection fails
        try {
            return insertViaSupabaseAPI($data);
        } catch(Exception $api_e) {
            error_log("Supabase API fallback failed: " . $api_e->getMessage());
            return false;
        }
    }
}

/**
 * Send email notification
 */
function sendEmailNotification($data) {
    $to = $admin_email;
    $subject = "New Contact Form Submission - " . $company_name;

    // Email headers
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: " . $from_email . "\r\n";
    $headers .= "Reply-To: " . $data['email'] . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    // Email body
    $message = "
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #ff3366; color: white; padding: 20px; text-align: center; }
            .content { background: #f9f9f9; padding: 20px; }
            .field { margin-bottom: 15px; }
            .label { font-weight: bold; color: #ff3366; }
            .value { margin-top: 5px; }
            .footer { background: #0a0a0a; color: white; padding: 15px; text-align: center; font-size: 12px; }
            .supabase-info { background: #e8f5e8; padding: 10px; border-left: 4px solid #4caf50; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>New Contact Form Submission</h1>
                <p>TechEmir - Moving Entertainment Forward</p>
            </div>
            <div class='content'>
                <div class='supabase-info'>
                    <strong>📊 Powered by Supabase</strong> - This submission has been securely stored in your Supabase database.
                </div>

                <div class='field'>
                    <div class='label'>Name:</div>
                    <div class='value'>" . htmlspecialchars($data['name']) . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Email:</div>
                    <div class='value'>" . htmlspecialchars($data['email']) . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Phone:</div>
                    <div class='value'>" . htmlspecialchars($data['phone'] ?: 'Not provided') . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Client Type:</div>
                    <div class='value'>" . htmlspecialchars($data['client_type'] ?: 'Not specified') . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Primary Service:</div>
                    <div class='value'>" . htmlspecialchars($data['service']) . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Project Details:</div>
                    <div class='value'>" . nl2br(htmlspecialchars($data['message'])) . "</div>
                </div>
                <div class='field'>
                    <div class='label'>Submitted:</div>
                    <div class='value'>" . date('Y-m-d H:i:s') . "</div>
                </div>
                <div class='field'>
                    <div class='label'>IP Address:</div>
                    <div class='value'>" . $_SERVER['REMOTE_ADDR'] . "</div>
                </div>
            </div>
            <div class='footer'>
                <p>This email was sent from the TechEmir contact form.</p>
                <p>Reply directly to this email to respond to the customer.</p>
                <p>View all submissions in your Supabase dashboard or admin panel.</p>
            </div>
        </div>
    </body>
    </html>";

    return mail($to, $subject, $message, $headers);
}

/**
 * Send confirmation email to customer
 */
function sendConfirmationEmail($data) {
    $to = $data['email'];
    $subject = "Thank you for contacting " . $company_name;

    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: " . $from_email . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    $message = "
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #ff3366; color: white; padding: 20px; text-align: center; }
            .content { background: #f9f9f9; padding: 30px; }
            .footer { background: #0a0a0a; color: white; padding: 20px; text-align: center; }
            .cta { background: #ff3366; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Thank You, " . htmlspecialchars($data['name']) . "!</h1>
                <p>TechEmir - Moving Entertainment Forward</p>
            </div>
            <div class='content'>
                <h2>We've received your message</h2>
                <p>Thank you for getting in touch with TechEmir. We've received your inquiry about <strong>" . htmlspecialchars($data['service']) . "</strong> and will get back to you shortly.</p>

                <h3>What happens next?</h3>
                <ul>
                    <li>We'll review your requirements within 4 business hours</li>
                    <li>A member of our team will contact you to discuss your project</li>
                    <li>We'll provide a detailed proposal tailored to your needs</li>
                </ul>

                <p>For urgent matters, you can reach us directly at:</p>
                <p><strong>Phone:</strong> +44 7865 797072<br>
                <strong>Email:</strong> info@techemir.co.uk</p>

                <div style='text-align: center;'>
                    <a href='https://www.techemir.co.uk' class='cta'>Visit Our Website</a>
                </div>
            </div>
            <div class='footer'>
                <p>TechEmir - Technology & Transport Solutions</p>
                <p>Moving Entertainment Forward</p>
                <p><small>Your data is securely stored and managed using Supabase infrastructure.</small></p>
            </div>
        </div>
    </body>
    </html>";

    return mail($to, $subject, $message, $headers);
}

// Main processing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $response = ['success' => false, 'message' => '', 'errors' => []];

    try {
        // Check if reCAPTCHA response exists
        if (!isset($_POST['recaptcha_response']) || empty($_POST['recaptcha_response'])) {
            throw new Exception('reCAPTCHA verification is required.');
        }

        // Verify reCAPTCHA
        if (!verifyRecaptcha($_POST['recaptcha_response'])) {
            throw new Exception('reCAPTCHA verification failed. Please try again.');
        }

        // Sanitize and validate input
        $data = [
            'name' => sanitizeInput($_POST['name'] ?? ''),
            'email' => sanitizeInput($_POST['email'] ?? ''),
            'phone' => sanitizeInput($_POST['phone'] ?? ''),
            'client_type' => sanitizeInput($_POST['client_type'] ?? ''),
            'service' => sanitizeInput($_POST['service'] ?? ''),
            'message' => sanitizeInput($_POST['message'] ?? '')
        ];

        // Validation
        if (empty($data['name'])) {
            $response['errors'][] = 'Name is required.';
        }

        if (empty($data['email']) || !validateEmail($data['email'])) {
            $response['errors'][] = 'Valid email address is required.';
        }

        if (empty($data['service'])) {
            $response['errors'][] = 'Please select a service.';
        }

        if (empty($data['message'])) {
            $response['errors'][] = 'Project details are required.';
        }

        if (!empty($response['errors'])) {
            throw new Exception('Please correct the errors and try again.');
        }

        // Rate limiting check (simple implementation)
        $ip = $_SERVER['REMOTE_ADDR'];
        $rate_limit_file = sys_get_temp_dir() . '/techemir_rate_limit_' . md5($ip);

        if (file_exists($rate_limit_file)) {
            $last_submission = filemtime($rate_limit_file);
            if (time() - $last_submission < 60) { // 1 minute rate limit
                throw new Exception('Please wait before submitting another message.');
            }
        }

        // Create rate limit file
        touch($rate_limit_file);

        // Save to Supabase
        $submission_id = saveToSupabase($data);

        if (!$submission_id) {
            throw new Exception('Failed to save submission. Please try again.');
        }

        // Send notifications
        $admin_email_sent = sendEmailNotification($data);
        $customer_email_sent = sendConfirmationEmail($data);

        if ($admin_email_sent) {
            $response['success'] = true;
            $response['message'] = 'Thank you! Your message has been sent successfully. We\'ll get back to you within 4 business hours.';

            // Log successful submission
            error_log("Contact form submission from: " . $data['email'] . " - Supabase ID: " . $submission_id);

        } else {
            // Data was saved but email failed
            $response['success'] = true;
            $response['message'] = 'Your message has been received and saved. We\'ll contact you soon!';
            error_log("Email sending failed for submission ID: " . $submission_id);
        }

    } catch (Exception $e) {
        $response['message'] = $e->getMessage();
        error_log("Contact form error: " . $e->getMessage());
    }

    // Return JSON response for AJAX requests
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode($response);
        exit;
    }

    // Redirect for regular form submissions
    if ($response['success']) {
        header('Location: ../index.html?success=1');
    } else {
        header('Location: ../index.html?error=' . urlencode($response['message']));
    }
    exit;

} else {
    // Redirect if accessed directly
    header('Location: ../index.html');
    exit;
}
?>

-- Create the contact_submissions table
CREATE TABLE contact_submissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    client_type VARCHAR(100),
    service VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'unread' CHECK (status IN ('read', 'unread')),
    admin_notes TEXT,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_contact_status ON contact_submissions(status);
CREATE INDEX idx_contact_submitted_at ON contact_submissions(submitted_at);
CREATE INDEX idx_contact_service ON contact_submissions(service);

-- Enable Row Level Security (RLS)
ALTER TABLE contact_submissions ENABLE ROW LEVEL SECURITY;

-- Create policy for service role (allows all operations)
CREATE POLICY "Enable all operations for service role" ON contact_submissions
    FOR ALL USING (auth.role() = 'service_role');

-- Create policy for anon users (insert only)
CREATE POLICY "Enable insert for anon users" ON contact_submissions
    FOR INSERT WITH CHECK (true);
