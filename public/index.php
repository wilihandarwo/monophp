<?php

// Strict types
declare(strict_types=1);

// <env>
const SITE_ENV_FILE = __DIR__ . "/../.env";
function load_env()
{
    if (!file_exists(SITE_ENV_FILE)) {
        die(".env file not found yes");
    }

    $lines = file(SITE_ENV_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), "#") === 0) {
            continue;
        }
        [$key, $value] = explode("=", $line, 2);
        $key = trim($key);
        $value = trim($value);
        if (strpos($value, '"') === 0 || strpos($value, "'") === 0) {
            $value = substr($value, 1, -1);
        }
        putenv("$key=$value");
        $_ENV[$key] = $value;
    }
}
load_env();
// </env>





// <config>
const SITE_APP_VERSION = "1.0.0";
const SITE_DB_FILE = __DIR__ . "/../database/monophp.sqlite";
const SITE_LOG_FILE = __DIR__ . "/../logs/app.log";
define('SITE_DOMAIN', getenv('SITE_DOMAIN') ?: 'localhost');
// </config>





// <session-management>
ini_set("session.use_only_cookies", "1");
// Extract domain from SITE_DOMAIN (remove protocol if present)
$session_domain = SITE_DOMAIN;
if (strpos($session_domain, 'http://') === 0) {
    $session_domain = substr($session_domain, 7);
} elseif (strpos($session_domain, 'https://') === 0) {
    $session_domain = substr($session_domain, 8);
}

session_set_cookie_params([
    "lifetime" => 86400, // 24 hours
    "path" => "/",
    "domain" => $session_domain === 'localhost' ? '' : $session_domain,
    "secure" => isset($_SERVER["HTTPS"]),
    "httponly" => true,
    "samesite" => "Lax",
]);
session_start();

// Clean up stale OAuth data on every page load (but not during OAuth callback)
if (isset($_SESSION['oauth_timestamp']) && (time() - $_SESSION['oauth_timestamp']) > 300 && !isset($_GET['code'])) {
    // OAuth state is older than 5 minutes, clear it (unless we're processing OAuth callback)
    clear_oauth_session();
}

// Clean up expired sessions
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 86400) {
    // Session is older than 24 hours, clear user data
    unset($_SESSION['user'], $_SESSION['login_time'], $_SESSION['login_ip']);
}
// </session-management>





// <security-headers>
// csrf
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION["csrf_token"];

// csp
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://*.googleusercontent.com data:; https:; connect-src 'self' https:;");
// </security-headers>





// <error-handling>
// $is_development = false;
$is_development =
    $_SERVER["SERVER_NAME"] === "localhost" ||
    $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
    $_SERVER["REMOTE_ADDR"] === "127.0.0.1";

// Setup error log
$error_log_path = SITE_LOG_FILE;
if (!file_exists($error_log_path)) {
    touch($error_log_path);
    chmod($error_log_path, 0666);
}

// Helper function to get error type name
function getErrorTypeName($errno) {
    return match ($errno) { E_ERROR => "Fatal Error", E_WARNING => "Warning", E_PARSE => "Parse Error", E_NOTICE => "Notice", E_CORE_ERROR => "Core Error", E_CORE_WARNING => "Core Warning", E_COMPILE_ERROR => "Compile Error", E_COMPILE_WARNING => "Compile Warning", E_USER_ERROR => "User Error", E_USER_WARNING => "User Warning", E_USER_NOTICE => "User Notice", E_RECOVERABLE_ERROR => "Recoverable Error", E_DEPRECATED => "Deprecated", E_USER_DEPRECATED => "User Deprecated", default => "Unknown Error", };
}

// Helper function to get code context
function getCodeContext($file, $line, $context_lines = 5) {
    if (!file_exists($file)) return "File not found";

    $lines = file($file);
    $start = max(0, $line - $context_lines - 1);
    $end = min(count($lines), $line + $context_lines);

    $context = "";
    for ($i = $start; $i < $end; $i++) {
        $line_num = $i + 1;
        $marker = ($line_num == $line) ? " >>> " : "     ";
        $context .= sprintf("%s%d: %s", $marker, $line_num, $lines[$i]);
    }

    return $context;
}

// Development environment
if ($is_development) {
    error_reporting(E_ALL);
    ini_set("display_errors", 0);
    ini_set("display_startup_errors", 0);

    // Error handler for development
    set_error_handler(function ($errno, $errstr, $errfile, $errline) {
        $error_type = getErrorTypeName($errno);
        $code_context = getCodeContext($errfile, $errline);

        echo "<div style='font-family: monospace; background: #f8f8f8; padding: 20px; margin: 20px; border-left: 5px solid #ff5757;'>";
        echo "<h3 style='color: #ff5757; margin: 0 0 10px 0;'>⚠️ {$error_type}</h3>";
        echo "<p><strong>Message:</strong> {$errstr}</p>";
        echo "<p><strong>File:</strong> {$errfile}</p>";
        echo "<p><strong>Line:</strong> {$errline}</p>";
        echo "<details><summary><strong>Code Context</strong></summary>";
        echo "<pre style='background: #fff; padding: 10px; overflow-x: auto;'>{$code_context}</pre>";
        echo "</details>";
        echo "</div>";

        return true;
    });

    // Exception handler for development
    set_exception_handler(function ($e) {
        $code_context = getCodeContext($e->getFile(), $e->getLine());

        echo "<div style='font-family: monospace; background: #f8f8f8; padding: 20px; margin: 20px; border-left: 5px solid #ff5757;'>";
        echo "<h3 style='color: #ff5757; margin: 0 0 10px 0;'>💥 Uncaught Exception</h3>";
        echo "<p><strong>Message:</strong> " . $e->getMessage() . "</p>";
        echo "<p><strong>File:</strong> " . $e->getFile() . "</p>";
        echo "<p><strong>Line:</strong> " . $e->getLine() . "</p>";
        echo "<details><summary><strong>Code Context</strong></summary>";
        echo "<pre style='background: #fff; padding: 10px; overflow-x: auto;'>{$code_context}</pre>";
        echo "</details>";
        echo "<details><summary><strong>Stack Trace</strong></summary>";
        echo "<pre style='background: #fff; padding: 10px; overflow-x: auto;'>" . $e->getTraceAsString() . "</pre>";
        echo "</details>";
        echo "</div>";
    });

// Production environment
} else {
    error_reporting(E_ALL);
    ini_set("display_errors", 0);
    ini_set("display_startup_errors", 0);
    ini_set("log_errors", 1);
    ini_set("error_log", $error_log_path);

    // Start error group logging
    date_default_timezone_set("Asia/Jakarta");
    $date = date("Y-m-d H:i:s");
    $uri = $_SERVER["REQUEST_URI"] ?? 'CLI';
    $separator = "\n========== Error Group: {$date} WIB | URI: {$uri} ==========\n";
    file_put_contents($error_log_path, $separator, FILE_APPEND);

    // Error handler for production
    set_error_handler(function ($errno, $errstr, $errfile, $errline) use ($error_log_path) {
        $date = date("Y-m-d H:i:s");
        $error_type = getErrorTypeName($errno);
        $error_message = "[{$date}] {$error_type} [{$errno}]: {$errstr}\n";
        $error_message .= "File: {$errfile}\n";
        $error_message .= "Line: {$errline}\n\n";
        file_put_contents($error_log_path, $error_message, FILE_APPEND);
        return true;
    });

    // Exception handler for production
    set_exception_handler(function ($e) use ($error_log_path) {
        $date = date("Y-m-d H:i:s");
        $error_message = "[{$date}] Uncaught Exception: " . $e->getMessage() . "\n";
        $error_message .= "File: " . $e->getFile() . "\n";
        $error_message .= "Line: " . $e->getLine() . "\n";
        $error_message .= "\nTrace:\n" . $e->getTraceAsString() . "\n";
        file_put_contents($error_log_path, $error_message, FILE_APPEND);

        // End error group
        $separator = "==========\n\n";
        file_put_contents($error_log_path, $separator, FILE_APPEND);

        http_response_code(500);
        echo "<div style='font-family: monospace; background: #f8f8f8; padding: 20px; margin: 20px; border-left: 5px solid #ff5757;'>";
        echo "<h3 style='color: #ff5757; margin: 0 0 10px 0;'>⚠️ Server Error</h3>";
        echo "<p>Sorry, something went wrong! Our team has been notified.</p>";
        echo "</div>";
        exit();
    });
}
// Sample error trigger:
// trigger_error("This is a sample error message.", E_USER_ERROR);
// undefined_function();
// </error-handling>





// <database>
// Creates and returns a PDO database connection.
function get_db_connection(): PDO
{
    try {
        $pdo = new PDO("sqlite:" . SITE_DB_FILE);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec("PRAGMA foreign_keys = ON;");
        return $pdo;
    } catch (PDOException $e) {
        die("Database connection failed: " . $e->getMessage());
    }
}

// Initializes the core database tables if they don't exist.
function initialize_database(): void
{
    $pdo = get_db_connection();
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            picture TEXT,
            role VARCHAR(255) DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );");
    $pdo->exec("CREATE TABLE IF NOT EXISTS migrations (
            version TEXT UNIQUE NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );");
}

// Runs pending database migrations to update the schema without data loss.
function run_migrations(): void
{
    $migrations = [
        // Migrations can be added here in the future. Example:
        // '2025_08_01_100000_add_priority_to_todos' => "ALTER TABLE todos ADD COLUMN priority TEXT DEFAULT 'Medium';"
    ];

    $pdo = get_db_connection();
    $applied_migrations = $pdo
        ->query("SELECT version FROM migrations")
        ->fetchAll(PDO::FETCH_COLUMN);

    $pdo->beginTransaction();
    try {
        foreach ($migrations as $version => $sql) {
            if (!in_array($version, $applied_migrations)) {
                $pdo->exec($sql);
                $stmt = $pdo->prepare(
                    "INSERT INTO migrations (version) VALUES (:version)",
                );
                $stmt->execute([":version" => $version]);
            }
        }
        $pdo->commit();
    } catch (Exception $e) {
        $pdo->rollBack();
        die("A database migration failed: " . $e->getMessage());
    }
}

// Initialize and migrate database on every run.
initialize_database();
run_migrations();
// </database>





// <helpers>
// Escapes special characters in a string for safe HTML output.
function e(?string $string): string
{
    return htmlspecialchars((string) $string, ENT_QUOTES, "UTF-8");
}

// Sanitizes input data to prevent XSS attacks.
function sanitize_input(array $data): array {
    $sanitized = [];
    foreach ($data as $key => $value) {
        if (is_string($value)) {
            $sanitized[$key] = trim(strip_tags($value));
        } else {
            $sanitized[$key] = $value;
        }
    }
    return $sanitized;
}

// CSRF token generation and validation
function csrf_token(): string {
    return $_SESSION['csrf_token'];
}

// CSRF token field for forms
function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

// Redirects to a URL and exits script execution.
function redirect(string $url): void
{
    header("Location: " . $url);
    exit();
}
// </helpers>





// <authentication>
// Clear stale OAuth sessions and data
function clear_oauth_session(): void
{
    $keys_to_clear = ['oauth_state', 'oauth_timestamp', 'google_auth_error', 'google_auth_url'];
    foreach ($keys_to_clear as $key) {
        unset($_SESSION[$key]);
    }
}

// Validate user session
function is_valid_session(): bool
{
    if (!isset($_SESSION['user']) || !isset($_SESSION['login_time'])) {
        return false;
    }

    // Check if session is too old (24 hours)
    if ((time() - $_SESSION['login_time']) > 86400) {
        return false;
    }

    // Check if IP changed (optional security measure)
    $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (isset($_SESSION['login_ip']) && $_SESSION['login_ip'] !== $current_ip) {
        error_log("Session IP mismatch. Original: " . $_SESSION['login_ip'] . ", Current: " . $current_ip);
        // Uncomment the next line if you want strict IP validation
        // return false;
    }

    return true;
}

// Initialize clean OAuth session
function init_oauth_session(): void
{
    // Clear any existing OAuth data
    clear_oauth_session();

    // Clear any error messages
    unset($_SESSION['error']);
}

// Checks if a user is currently logged in.
function is_logged_in(): bool
{
    return isset($_SESSION["user"]);
}

// Gets the current user's data from the session.
function get_user(): ?array
{
    return $_SESSION["user"] ?? null;
}
// </authentication>





// <google-oauth>
// Google OAuth - Configuration
function get_google_config(): array
{
    $site_domain = SITE_DOMAIN;
    $is_development =
        $site_domain === 'localhost' ||
        $_SERVER["SERVER_NAME"] === "localhost" ||
        $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
        $_SERVER["REMOTE_ADDR"] === "127.0.0.1";

    $redirect_uri = $is_development
        ? 'http://localhost:8000/auth/google/callback'
        : getenv('GOOGLE_REDIRECT_URI');

    return [
        'client_id' => getenv('GOOGLE_CLIENT_ID') ?? '',
        'client_secret' => getenv('GOOGLE_CLIENT_SECRET') ?? '',
        'redirect_uri' => $redirect_uri,
        'scope' => 'openid email profile'
    ];
}

// Google OAuth - Generate Google OAuth URL with state validation
function get_google_auth_url(): string
{
    $config = get_google_config();

    // Generate and store state for CSRF protection
    $state = bin2hex(random_bytes(16));
    $_SESSION['oauth_state'] = $state;
    $_SESSION['oauth_timestamp'] = time();

    $params = [
        'client_id' => $config['client_id'],
        'redirect_uri' => $config['redirect_uri'],
        'scope' => $config['scope'],
        'response_type' => 'code',
        'access_type' => 'online',
        'state' => $state,
        'prompt' => 'select_account' // Force account selection to avoid cached sessions
    ];

    return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
}

// Google OAuth - Exchange authorization code for access token with error handling
function exchange_code_for_token(string $code): ?array
{
    $config = get_google_config();

    $data = [
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret'],
        'code' => $code,
        'grant_type' => 'authorization_code',
        'redirect_uri' => $config['redirect_uri']
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://oauth2.googleapis.com/token');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($curl_error) {
        error_log("Google OAuth token exchange cURL error: " . $curl_error);
        return null;
    }

    if ($http_code === 200 && $response) {
        $token_data = json_decode($response, true);
        if (json_last_error() === JSON_ERROR_NONE && isset($token_data['access_token'])) {
            return $token_data;
        }
        error_log("Google OAuth token exchange JSON decode error or missing access_token");
    } else {
        error_log("Google OAuth token exchange failed. HTTP Code: $http_code, Response: $response");
    }

    return null;
}

// Google OAuth - Get user information from Google with error handling
function get_google_user_info(string $access_token): ?array
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.googleapis.com/oauth2/v2/userinfo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $access_token]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($curl_error) {
        error_log("Google OAuth user info cURL error: " . $curl_error);
        return null;
    }

    if ($http_code === 200 && $response) {
        $user_data = json_decode($response, true);
        if (json_last_error() === JSON_ERROR_NONE && isset($user_data['email'])) {
            return $user_data;
        }
        error_log("Google OAuth user info JSON decode error or missing email");
    } else {
        error_log("Google OAuth user info failed. HTTP Code: $http_code, Response: $response");
    }

    return null;
}

// Google OAuth - Create or update user from Google data
function create_or_update_google_user(array $google_user): ?array
{
    $pdo = get_db_connection();

    try {
        // Check if user exists
        $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ? OR email = ?');
        $stmt->execute([$google_user['id'], $google_user['email']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Update existing user
            $stmt = $pdo->prepare('
                UPDATE users
                SET google_id = ?, name = ?, email = ?, picture = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ');
            $stmt->execute([
                $google_user['id'],
                $google_user['name'],
                $google_user['email'],
                $google_user['picture'],
                $user['id']
            ]);

            // Return updated user data with role preserved
            return [
                'id' => $user['id'],
                'google_id' => $google_user['id'],
                'name' => $google_user['name'],
                'email' => $google_user['email'],
                'picture' => $google_user['picture'],
                'role' => $user['role'] ?? 'user',
                'created_at' => $user['created_at'],
                'updated_at' => date('Y-m-d H:i:s')
            ];
        } else {
            // Create new user with default role
            $stmt = $pdo->prepare('
                INSERT INTO users (google_id, name, email, picture, role)
                VALUES (?, ?, ?, ?, ?)
            ');
            $stmt->execute([
                $google_user['id'],
                $google_user['name'],
                $google_user['email'],
                $google_user['picture'],
                'user'
            ]);

            $user_id = $pdo->lastInsertId();

            // Return newly created user data
            return [
                'id' => $user_id,
                'google_id' => $google_user['id'],
                'name' => $google_user['name'],
                'email' => $google_user['email'],
                'picture' => $google_user['picture'],
                'role' => 'user',
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];
        }
    } catch (PDOException $e) {
        error_log('Database error in create_or_update_google_user: ' . $e->getMessage());
        return null;
    }
}
// </google-oauth>





// <view-initialization>
$errors = [];
$messages = [];
$user = get_user();
$pdo = get_db_connection();
// </view-initialization>






// <oauth-flow>
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$path = trim($path, '/');

// Validate existing session
if (isset($_SESSION['user']) && !is_valid_session()) {
    // Invalid session, clear it
    $_SESSION = array();
    session_destroy();
    session_start();
}

// Handle OAuth state cleanup (manual trigger)
if (isset($_GET['clear_oauth'])) {
    init_oauth_session();
    header('Location: /');
    exit;
}

// Handle Google OAuth callback
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    $state = $_GET['state'] ?? '';
    $error_param = $_GET['error'] ?? '';

    // Handle OAuth errors
    if ($error_param) {
        error_log("Google OAuth error: " . $error_param);
        $errors[] = 'Authentication was cancelled or failed. Please try again.';
    }
    // Validate state parameter for CSRF protection
    elseif (empty($state) || !isset($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
        error_log("Google OAuth state validation failed. Expected: " . ($_SESSION['oauth_state'] ?? 'none') . ", Got: " . $state);
        $errors[] = 'Invalid authentication state. Please try again.';
    }
    // Check if state is not too old (5 minutes max)
    elseif (!isset($_SESSION['oauth_timestamp']) || (time() - $_SESSION['oauth_timestamp']) > 300) {
        error_log("Google OAuth state expired. Timestamp: " . ($_SESSION['oauth_timestamp'] ?? 'none'));
        $errors[] = 'Authentication session expired. Please try again.';
    }
    else {
        // Clear OAuth state from session
        unset($_SESSION['oauth_state'], $_SESSION['oauth_timestamp']);

        try {
            // Exchange code for access token
            $token_info = exchange_code_for_token($code);

            if (isset($token_info['access_token'])) {
                // Get user info from Google
                $user_data = get_google_user_info($token_info['access_token']);

                if ($user_data && isset($user_data['email'])) {
                    // Save user to database and store in session
                    $db_user = create_or_update_google_user($user_data);

                    if ($db_user) {
                        // Regenerate session ID for security
                        session_regenerate_id(true);

                        $_SESSION['user'] = [
                            'id' => $db_user['id'],
                            'google_id' => $db_user['google_id'],
                            'name' => $db_user['name'],
                            'email' => $db_user['email'],
                            'picture' => $db_user['picture'],
                            'role' => $db_user['role'] ?? 'user',
                            'created_at' => $db_user['created_at'],
                            'updated_at' => $db_user['updated_at']
                        ];
                        $_SESSION['login_time'] = time();
                        $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

                        // Redirect to dashboard
                        redirect('/dashboard');
                    } else {
                        error_log("Failed to create/update user in database for email: " . $user_data['email']);
                        $errors[] = 'Failed to create user account. Please try again.';
                    }
                } else {
                    error_log("Failed to get user info from Google or missing email");
                    $errors[] = 'Failed to retrieve user information from Google. Please try again.';
                }
            } else {
                error_log("Failed to exchange code for token");
                $errors[] = 'Failed to authenticate with Google. Please try again.';
            }
        } catch (Exception $e) {
            error_log("Google OAuth exception: " . $e->getMessage());
            $errors[] = "Authentication failed. Please try again.";
        }
    }

    // Clean up OAuth session data on any error
    if (!empty($errors)) {
        unset($_SESSION['oauth_state'], $_SESSION['oauth_timestamp']);
    }
}

// Handle logout with comprehensive cleanup
if (isset($_GET['logout']) || $path === 'logout') {
    // Clear all session data
    $_SESSION = array();

    // Delete session cookie if it exists
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    // Clear any OAuth-related cookies
    $cookie_options = [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Lax'
    ];

    // Clear potential OAuth cookies
    setcookie('oauth_state', '', $cookie_options);
    setcookie('google_auth', '', $cookie_options);

    // Destroy session
    session_destroy();

    // Redirect with cache busting
    header('Location: /?t=' . time());
    exit;
}
// </oauth-flow>





// <routing>
// Define available pages
$pages = [
    '' => 'home',
    'home' => 'home',
    'about' => 'about',
    'contact' => 'contact',
    'dashboard' => 'dashboard',
    'auth/google/callback' => 'oauth_callback',
    'logout' => 'logout'
];

// Determine current page
$current_page = $pages[$path] ?? 'home';

// Check if user is logged in
$is_logged_in = is_logged_in();

// Protect dashboard page
if ($current_page === 'dashboard' && !$is_logged_in) {
    redirect('/');
}

// Page titles
$page_titles = [
    'home' => 'MonoPHP',
    'about' => 'About - MonoPHP',
    'contact' => 'Contact - MonoPHP',
    'dashboard' => 'Dashboard - MonoPHP'
];
// </routing>





?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo e($page_titles[$current_page] ?? 'MonoPHP'); ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8f9fa;
            line-height: 1.6;
            color: #333;
        }

        .navbar {
            background: white;
            border-bottom: 1px solid #e9ecef;
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: #333;
            text-decoration: none;
        }

        .nav-links {
            display: flex;
            list-style: none;
            gap: 2rem;
            align-items: center;
        }

        .nav-links a {
            text-decoration: none;
            color: #666;
            font-weight: 500;
            transition: color 0.2s;
        }

        .nav-links a:hover,
        .nav-links a.active {
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }

        .hero {
            text-align: center;
            padding: 4rem 0;
        }

        .hero h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: #333;
        }

        .hero p {
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 2rem;
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: #333;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            transition: all 0.2s;
            border: none;
            cursor: pointer;
        }

        .btn:hover {
            background: #555;
            transform: translateY(-1px);
        }

        .btn-google {
            background: #4285f4;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-google:hover {
            background: #3367d6;
        }

        .btn-danger {
            background: #dc3545;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        .content {
            max-width: 800px;
            margin: 0 auto;
        }

        .content h2 {
            font-size: 2rem;
            margin-bottom: 1rem;
            color: #333;
        }

        .content p {
            margin-bottom: 1rem;
            color: #666;
        }

        .user-profile {
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .user-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 1rem;
            border: 3px solid #f0f0f0;
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            border: 1px solid #f5c6cb;
        }

        @media (max-width: 768px) {
            .nav-container {
                padding: 0 1rem;
            }

            .nav-links {
                gap: 1rem;
            }

            .container {
                padding: 2rem 1rem;
            }

            .hero h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="logo">MonoPHP</a>
            <ul class="nav-links">
                <li><a href="/" class="<?php echo $current_page === 'home' ? 'active' : ''; ?>">Home</a></li>
                <li><a href="/about" class="<?php echo $current_page === 'about' ? 'active' : ''; ?>">About</a></li>
                <li><a href="/contact" class="<?php echo $current_page === 'contact' ? 'active' : ''; ?>">Contact</a></li>
                <?php if ($is_logged_in): ?>
                    <li><a href="/dashboard" class="<?php echo $current_page === 'dashboard' ? 'active' : ''; ?>">Dashboard</a></li>
                    <li><a href="/logout" class="btn btn-danger">Logout</a></li>
                <?php else: ?>
                    <?php
                    // Generate OAuth URL only if not already set in session
                    if (!isset($_SESSION['google_auth_url']) || !isset($_SESSION['oauth_state'])) {
                        $_SESSION['google_auth_url'] = get_google_auth_url();
                    }
                    ?>
                    <li><a href="<?php echo e($_SESSION['google_auth_url']); ?>" class="btn btn-google">
                        <svg width="16" height="16" viewBox="0 0 24 24">
                            <path fill="white" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                            <path fill="white" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                            <path fill="white" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                            <path fill="white" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                        </svg>
                        Login
                    </a></li>
                <?php endif; ?>
            </ul>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <?php if (!empty($errors)): ?>
            <div class="error">
                <?php foreach ($errors as $error): ?>
                    <p><?php echo e($error); ?></p>
                <?php endforeach; ?>
                <div style="margin-top: 10px; font-size: 0.9rem;">
                    <a href="?clear_oauth=1" style="color: #721c24; text-decoration: underline;">Clear OAuth state and try again</a>
                </div>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['debug']) && $_GET['debug'] === '1'): ?>
            <div style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 1rem; border-radius: 5px; margin-bottom: 2rem; font-family: monospace; font-size: 0.875rem;">
                <strong>Debug Information:</strong><br>
                Session ID: <?= session_id() ?><br>
                OAuth State: <?= isset($_SESSION['oauth_state']) ? 'Set (' . substr($_SESSION['oauth_state'], 0, 8) . '...)' : 'Not set' ?><br>
                OAuth Timestamp: <?= isset($_SESSION['oauth_timestamp']) ? date('Y-m-d H:i:s', $_SESSION['oauth_timestamp']) : 'Not set' ?><br>
                User Session: <?= isset($_SESSION['user']) ? 'Logged in as ' . $_SESSION['user']['email'] : 'Not logged in' ?><br>
                Current URL: <?= $_SERVER['REQUEST_URI'] ?? 'Unknown' ?><br>
                Server Name: <?= $_SERVER['SERVER_NAME'] ?? 'Unknown' ?><br>
            </div>
        <?php endif; ?>

        <?php
        // Page content based on current page
        switch ($current_page) {
            case 'home':
                ?>
                <div class="hero">
                    <h1>MonoPHP</h1>
                    <p>Simple & Minimalist PHP Framework</p>

                    <?php if (!$is_logged_in): ?>
                        <p>Build fast, secure web applications with minimal code.</p>
                        <a href="<?php echo e($_SESSION['google_auth_url']); ?>" class="btn btn-google">
                            <svg width="16" height="16" viewBox="0 0 24 24">
                                <path fill="white" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                                <path fill="white" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                                <path fill="white" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                                <path fill="white" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                            </svg>
                            Get Started with Google
                        </a>
                        <div style="margin-top: 1rem;">
                            <small style="color: #666;">
                                Having login issues? <a href="?clear_oauth=1" style="color: #666; text-decoration: underline;">Clear OAuth state</a>
                            </small>
                        </div>
                    <?php else: ?>
                        <p>Welcome back, <strong><?php echo e($_SESSION['user']['name']); ?></strong>!</p>
                        <a href="/dashboard" class="btn">Go to Dashboard</a>
                    <?php endif; ?>
                </div>

                <div class="content">
                    <h2>Features</h2>
                    <p>MonoPHP is designed for developers who want to build web applications quickly without the complexity of large frameworks.</p>

                </div>
                <?php
                break; ?>
            <?php case 'about': ?>
                <div class="content">
                    <h2>About MonoPHP</h2>
                    <p>MonoPHP is a minimalist PHP framework inspired by the philosophy of keeping things simple and effective. Built with modern web development practices in mind, it provides just enough structure to build robust applications without the bloat.</p>

                    <h2>Philosophy</h2>
                    <p>We believe in the power of simplicity. MonoPHP follows the principle that code should be:</p>

                    <ul style="margin-bottom: 2rem;">
                        <li><strong>Readable</strong> - Clean, self-documenting code</li>
                        <li><strong>Maintainable</strong> - Easy to modify and extend</li>
                        <li><strong>Secure</strong> - Built-in security best practices</li>
                        <li><strong>Fast</strong> - Optimized for performance</li>
                    </ul>

                    <h2>Core Features</h2>

                    <div style="display: grid; gap: 1.5rem; margin-bottom: 2rem;">
                        <div style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <h3 style="margin-bottom: 0.5rem; color: #333;">🛣️ Simple Routing</h3>
                            <p style="margin: 0; color: #666;">Clean URL routing with easy-to-manage page structure. Add new pages by simply updating the switch statement.</p>
                        </div>

                        <div style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <h3 style="margin-bottom: 0.5rem; color: #333;">🔐 OAuth Integration</h3>
                            <p style="margin: 0; color: #666;">Built-in Google OAuth authentication with secure session management and CSRF protection.</p>
                        </div>

                        <div style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <h3 style="margin-bottom: 0.5rem; color: #333;">🗄️ SQLite Database</h3>
                            <p style="margin: 0; color: #666;">Lightweight SQLite database with automatic migrations and PDO for secure database operations.</p>
                        </div>

                        <div style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <h3 style="margin-bottom: 0.5rem; color: #333;">⚡ Error Handling</h3>
                            <p style="margin: 0; color: #666;">Comprehensive error handling with development-friendly debugging and production-ready logging.</p>
                        </div>
                    </div>

                    <h2>Getting Started</h2>
                    <p>MonoPHP is designed to get you up and running quickly:</p>

                    <ol style="margin-bottom: 2rem;">
                        <li>Clone the repository</li>
                        <li>Copy <code>.env.example</code> to <code>.env</code> and configure your settings</li>
                        <li>Set up your Google OAuth credentials</li>
                        <li>Start building your application</li>
                    </ol>

                    <p>That's it! You're ready to build amazing web applications with MonoPHP.</p>
                </div>
                <?php
                break;

            case 'contact':
                ?>
                <div class="content">
                    <h2>Contact Us</h2>
                    <p>Have questions about MonoPHP? We'd love to hear from you. Send us a message and we'll get back to you as soon as possible.</p>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem;">
                        <div>
                            <form method="POST" action="/contact" style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                                <?php echo csrf_field(); ?>

                                <div style="margin-bottom: 1rem;">
                                    <label for="name" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Name</label>
                                    <input type="text" id="name" name="name" required
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                                </div>

                                <div style="margin-bottom: 1rem;">
                                    <label for="email" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Email</label>
                                    <input type="email" id="email" name="email" required
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                                </div>

                                <div style="margin-bottom: 1rem;">
                                    <label for="subject" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Subject</label>
                                    <input type="text" id="subject" name="subject" required
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                                </div>

                                <div style="margin-bottom: 1.5rem;">
                                    <label for="message" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Message</label>
                                    <textarea id="message" name="message" rows="5" required
                                              style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem; resize: vertical;"></textarea>
                                </div>

                                <button type="submit" class="btn" style="width: 100%;">Send Message</button>
                            </form>
                        </div>

                        <div>
                            <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); height: fit-content;">
                                <h3 style="margin-bottom: 1rem; color: #333;">Get in Touch</h3>

                                <div style="margin-bottom: 1.5rem;">
                                    <h4 style="margin-bottom: 0.5rem; color: #333;">📧 Email</h4>
                                    <p style="margin: 0; color: #666;">hello@monophp.dev</p>
                                </div>

                                <div style="margin-bottom: 1.5rem;">
                                    <h4 style="margin-bottom: 0.5rem; color: #333;">💬 Community</h4>
                                    <p style="margin: 0; color: #666;">Join our community discussions on GitHub</p>
                                </div>

                                <div style="margin-bottom: 1.5rem;">
                                    <h4 style="margin-bottom: 0.5rem; color: #333;">📚 Documentation</h4>
                                    <p style="margin: 0; color: #666;">Check out our comprehensive documentation and examples</p>
                                </div>

                                <div>
                                    <h4 style="margin-bottom: 0.5rem; color: #333;">🐛 Bug Reports</h4>
                                    <p style="margin: 0; color: #666;">Found a bug? Please report it on our GitHub issues page</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <style>
                @media (max-width: 768px) {
                    .content > div {
                        grid-template-columns: 1fr !important;
                    }
                }
                </style>
                <?php
                break;

            case 'dashboard':
                // Ensure user is logged in (this check is also done in routing)
                if (!$is_logged_in) {
                    redirect('/');
                }

                $user = $_SESSION['user'];
                ?>

                <div class="content">
                    <h2>Dashboard</h2>
                    <p>Welcome to your dashboard, <?php echo e($user['name']); ?>!</p>

                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; margin-top: 2rem;">
                        <!-- User Profile Card -->
                        <div class="user-profile">
                            <img src="<?php echo e($user['picture']); ?>" alt="Profile Picture" class="user-avatar">
                            <h3 style="margin-bottom: 0.5rem; color: #333;"><?php echo e($user['name']); ?></h3>
                            <p style="margin-bottom: 1rem; color: #666;"><?php echo e($user['email']); ?></p>
                            <p style="margin-bottom: 1rem; font-size: 0.9rem; color: #888;">
                                Role: <span style="background: #e9ecef; padding: 0.25rem 0.5rem; border-radius: 3px;"><?php echo e($user['role'] ?? 'user'); ?></span>
                            </p>
                            <p style="margin-bottom: 1.5rem; font-size: 0.9rem; color: #888;">
                                Member since: <?php echo date('M j, Y', strtotime($user['created_at'])); ?>
                            </p>
                            <a href="/logout" class="btn btn-danger" style="width: 100%;">Logout</a>
                        </div>

                        <!-- Dashboard Content -->
                        <div>
                            <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 2rem;">
                                <h3 style="margin-bottom: 1rem; color: #333;">📊 Quick Stats</h3>

                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                                    <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 5px;">
                                        <div style="font-size: 2rem; font-weight: 700; color: #333;">1</div>
                                        <div style="font-size: 0.9rem; color: #666;">Active Sessions</div>
                                    </div>

                                    <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 5px;">
                                        <div style="font-size: 2rem; font-weight: 700; color: #333;"><?php echo date('j'); ?></div>
                                        <div style="font-size: 0.9rem; color: #666;">Days This Month</div>
                                    </div>

                                    <div style="text-align: center; padding: 1rem; background: #f8f9fa; border-radius: 5px;">
                                        <div style="font-size: 2rem; font-weight: 700; color: #333;">✓</div>
                                        <div style="font-size: 0.9rem; color: #666;">Account Verified</div>
                                    </div>
                                </div>
                            </div>

                            <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 2rem;">
                                <h3 style="margin-bottom: 1rem; color: #333;">🚀 Quick Actions</h3>

                                <div style="display: grid; gap: 1rem;">
                                    <a href="/" class="btn" style="text-decoration: none; text-align: center;">🏠 Go to Homepage</a>
                                    <a href="/about" class="btn" style="text-decoration: none; text-align: center; background: #6c757d;">📖 Learn More About MonoPHP</a>
                                    <a href="/contact" class="btn" style="text-decoration: none; text-align: center; background: #17a2b8;">💬 Contact Support</a>
                                </div>
                            </div>

                            <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                                <h3 style="margin-bottom: 1rem; color: #333;">📝 Recent Activity</h3>

                                <div style="border-left: 3px solid #e9ecef; padding-left: 1rem;">
                                    <div style="margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #f8f9fa;">
                                        <div style="font-weight: 500; color: #333;">Logged in successfully</div>
                                        <div style="font-size: 0.9rem; color: #666;">Today at <?php echo date('g:i A'); ?></div>
                                    </div>

                                    <div style="margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #f8f9fa;">
                                        <div style="font-weight: 500; color: #333;">Account created</div>
                                        <div style="font-size: 0.9rem; color: #666;"><?php echo date('M j, Y \a\t g:i A', strtotime($user['created_at'])); ?></div>
                                    </div>

                                    <div>
                                        <div style="font-weight: 500; color: #333;">Welcome to MonoPHP!</div>
                                        <div style="font-size: 0.9rem; color: #666;">Start exploring the features</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <style>
                @media (max-width: 768px) {
                    .content > div {
                        grid-template-columns: 1fr !important;
                    }
                }
                </style>
                <?php
                break;

            default:
                // Default to home page
                ?>
                <div class="hero">
                    <h1>MonoPHP</h1>
                    <p>Simple & Minimalist PHP Framework</p>

                    <?php if (!$is_logged_in): ?>
                        <p>Build fast, secure web applications with minimal code.</p>
                        <a href="<?php echo e($_SESSION['google_auth_url']); ?>" class="btn btn-google">
                            <svg width="16" height="16" viewBox="0 0 24 24">
                                <path fill="white" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                                <path fill="white" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                                <path fill="white" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                                <path fill="white" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                            </svg>
                            Get Started with Google
                        </a>
                    <?php else: ?>
                        <p>Welcome back, <strong><?php echo e($_SESSION['user']['name']); ?></strong>!</p>
                        <a href="/dashboard" class="btn">Go to Dashboard</a>
                    <?php endif; ?>
                </div>
                <?php
                break;
        }
        ?>
    </div>
</body>
</html>
