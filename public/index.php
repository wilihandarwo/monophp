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
        :root {
        /* ========== BRAND COLORS (Primary = Deep Gold) ========== */
        --primary: #B88400;                    /* Main CTAs, primary buttons, active nav items */
        --primary-light: #D9A63A;              /* Hover states for primary elements (slightly lighter) */
        --primary-dark: #7A5200;               /* Active/pressed states, focus rings (deeper gold) */
        --primary-transparent: #B884001a;      /* Subtle highlights, selection backgrounds, badges */

        --secondary: #2F2E3A;                  /* Charcoal: headings, body text, secondary buttons, links */
        --secondary-light: #4A4756;            /* Hover for secondary elements */
        --secondary-dark: #1E1D25;             /* Active states / strong text on light backgrounds */
        --secondary-transparent: #2F2E3A1a;    /* Subtle charcoal overlays and borders */

        --accent: #22C55E;                     /* Success states, positive indicators, completion badges */
        --accent-light: #57D987;               /* Success hover states, positive highlights */
        --accent-dark: #15803D;                /* Success active states, confirmed actions */
        --accent-transparent: #22C55E1a;       /* Success backgrounds, positive status indicators */
        /* ========== NEUTRAL COLORS ========== */
        --white: #ffffff;                      /* Pure white backgrounds, text on dark backgrounds */
        --white-transparent: #ffffffe6;        /* IMPROVED: More visible than e5 - overlay backgrounds, modals */
        --black: #000000;                      /* Pure black (rarely used directly) */
        --gray-50: #f9fafb;                    /* Subtle background variations, disabled states */
        --gray-100: #f3f4f6;                   /* Light backgrounds, input backgrounds */
        --gray-200: #e5e7eb;                   /* Borders, dividers, subtle separations */
        --gray-300: #d1d5db;                   /* Disabled borders, placeholder text */
        --gray-400: #9ca3af;                   /* Muted text, secondary icons */
        --gray-500: #6b7280;                   /* Secondary text, less important content */
        --gray-600: #4b5563;                   /* Primary text on light backgrounds */
        --gray-700: #374151;                   /* Dark text, headings */
        --gray-800: #1f2937;                   /* Very dark text, dark mode surfaces */
        --gray-900: #111827;                   /* Primary text, main content */

        /* ========== SEMANTIC COLORS ========== */
        --success: #2da165;                    /* Success messages, checkmarks, completed states */
        --warning: #fadc5b;                    /* Warning messages, caution indicators */
        --error: #ee4f4f;                      /* Error messages, validation errors, destructive actions */
        --info: var(--secondary);              /* Info messages, tips, neutral notifications */

        /* ========== SURFACES ========== */
        --bg-body: var(--white);               /* Main page background */
        --bg-body-transparent: var(--white-transparent); /* Backdrop overlays, modal backgrounds */
        --bg-surface: var(--gray-50);          /* Section backgrounds, page containers */
        --bg-card: var(--white);               /* Card backgrounds, elevated content */
        --bg-muted: var(--gray-100);           /* IMPROVED: Less harsh - sidebar backgrounds, disabled areas */
        --bg-hover: var(--gray-50);            /* ADDED: Hover states for list items, buttons */
        --bg-selected: var(--primary-transparent); /* ADDED: Selected states, active items */

        /* ========== TEXT COLORS ========== */
        --text-primary: var(--gray-900);       /* Main headings, primary content */
        --text-secondary: var(--gray-600);     /* Subheadings, secondary content */
        --text-muted: var(--gray-400);         /* Placeholder text, timestamps, metadata */
        --text-inverse: var(--white);          /* Text on dark backgrounds */
        --text-link: var(--secondary);         /* ADDED: Link colors, interactive text */
        --text-link-hover: var(--primary); /* ADDED: Link hover states */
        --text-link-active: var(--primary);        /* ADDED: Active navbar links, current page */

        /* ========== BORDERS & DIVIDERS ========== */
        --border-light: var(--gray-200);       /* Subtle borders, card edges */
        --border-base: var(--gray-300);        /* IMPROVED: More visible - input borders, standard dividers */
        --border-dark: var(--gray-600);        /* IMPROVED: Better contrast - emphasized borders */
        --border-focus: var(--primary);        /* ADDED: Focus rings, active input borders */

        /* ========== TYPOGRAPHY ========== */
        --font-sans: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, Roboto, sans-serif; /* UI text, buttons, navigation */
        --font-serif: "Crimson Pro", Georgia, serif; /* Editorial content, blog posts, testimonials */
        --font-mono: "JetBrains Mono", Consolas, monospace; /* Code blocks, technical content, data */

        /* Font Sizes */
        --text-xs: 0.75rem;                    /* Small labels, captions, metadata */
        --text-sm: 0.875rem;                   /* Form labels, secondary text */
        --text-base: 1rem;                     /* Body text, paragraphs */
        --text-lg: 1.125rem;                   /* Large body text, lead paragraphs */
        --text-xl: 1.25rem;                    /* Small headings, card titles */
        --text-2xl: 1.5rem;                    /* Section headings, modal titles */
        --text-3xl: 1.875rem;                  /* Page headings, major sections */
        --text-4xl: 2.25rem;                   /* Hero headings, landing page titles */
        --text-5xl: 3rem;                      /* Large hero text, marketing headlines */
        --text-6xl: 3.75rem;                   /* Extra large display text */

        /* Font Weights */
        --font-light: 300;                     /* Light emphasis, subtle text */
        --font-normal: 400;                    /* Regular body text */
        --font-medium: 500;                    /* Slightly emphasized text, navigation */
        --font-semibold: 600;                  /* Buttons, form labels, subheadings */
        --font-bold: 700;                      /* Headings, important emphasis */

        /* Line Heights */
        --leading-tight: 1.1;                 /* Headings, compact text */
        --leading-normal: 1.5;                 /* Body text, readable content */
        --leading-relaxed: 1.75;               /* Long-form content, blog posts */

        /* ========== SPACING ========== */
        --space-xs: 0.5rem;                    /* Tight spacing, icon gaps */
        --space-sm: 0.75rem;                   /* Small padding, compact layouts */
        --space-md: 1rem;                      /* Standard spacing, button padding */
        --space-lg: 1.5rem;                    /* Section spacing, card padding */
        --space-xl: 2rem;                      /* Large gaps, component margins */
        --space-2xl: 3rem;                     /* Section separations */
        --space-3xl: 4rem;                     /* Major layout spacing */
        --space-4xl: 5rem;                     /* Hero sections, large separations */

        /* ========== LAYOUT ========== */
        --container-sm: 640px;                 /* Small screens, mobile-first content */
        --container-md: 768px;                 /* Medium screens, tablet layouts */
        --container-lg: 1024px;                /* Large screens, desktop content */
        --container-xl: 1280px;                /* Extra large screens, wide layouts */
        --container-2xl: 1536px;               /* Ultra wide screens, max content width */

        /* Border Radius */
        --radius-none: 0;                      /* ADDED: Sharp corners, technical interfaces */
        --radius-sm: 0.25rem;                  /* Small elements, badges, tags */
        --radius-md: 0.5rem;                   /* Buttons, form inputs, standard cards */
        --radius-lg: 0.75rem;                  /* Large cards, modals */
        --radius-xl: 1rem;                     /* Hero sections, prominent elements */
        --radius-full: 9999px;                 /* Avatars, pills, circular buttons */

        /* ========== SHADOWS ========== */
        --shadow-sm: 0 1px 2px rgba(44, 69, 97, 0.12); /* IMPROVED: Proper shadow format - subtle elevation */
        --shadow-md: 0 4px 6px rgba(44, 69, 97, 0.2);  /* IMPROVED: Cards, dropdowns */
        --shadow-lg: 0 10px 15px rgba(44, 69, 97, 0.31); /* IMPROVED: Modals, large cards */
        --shadow-xl: 0 20px 25px rgba(44, 69, 97, 0.4); /* ADDED: Maximum elevation */
        --text-shadow: 0 1px 2px rgba(20, 16, 99, 0.15); /* IMPROVED: Text shadows on images */
        --button-shadow: inset 0 2px 2px #fff3, inset 0 -2px 2px #0003, 0 2px 2px #00000040; /* IMPROVED: Button shadow */
        --button-secondary-shadow: inset 0 2px 2px #fff3, inset 0 -2px 2px #0000001a, 0 2px 2px #00000040;

        /* ========== TRANSITIONS ========== */
        --transition-fast: 0.15s ease;         /* Micro-interactions, hover states */
        --transition-base: 0.25s ease;         /* Standard animations, state changes */
        --transition-slow: 0.35s ease;         /* Complex animations, layout changes */
        --transition-bounce: 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55); /* Playful animations */

        /* ========== Z-INDEX ========== */
        --z-base: 1;                           /* ADDED: Base layer reference */
        --z-navbar: 50;                        /* Navigation bars, sticky headers */
        --z-dropdown: 100;                     /* Dropdowns, select menus */
        --z-modal: 200;                        /* Modals, overlays */
        --z-tooltip: 300;                      /* Tooltips, highest priority elements */

        /* ========== COMPONENT SPECIFIC ========== */
        /* Form Elements */
        --input-height: 2.5rem;                /* Standard input height */
        --input-padding: var(--space-sm) var(--space-md); /* Input padding */

        /* Buttons */
        --btn-height: 2.5rem;                  /* Button height consistency */
        --btn-padding: var(--space-sm) var(--space-lg); /* Button padding */

        /* Cards */
        --card-padding: var(--space-lg);       /* Standard card padding */
        }

        body {
            font-family: var(--font-sans);
            margin: 0;
            background-color: var(--bg-body);
            color: var(--text-primary);
            padding-top: var(--space-lg);
        }
        .container {
            max-width: var(--container-2xl);
            margin: var(--space-4xl) auto;
            padding: var(--space-xl);
        }
    </style>
</head>
<body>
    <?php
        if ($current_page == 'home' || 'about' || 'contact') {
            ?>
            <!-- <navbar> -->
                <style>
                    #navbar {
                        position: fixed;
                        top: var(--space-lg);
                        left: 50%;
                        transform: translateX(-50%);
                        z-index: var(--z-navbar);
                        width: calc(100% - 40px);
                        max-width: var(--container-xl);
                        background-color: var(--bg-card);
                        padding: var(--space-xs) var(--space-xs);
                        backdrop-filter: blur(10px);
                        -webkit-backdrop-filter: blur(10px);
                        box-shadow: var(--shadow-sm);
                        border-radius: var(--radius-lg);
                        border: 1px solid var(--border-light);
                        align-items: center;
                        display: flex;
                        justify-content: space-between;
                    }

                    #navbar .navbar-left {
                        display: flex;
                        align-items: center;
                    }
                    #navbar .navbar-left img {
                        height: 32px;
                        width: auto;
                    }

                    #navbar .navbar-center {
                        display: flex; align-items: center; gap: var(--space-xs);
                    }

                    #navbar .menu-item {
                        position: relative; display: flex; align-items: center;
                    }
                    #navbar a {
                        color: var(--text-primary);
                        text-decoration: none;
                        padding: var(--space-sm) var(--space-md);
                        font-weight: var(--font-medium);
                        font-size: var(--text-sm);
                        display: flex;
                        align-items: center;
                        gap: var(--space-xs);
                    }
                    #navbar a:hover {
                        color: var(--text-link-hover);
                    }
                    #navbar a.active {
                        color: var(--text-link-active);
                    }
                    #navbar a.dropdown::after {
                        content: "▼";
                        font-size: var(--text-xs);
                        color: var(--text-primary);
                    }
                    #navbar a.dropdown:hover::after {
                        color: var(--text-link-hover);
                    }
                    #navbar .dropdown-menu {
                        position: absolute;
                        top: 100%;
                        left: 0;
                        min-width: 220px;
                        background: var(--bg-card);
                        border-radius: var(--radius-md);
                        padding: var(--space-sm) 0;
                        box-shadow: var(--shadow-sm);
                        border: 1px solid var(--border-light);
                        opacity: 0;
                        visibility: hidden;
                        transform: translateY(-10px);
                        transition: all var(--transition-base);
                        z-index: var(--z-dropdown);
                    }
                    #navbar .menu-item:hover .dropdown-menu {
                        opacity: 1;
                        visibility: visible;
                        transform: translateY(0);
                    }
                    #navbar .dropdown-menu a {
                        padding: 12px 20px;
                        font-size: var(--text-sm);
                        color: var(--text-secondary);
                        display: flex;
                        align-items: center;
                        gap: var(--space-sm);
                        border-radius: 0;
                    }
                    #navbar .dropdown-menu a:hover {
                        background-color: var(--bg-hover); color: var(--text-link-hover);
                    }
                    #navbar .dropdown-menu a .icon {
                        width: 32px; height: 32px; border-radius: 8px;
                        display: flex; align-items: center; justify-content: center;
                        font-size: 16px; flex-shrink: 0;
                        background-color: var(--primary-transparent);
                    }
                    #navbar .dropdown-item-title {
                        font-weight: var(--font-semibold);
                    }
                    #navbar .dropdown-item-description {
                        font-size: var(--text-sm);
                        color: var(--text-muted);
                    }

                    #navbar .navbar-right {
                        display: flex; align-items: center; gap: var(--space-xs);
                    }
                    #navbar a.button {
                        background: var(--primary);
                        color: var(--white) !important;
                        text-align: center;
                        padding: 12px 24px; border-radius: var(--radius-md);
                        font-weight: var(--font-bold); font-size: 14px;
                        line-height: var(--leading-relaxed);
                        padding: var(--space-xs) var(--space-md);
                        /* box-shadow: 0 4px 14px 0 rgba(79, 124, 255, 0.3); */
                        box-shadow: var(--button-shadow);
                        transition: var(--transition-base);
                        border: none;
                    }
                    #navbar a.button:hover {
                        background: var(--primary-dark);
                        color: var(--white) !important;
                        transform: translateY(-2px);
                        box-shadow: var(--button-shadow);
                    }

                    @media (max-width: 768px) {
                      #navbar {
                        flex-wrap: wrap;
                        align-items: center;
                        gap: var(--space-xs);
                        /* Ensure horizontal margins on mobile */
                        left: 0;
                        right: 0;
                        transform: none;
                        width: auto;
                        margin: 0 20px; /* keeps the floating look on mobile */
                      }
                      #navbar .navbar-left {
                        order: 1;
                      }
                      #navbar .navbar-right {
                        order: 2;
                        margin-left: auto;
                      }
                      #navbar .navbar-center {
                        order: 3;
                        width: 100%;
                        display: flex;
                        justify-content: center;
                        gap: var(--space-xs);
                        margin-top: var(--space-xs);
                      }
                    }

                    @media (max-width: 1024px) {
                      #navbar {
                        left: 0;
                        right: 0;
                        transform: none;
                        width: auto;
                        margin: 0 20px; /* horizontal margins on tablet */
                      }
                    }

                    @media (max-width: 1280px) {
                      #navbar {
                        left: 0;
                        right: 0;
                        transform: none;
                        width: auto;
                        margin: 0 20px; /* horizontal margins on tablet */
                      }
                    }

                    @media (max-width: 1536px) {
                      #navbar {
                        left: 0;
                        right: 0;
                        transform: none;
                        width: auto;
                        margin: 0 20px; /* horizontal margins on tablet */
                      }
                    }
                </style>
                <nav id="navbar">
                    <div class="navbar-left">
                        <a href="/">
                            <img src="/assets/images/logo.png" alt="Aplikasi Emas Pintar">
                        </a>
                    </div>

                    <div class="navbar-center">
                        <div class="menu-item">
                            <a href="/home" class="<?= $current_page === 'home' ? 'active' : ''; ?>">Home</a>
                        </div>
                        <div class="menu-item">
                            <a href="#" class="dropdown">Fitur</a>
                            <div class="dropdown-menu">
                                <a href="/home">
                                    <div class="icon">🔍</div>
                                    <div>
                                        <div class="dropdown-item-title">All Features</div>
                                        <div class="dropdown-item-description">Complete overview</div>
                                    </div>
                                </a>
                                <a href="/about">
                                    <div class="icon">🧩</div>
                                    <div>
                                        <div class="dropdown-item-title">Components</div>
                                        <div class="dropdown-item-description">Reusable building blocks</div>
                                    </div>
                                </a>
                                <a href="#">
                                    <div class="icon">📋</div>
                                    <div>
                                        <div class="dropdown-item-title">Templates</div>
                                        <div class="dropdown-item-description">Ready-made designs</div>
                                    </div>
                                </a>
                                <a href="#">
                                    <div class="icon">🔗</div>
                                    <div>
                                        <div class="dropdown-item-title">Integrations</div>
                                        <div class="dropdown-item-description">Connect your tools</div>
                                    </div>
                                </a>
                            </div>
                        </div>
                        <div class="menu-item">
                            <a href="/">Artikel</a>
                        </div>
                        <div class="menu-item">
                            <a href="/">Kontak</a>
                        </div>
                    </div>

                    <div class="navbar-right">
                        <?php if ($is_logged_in): ?>
                            <a href="/dashboard" class="button">Dashboard</a>
                        <?php else: ?>
                            <?php
                                // Generate OAuth URL only if not already set in session
                                if (!isset($_SESSION['google_auth_url']) || !isset($_SESSION['oauth_state'])) {
                                    $_SESSION['google_auth_url'] = get_google_auth_url();
                                }
                            ?>
                            <a href="<?= e($_SESSION['google_auth_url']); ?>">
                                <img src="/assets/images/google_login.svg" alt="Google Logo" width="auto" height="46">
                            </a>
                        <?php endif; ?>
                    </div>
                </nav>
            <!-- </navbar> -->
            <?php
        } else {
        echo "Dashboard";
        }
    ?>





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
                <!-- <hero section -->
                <style>
                    #hero-section {
                        padding: var(--space-xl) 0 var(--space-xl);
                        background: linear-gradient(135deg, var(--white) 0%, var(--gray-50) 100%);
                        background-image: radial-gradient(circle, var(--bg-body-transparent), var(--bg-body)), url('/assets/images/background-square.svg');
                        background-repeat: repeat;
                        background-size: auto, 20px 20px;
                        background-position: center, 0 0;
                        margin-bottom: var(--space-4xl);
                        width: 100vw;
                        margin-left: calc(-50vw + 50%);
                        position: relative;
                        margin-top: var(--space-sm);
                    }
                    .hero-container {
                        max-width: var(--container-2xl);
                        margin: 0 auto;
                        padding: 0 var(--space-xl);
                        display: flex;
                        align-items: center;
                        gap: var(--space-lg);
                    }
                    .hero-content {
                        flex: 1;
                        text-align: left;
                    }
                    .hero-image {
                        flex: 1;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                    }
                    .hero-image img {
                        max-width: 100%;
                        height: auto;
                        border-radius: 12px;
                        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                    }
                    .hero-badge {
                        display: inline-flex;
                        align-items: center;
                        gap: var(--space-xs);
                        font-size: var(--text-sm);
                        color: var(--text-secondary);
                        font-weight: var(--font-medium);
                        margin-bottom: var(--space-md);
                    }
                    .hero-title {
                        font-family: var(--font-serif);
                        font-size: var(--text-6xl);
                        font-weight: var(--font-bold);
                        line-height: var(--leading-tight);
                        margin: 0 0 var(--space-lg) 0;
                        color: var(--text-primary);
                        border: none;
                        padding: 0;
                    }
                    .hero-title-highlight {
                        color: var(--primary);
                    }
                    .hero-subtitle {
                        font-size: var(--text-xl);
                        line-height: var(--leading-relaxed);
                        color: var(--text-secondary);
                        margin: 0 0 var(--space-2xl) 0;
                        max-width: var(--container-sm);
                    }
                    .hero-cta-buttons {
                        display: flex;
                        gap: var(--space-lg);
                        justify-content: flex-start;
                        margin-bottom: var(--space-2xl);
                    }
                    .hero-cta-primary {
                        background: var(--primary);
                        color: var(--white) !important;
                        text-align: center; align-items: center;
                        padding: 16px 32px; border-radius: var(--radius-md);
                        font-weight: var(--font-bold); font-size: var(--text-base);
                        box-shadow: var(--button-shadow);
                        transition: var(--transition-base);
                        border: none;
                        display: inline-flex;
                        cursor: pointer;
                        text-decoration: none;
                    }
                    .hero-cta-secondary {
                        background: var(--white);
                        color: var(--text-secondary) !important;
                        padding: 16px 32px; border-radius: var(--radius-md);
                        font-weight: var(--font-semibold); font-size: var(--text-base);
                        text-decoration: none;
                        border: 2px solid var(--border-light);
                        transition: var(--transition-base);
                        display: inline-flex;
                        align-items: center;
                        box-shadow: var(--button-secondary-shadow);
                    }
                    .trusted-by-section {
                        text-align: left;
                    }
                    .trusted-by-title {
                        font-size: var(--text-sm);
                        color: var(--text-muted);
                        font-weight: var(--font-medium);
                        letter-spacing: 0.05em;
                        margin-bottom: var(--space-xl);
                        text-transform: uppercase;
                    }
                    .trusted-by-logos {
                        display: flex;
                        align-items: center;
                        justify-content: flex-start;
                        gap: var(--space-2xl);
                        flex-wrap: wrap;
                    }
                    .trusted-by-logo {
                        height: 0.9rem;
                        max-width: 100px;
                        filter: grayscale(1) opacity(0.5);
                        transition: filter 0.2s ease;
                    }
                    .trusted-by-logo:hover {
                        filter: grayscale(0) opacity(1);
                    }

                    @media (max-width: 768px) {
                      .hero-title {
                        font-size: clamp(2rem, 8vw, var(--text-4xl));
                        line-height: var(--leading-tight);
                      }
                      .hero-subtitle {
                        font-size: var(--text-lg);
                        max-width: 100%;
                      }
                      .hero-cta-buttons {
                        flex-direction: column;
                        align-items: stretch;
                      }
                      .hero-cta-primary, .hero-cta-secondary {
                        width: 80%;
                        justify-content: center;
                      }
                    }

                    @media (max-width: 1024px) {
                      #hero-section {
                        padding: var(--space-xl) 0 var(--space-2xl);
                        margin-top: var(--space-3xl);
                      }
                      .hero-container {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: var(--space-xl);
                      }
                      .hero-content {
                        order: 1;
                        text-align: left;
                      }
                      .hero-image {
                        order: 2;
                        width: 100%;
                        margin-top: var(--space-lg);
                        justify-content: flex-start;
                      }
                      .hero-image img {
                        max-width: 90%;
                        height: auto;
                      }
                      .hero-cta-buttons {
                        justify-content: flex-start;
                        gap: var(--space-md);
                      }
                      .trusted-by-logos {
                        justify-content: flex-start;
                        gap: var(--space-lg);
                      }
                    }
                </style>
                <section id="hero-section">
                    <div class="hero-container">
                        <!-- Left Column: Content -->
                        <div class="hero-content">
                            <!-- Badge -->
                            <div class="hero-badge">
                                Your SaaS for Everyone
                            </div>

                            <!-- Main Heading -->
                            <h1 class="hero-title">
                                Tinggalkan <span class="hero-title-highlight">cara manual,</span><br>
                                majukan usaha emas Anda.
                            </h1>

                            <!-- Subtitle -->
                            <p class="hero-subtitle">
                                Dari manajemen pelanggan, stock, harga, hingga pembukuan, <br>semua rapi di satu aplikasi.
                            </p>

                            <!-- CTA Buttons -->
                            <div class="hero-cta-buttons">
                                <a href="/register" class="hero-cta-primary">
                                    Daftar Sekarang
                                </a>
                                <a href="/about" class="hero-cta-secondary">
                                    Lihat Demo
                                </a>
                            </div>

                            <!-- Trusted By Section -->
                            <div class="trusted-by-section">
                                <p class="trusted-by-title">
                                    Trusted by
                                </p>
                                <div class="trusted-by-logos">
                                    <img src="/assets/images/client-logo.svg" alt="Webflow" class="trusted-by-logo">
                                    <img src="/assets/images/client-logo.svg" alt="Slack" class="trusted-by-logo">
                                    <img src="/assets/images/client-logo.svg" alt="Finsweet" class="trusted-by-logo">
                                    <img src="/assets/images/client-logo.svg" alt="Reddit" class="trusted-by-logo">
                                    <img src="/assets/images/client-logo.svg" alt="Amazon" class="trusted-by-logo">
                                    <img src="/assets/images/client-logo.svg" alt="Salesforce" class="trusted-by-logo">
                                </div>
                            </div>
                        </div>

                        <!-- Right Column: Hero Image -->
                        <div class="hero-image">
                            <img src="/assets/images/hero-image.webp" alt="Hero Image">
                        </div>
                    </div>
                </section>
                <!-- </hero section -->

                <?php break; ?>
            <?php case 'about': ?>
                <div class="content">
                    <h2>About MonoPHP</h2>
                    <p>MonoPHP is a minimalist PHP framework inspired by the philosophy of keeping things simple and effective. Built with modern web development practices in mind, it provides just enough structure to build robust applications without the bloat.</p>
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
