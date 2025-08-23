<?php

// Strict types
declare(strict_types=1);

//------------------------------------------------------------------------------
// <config>
//------------------------------------------------------------------------------
const SITE_APP_VERSION = "1.0.0";
const SITE_ENV_FILE = __DIR__ . "/../.env";
const SITE_DB_FILE = __DIR__ . "/../database/database.sqlite";
const SITE_DOMAIN = "monophp.com";
// </config>

//------------------------------------------------------------------------------
// <env>
//------------------------------------------------------------------------------
// Access variables: getenv('VARIABLE_NAME') or $_ENV['VARIABLE_NAME']
function load_env()
{
    if (!file_exists(SITE_ENV_FILE)) {
        die(".env file not found");
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

//------------------------------------------------------------------------------
// <session>
//------------------------------------------------------------------------------
ini_set("session.use_only_cookies", "1");
session_set_cookie_params([
    "lifetime" => 86400, // 24 hours
    "path" => "/",
    "domain" => SITE_DOMAIN,
    "secure" => isset($_SERVER["HTTPS"]), // Only send cookie over HTTPS
    "httponly" => true, // Prevent JavaScript access to the session cookie
    "samesite" => "Lax", // CSRF protection
]);
session_start();
// </session>

//------------------------------------------------------------------------------
// <csrf>
//------------------------------------------------------------------------------
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION["csrf_token"];
// </csrf>

//------------------------------------------------------------------------------
// <security headers>
//------------------------------------------------------------------------------
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com;",);
// </security headers>

//------------------------------------------------------------------------------
// <error reporting>
//------------------------------------------------------------------------------
// $is_development = false;
$is_development = 
    $_SERVER["SERVER_NAME"] === "localhost" ||
    $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
    $_SERVER["REMOTE_ADDR"] === "127.0.0.1";

// Setup error log
$error_log_path = dirname(__DIR__) . "/../error.log";
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
// </error reporting>

//------------------------------------------------------------------------------
// <database>
//------------------------------------------------------------------------------
// Creates and returns a PDO database connection.
function get_db_connection(): PDO
{
    try {
        $pdo = new PDO("sqlite:" . SITE_DB_FILE);
        // Set PDO to throw exceptions on error, making error handling cleaner.
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Use default fetch mode as associative array for convenience.
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        // Enforce foreign key constraints in SQLite
        $pdo->exec("PRAGMA foreign_keys = ON;");
        return $pdo;
    } catch (PDOException $e) {
        // In a real app, you would log this error and show a generic message.
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
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            picture TEXT,
            role TEXT DEFAULT 'user',
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

//------------------------------------------------------------------------------
// <helpers>
//------------------------------------------------------------------------------
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

// Checks if a user is currently logged in. 🚧
function is_logged_in(): bool
{
    return isset($_SESSION["user"]);
}

// Gets the current user's data from the session.
function get_user(): ?array
{
    return $_SESSION["user"] ?? null;
}

// Response Helpers
function json_response(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit();
}

// Google OAuth - Configuration
function get_google_config(): array
{
    return [
        'client_id' => $_ENV['GOOGLE_CLIENT_ID'] ?? '',
        'client_secret' => $_ENV['GOOGLE_CLIENT_SECRET'] ?? '',
        'redirect_uri' => $_ENV['GOOGLE_REDIRECT_URI'] ?? 'http://localhost:8000/auth/google/callback',
        'scope' => 'openid email profile'
    ];
}

// Google OAuth - Generate Google OAuth URL
function get_google_auth_url(): string
{
    $config = get_google_config();
    $state = bin2hex(random_bytes(16));
    $_SESSION['oauth_state'] = $state;
    
    $params = [
        'client_id' => $config['client_id'],
        'redirect_uri' => $config['redirect_uri'],
        'scope' => $config['scope'],
        'response_type' => 'code',
        'state' => $state
    ];
    
    return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
}

// Google OAuth - Exchange authorization code for access token
function exchange_code_for_token(string $code): ?array
{
    $config = get_google_config();
    
    $data = [
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret'],
        'redirect_uri' => $config['redirect_uri'],
        'grant_type' => 'authorization_code',
        'code' => $code
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://oauth2.googleapis.com/token');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    }
    
    return null;
}

// Google OAuth -Get user info from Google
function get_google_user_info(string $access_token): ?array
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.googleapis.com/oauth2/v2/userinfo');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $access_token]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    }
    
    return null;
}

// Google OAuth - Create or update user from Google data
function create_or_update_google_user(array $google_user): ?array
{
    $pdo = get_db_connection();
    
    // Check if user exists
    $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = :google_id OR email = :email');
    $stmt->execute([
        ':google_id' => $google_user['id'],
        ':email' => $google_user['email']
    ]);
    $existing_user = $stmt->fetch();
    
    if ($existing_user) {
        // Update existing user
        $stmt = $pdo->prepare('
            UPDATE users 
            SET google_id = :google_id, email = :email, name = :name, picture = :picture 
            WHERE id = :id
        ');
        $stmt->execute([
            ':google_id' => $google_user['id'],
            ':email' => $google_user['email'],
            ':name' => $google_user['name'],
            ':picture' => $google_user['picture'] ?? null,
            ':id' => $existing_user['id']
        ]);
        
        return [
            'id' => $existing_user['id'],
            'google_id' => $google_user['id'],
            'email' => $google_user['email'],
            'name' => $google_user['name'],
            'picture' => $google_user['picture'] ?? null,
            'role' => $existing_user['role']
        ];
    } else {
        // Create new user
        $stmt = $pdo->prepare('
            INSERT INTO users (google_id, email, name, picture) 
            VALUES (:google_id, :email, :name, :picture)
        ');
        $stmt->execute([
            ':google_id' => $google_user['id'],
            ':email' => $google_user['email'],
            ':name' => $google_user['name'],
            ':picture' => $google_user['picture'] ?? null
        ]);
        
        $user_id = $pdo->lastInsertId();
        
        return [
            'id' => $user_id,
            'google_id' => $google_user['id'],
            'email' => $google_user['email'],
            'name' => $google_user['name'],
            'picture' => $google_user['picture'] ?? null,
            'role' => 'user'
        ];
    }
}

// </helpers>

//------------------------------------------------------------------------------
// <init variables for the view>
//------------------------------------------------------------------------------
$errors = [];
$messages = [];
$user = get_user();
$pdo = get_db_connection();
// </init variables for the view>

//------------------------------------------------------------------------------
// <handle post requests - form submissions>
//------------------------------------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Verify CSRF token on ALL POST requests.
    if (
        !isset($_POST["csrf_token"]) ||
        !hash_equals(csrf_token(), $_POST["csrf_token"])
    ) {
        die("CSRF token validation failed. Request aborted.");
    }

    // Google OAuth is handled via GET requests, no POST actions needed for auth
    $messages[] = "Google OAuth authentication is now active. Use the login button to authenticate.";
}
// </handle post requests - form submissions>

//------------------------------------------------------------------------------
// <handle get requests - page routing>
//------------------------------------------------------------------------------
$request_path = trim(parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH), "/");
$page = $request_path ?: "home";

// Initialize view data array
$view_data = [];

// Handle Google OAuth callback
if ($page === "auth/google/callback") {
    $code = $_GET['code'] ?? null;
    $state = $_GET['state'] ?? null;
    
    if (!$code || !$state || !isset($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
        $errors[] = "Invalid OAuth callback. Please try again.";
        redirect("/login");
    }
    
    unset($_SESSION['oauth_state']);
    
    try {
        // Exchange code for token
        $token_data = exchange_code_for_token($code);
        if (!$token_data || !isset($token_data['access_token'])) {
            $errors[] = "Failed to obtain access token from Google.";
            redirect("/login");
        }
        
        // Get user info from Google
        $google_user = get_google_user_info($token_data['access_token']);
        if (!$google_user) {
            $errors[] = "Failed to get user information from Google.";
            redirect("/login");
        }
        
        // Create or update user in database
        $user = create_or_update_google_user($google_user);
        if (!$user) {
            $errors[] = "Failed to create or update user account.";
            redirect("/login");
        }
        
        // Log the user in
        session_regenerate_id(true);
        $_SESSION["user"] = [
            "id" => $user["id"],
            "email" => $user["email"],
            "name" => $user["name"],
            "picture" => $user["picture"],
            "role" => $user["role"] ?? "user",
        ];
        
        redirect("/dashboard");
    } catch (Exception $e) {
        $errors[] = "Authentication failed. Please try again.";
        redirect("/login");
    }
}

// Handle special actions
if ($page === "logout") {
    session_unset();
    session_destroy();
    redirect("/login");
}

// Protect authenticated routes
$auth_pages = ["dashboard"];
if (in_array($page, $auth_pages) && !is_logged_in()) {
    redirect("/login");
}
// Redirect logged-in users from login to dashboard
if ($page === "login" && is_logged_in()) {
    redirect("/dashboard");
}
// </handle get requests - page routing>

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e(ucfirst($page)) ?> - Belajar</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        .navbar {
            background: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 1rem 0;
        }
        .nav-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav-brand {
            font-size: 1.5rem;
            font-weight: bold;
            color: #4285f4;
            text-decoration: none;
        }
        .nav-links {
            display: flex;
            list-style: none;
            gap: 2rem;
        }
        .nav-links a {
            text-decoration: none;
            color: #333;
            font-weight: 500;
            transition: color 0.3s;
        }
        .nav-links a:hover, .nav-links a.active {
            color: #4285f4;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
        }
        .main-content {
            padding: 2rem 0;
            min-height: calc(100vh - 200px);
        }
        .card {
            background: #fff;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        .google-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #4285f4;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            transition: background-color 0.3s;
        }
        .google-btn:hover {
            background: #3367d6;
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #4285f4;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .btn:hover {
            background: #3367d6;
        }
        .btn-secondary {
            background: #6c757d;
        }
        .btn-secondary:hover {
            background: #5a6268;
        }
        .alert {
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 2rem 0;
            margin-top: auto;
        }
        @media (max-width: 768px) {
            .nav-content {
                flex-direction: column;
                gap: 1rem;
            }
            .nav-links {
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <div class="container">
            <div class="nav-content">
                <a href="/" class="nav-brand">Belajar</a>
                
                <ul class="nav-links">
                    <li><a href="/" class="<?= $page === 'home' ? 'active' : '' ?>">Home</a></li>
                    <li><a href="/about" class="<?= $page === 'about' ? 'active' : '' ?>">About</a></li>
                    <?php if (is_logged_in()): ?>
                        <li><a href="/dashboard" class="<?= $page === 'dashboard' ? 'active' : '' ?>">Dashboard</a></li>
                    <?php endif; ?>
                </ul>
                
                <div class="user-info">
                    <?php if (is_logged_in()): ?>
                        <?php if (!empty($_SESSION['user']['picture'])): ?>
                            <img src="<?= e($_SESSION['user']['picture']) ?>" alt="Profile" class="user-avatar">
                        <?php endif; ?>
                        <span>Hello, <?= e($_SESSION['user']['name'] ?? $_SESSION['user']['email']) ?></span>
                        <a href="/logout" class="btn btn-secondary">Logout</a>
                    <?php else: ?>
                        <a href="/login" class="btn">Login</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <div class="container">
            <!-- Display Messages -->
            <?php if (!empty($messages)): ?>
                <?php foreach ($messages as $message): ?>
                    <div class="alert alert-success"><?= e($message) ?></div>
                <?php endforeach; ?>
            <?php endif; ?>
            
            <!-- Display Errors -->
            <?php if (!empty($errors)): ?>
                <?php foreach ($errors as $error): ?>
                    <div class="alert alert-error"><?= e($error) ?></div>
                <?php endforeach; ?>
            <?php endif; ?>

            <!-- Page Content -->
            <?php switch ($page):
                case 'home': ?>
                    <div class="card">
                        <h1>Welcome to Belajar</h1>
                        <p>A modern web application with Google OAuth authentication.</p>
                        <?php if (!is_logged_in()): ?>
                            <p>Please <a href="/login">login with Google</a> to access all features.</p>
                        <?php else: ?>
                            <p>Welcome back, <?= e($_SESSION['user']['name'] ?? $_SESSION['user']['email']) ?>!</p>
                            <a href="/dashboard" class="btn">Go to Dashboard</a>
                        <?php endif; ?>
                    </div>
                <?php break;
                
                case 'about': ?>
                    <div class="card">
                        <h1>About Belajar</h1>
                        <p>This is a PHP application demonstrating:</p>
                        <ul style="margin: 1rem 0; padding-left: 2rem;">
                            <li>Google OAuth 2.0 authentication</li>
                            <li>Session management</li>
                            <li>CSRF protection</li>
                            <li>Modern responsive design</li>
                            <li>SQLite database integration</li>
                        </ul>
                        <p>Built with vanilla PHP and modern web standards.</p>
                    </div>
                <?php break;
                // <login>
                case 'login': ?>
                    <div class="card" style="max-width: 400px; margin: 0 auto;">
                        <h1>Login</h1>
                        <p style="margin-bottom: 2rem;">Sign in with your Google account to continue.</p>
                        <a href="<?= e(get_google_auth_url()) ?>" class="google-btn">
                            <svg width="18" height="18" viewBox="0 0 24 24">
                                <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                                <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                                <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                                <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                            </svg>
                            Sign in with Google
                        </a>
                    </div>
                <?php break;
                // </login>
                case 'dashboard': ?>
                    <div class="card">
                        <h1>Dashboard</h1>
                        <p>Welcome to your dashboard, <?= e($_SESSION['user']['name'] ?? $_SESSION['user']['email']) ?>!</p>
                        
                        <div style="margin-top: 2rem;">
                            <h3>Your Profile Information:</h3>
                            <ul style="margin: 1rem 0; padding-left: 2rem;">
                                <li><strong>Name:</strong> <?= e($_SESSION['user']['name'] ?? 'N/A') ?></li>
                                <li><strong>Email:</strong> <?= e($_SESSION['user']['email']) ?></li>
                                <li><strong>Role:</strong> <?= e($_SESSION['user']['role']) ?></li>
                                <li><strong>Google ID:</strong> <?= e($_SESSION['user']['id']) ?></li>
                            </ul>
                        </div>
                    </div>
                <?php break;
                
                default: ?>
                    <div class="card">
                        <h1>404 - Page Not Found</h1>
                        <p>The page you're looking for doesn't exist.</p>
                        <a href="/" class="btn">Go Home</a>
                    </div>
                <?php break;
            endswitch; ?>
        </div>
    </main>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 Belajar. Built with PHP and Google OAuth.</p>
        </div>
    </footer>
</body>
</html>