<?php

// Strict types
declare(strict_types=1);

//------------------------------------------------------------------------------
// <config>
//------------------------------------------------------------------------------
const SITE_APP_VERSION = "1.0.0";
const SITE_ENV_FILE = __DIR__ . "/../.env";
const SITE_DB_FILE = __DIR__ . "/../database/database.sqlite";
const SITE_DOMAIN = "https://monophp.fadli.cloud";
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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:;");
// </security headers>

//------------------------------------------------------------------------------
// <error reporting>
//------------------------------------------------------------------------------
$is_development = 
    $_SERVER["SERVER_NAME"] === "localhost" ||
    $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
    $_SERVER["REMOTE_ADDR"] === "127.0.0.1";

if ($is_development) {
    error_reporting(E_ALL);
    ini_set("display_errors", 1);
    ini_set("display_startup_errors", 1);
} else {
    error_reporting(E_ALL);
    ini_set("display_errors", 0);
    ini_set("display_startup_errors", 0);
    ini_set("log_errors", 1);
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );");
}

// Initialize database on every run.
initialize_database();
// </database>

//------------------------------------------------------------------------------
// <helpers>
//------------------------------------------------------------------------------
// Escapes special characters in a string for safe HTML output.
function e(?string $string): string
{
    return htmlspecialchars((string) $string, ENT_QUOTES, "UTF-8");
}

// Redirects to a URL and exits script execution.
function redirect(string $url): void
{
    header("Location: " . $url);
    exit();
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

// Google OAuth - Configuration
function get_google_config(): array
{
    return [
        'client_id' => getenv('GOOGLE_CLIENT_ID') ?? '',
        'client_secret' => getenv('GOOGLE_CLIENT_SECRET') ?? '',
        'redirect_uri' => getenv('GOOGLE_REDIRECT_URI') ?? '',
        'scope' => 'openid email profile'
    ];
}

// Google OAuth - Generate Google OAuth URL
function get_google_auth_url(): string
{
    $config = get_google_config();
    
    $params = [
        'client_id' => $config['client_id'],
        'redirect_uri' => $config['redirect_uri'],
        'scope' => $config['scope'],
        'response_type' => 'code',
        'access_type' => 'online'
    ];
    
    return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
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
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    }
    
    return null;
}

// Google OAuth - Get user info from Google
function get_google_user_info(string $access_token): ?array
{
    $user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo?access_token=' . $access_token;
    $user_response = file_get_contents($user_info_url);
    
    if ($user_response !== false) {
        return json_decode($user_response, true);
    }
    
    return null;
}

// Google OAuth - Create or update user from Google data
function create_or_update_google_user(array $google_user): ?array
{
    $pdo = get_db_connection();
    
    try {
        // Check if user exists
        $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
        $stmt->execute([$google_user['id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Update existing user
            $stmt = $pdo->prepare('
                UPDATE users
                SET name = ?, email = ?, picture = ?, updated_at = CURRENT_TIMESTAMP
                WHERE google_id = ?
            ');
            $stmt->execute([
                $google_user['name'],
                $google_user['email'],
                $google_user['picture'],
                $google_user['id']
            ]);

            // Get updated user data
            $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
            $stmt->execute([$google_user['id']]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } else {
            // Create new user
            $stmt = $pdo->prepare('
                INSERT INTO users (google_id, name, email, picture)
                VALUES (?, ?, ?, ?)
            ');
            $stmt->execute([
                $google_user['id'],
                $google_user['name'],
                $google_user['email'],
                $google_user['picture']
            ]);

            // Get newly created user
            $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
            $stmt->execute([$google_user['id']]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }
    } catch (PDOException $e) {
        die('Database error: ' . $e->getMessage());
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
// <handle get requests - page routing>
//------------------------------------------------------------------------------
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$path = trim($path, '/');

// Handle Google OAuth callback
if (isset($_GET['code'])) {
    $code = $_GET['code'];

    try {
        // Exchange code for access token
        $token_info = exchange_code_for_token($code);

        if (isset($token_info['access_token'])) {
            // Get user info from Google
            $user_data = get_google_user_info($token_info['access_token']);

            if ($user_data) {
                // Save user to database and store in session
                $db_user = create_or_update_google_user($user_data);
                $_SESSION['user'] = [
                    'id' => $db_user['id'],
                    'google_id' => $db_user['google_id'],
                    'name' => $db_user['name'],
                    'email' => $db_user['email'],
                    'picture' => $db_user['picture'],
                    'created_at' => $db_user['created_at'],
                    'updated_at' => $db_user['updated_at']
                ];

                // Redirect to dashboard
                redirect('/dashboard');
            }
        }
    } catch (Exception $e) {
        $errors[] = "Authentication failed. Please try again.";
    }
}

// Handle logout
if (isset($_GET['logout']) || $path === 'logout') {
    session_destroy();
    redirect('/');
}

// Determine current page
if ($path === 'auth/google/callback') {
    $current_page = 'oauth_callback';
} elseif ($path === 'logout') {
    $current_page = 'logout';
} elseif ($path === '' || $path === 'index.php') {
    $current_page = 'home';
} elseif ($path === 'dashboard') {
    $current_page = 'dashboard';
} else {
    $current_page = 'home';
}

// Check if user is logged in
$is_logged_in = is_logged_in();

// Protect dashboard page
if ($current_page === 'dashboard' && !$is_logged_in) {
    redirect('/');
}

// Google OAuth URL
$google_auth_url = get_google_auth_url();
// </handle get requests - page routing>

//------------------------------------------------------------------------------
// <view>
//------------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $current_page === 'dashboard' ? 'Dashboard' : 'MonoPHP'; ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            text-align: center;
            max-width: 400px;
            width: 90%;
        }

        .logo {
            font-size: 2.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 10px;
        }

        .subtitle {
            color: #666;
            margin-bottom: 40px;
            font-size: 1.1rem;
        }

        .google-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #4285f4;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 50px;
            text-decoration: none;
            font-size: 1rem;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(66, 133, 244, 0.3);
        }

        .google-btn:hover {
            background: #3367d6;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(66, 133, 244, 0.4);
        }

        .google-icon {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            background: white;
            border-radius: 3px;
            padding: 2px;
        }

        .user-profile {
            text-align: center;
        }

        .user-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 20px;
            border: 4px solid #f0f0f0;
        }

        .user-name {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }

        .user-email {
            color: #666;
            margin-bottom: 30px;
        }

        .logout-btn {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 25px;
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .logout-btn:hover {
            background: #c82333;
            transform: translateY(-1px);
        }

        .dashboard-title {
            font-size: 2rem;
            color: #333;
            margin-bottom: 30px;
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!empty($errors)): ?>
            <?php foreach ($errors as $error): ?>
                <div class="error"><?php echo e($error); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>

        <?php if ($current_page === 'dashboard' && $is_logged_in): ?>
            <!-- Dashboard Page -->
            <h1 class="dashboard-title">Dashboard</h1>
            <div class="user-profile">
                <img src="<?php echo e($_SESSION['user']['picture']); ?>" alt="Profile Picture" class="user-avatar">
                <div class="user-name"><?php echo e($_SESSION['user']['name']); ?></div>
                <div class="user-email"><?php echo e($_SESSION['user']['email']); ?></div>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        <?php else: ?>
            <!-- Home Page -->
            <div class="logo">MonoPHP</div>
            <div class="subtitle">Simple & Minimalist PHP Framework</div>

            <?php if (!$is_logged_in): ?>
                <a href="<?php echo e($google_auth_url); ?>" class="google-btn">
                    <svg class="google-icon" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Continue with Google
                </a>
            <?php else: ?>
                <p style="margin-bottom: 20px;">Welcome back, <?php echo e($_SESSION['user']['name']); ?>!</p>
                <a href="/dashboard" style="background: #28a745; color: white; padding: 10px 20px; border-radius: 25px; text-decoration: none; margin-right: 10px;">Go to Dashboard</a>
                <a href="/logout" class="logout-btn">Logout</a>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
<?php
// </view>
?>
