<?php
// <initial setting>
    // Strict types
        declare(strict_types=1);
    // Define development mode
        // $is_development = false;
        $is_development =
            $_SERVER["SERVER_NAME"] === "localhost" ||
            $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
            $_SERVER["REMOTE_ADDR"] === "127.0.0.1";
// </initial setting>

// <env>
    // Locate env file
        const SITE_ENV_FILE = __DIR__ . "/../.env";
    // Function to load env
        function load_env() {
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

// <config>
    // Site settings
        const SITE_APP_VERSION = "1.0.0";
        define('SITE_DOMAIN', getenv('SITE_DOMAIN') ?: 'localhost');
    // File location
        const SITE_DB_FILE = __DIR__ . "/../database/monophp.sqlite";
        const SITE_LOG_FILE = __DIR__ . "/../logs/app.log";
// </config>

// <session-management>
    // Initialize session (minimal - only for CSRF)
        ini_set("session.use_only_cookies", "1");
    // Extract domain from SITE_DOMAIN (remove protocol if present)
        $session_domain = SITE_DOMAIN;
        if (strpos($session_domain, 'http://') === 0) {
            $session_domain = substr($session_domain, 7);
        } elseif (strpos($session_domain, 'https://') === 0) {
            $session_domain = substr($session_domain, 8);
        }
    // Set cookie parameters
        session_set_cookie_params([
            "lifetime" => 86400, // 24 hours
            "path" => "/",
            "domain" => $session_domain === 'localhost' ? '' : $session_domain,
            "secure" => isset($_SERVER["HTTPS"]),
            "httponly" => true,
            "samesite" => "Lax",
        ]);
    // Start session
        session_start();
// </session-management>

// <security-headers>
    // csrf
        if (empty($_SESSION["csrf_token"])) {
            $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
        }
        $csrf_token = $_SESSION["csrf_token"];
    // csp
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com https://code.jquery.com https://kit.fontawesome.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://ka-f.fontawesome.com; font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com https://fonts.googleapis.com; img-src 'self' https://*.googleusercontent.com https://i.pravatar.cc data:; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://ka-f.fontawesome.com; frame-src 'self' https://www.youtube.com;");
// </security-headers>

// <error-handling>
    // Setup error log
        $error_log_path = SITE_LOG_FILE;
        if (!file_exists($error_log_path)) {
            touch($error_log_path);
            chmod($error_log_path, 0640);
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
        function get_db_connection(): PDO {
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
        function initialize_database(): void {
            $pdo = get_db_connection();
            $pdo->exec("CREATE TABLE IF NOT EXISTS migrations (
                    version TEXT UNIQUE NOT NULL,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );");
        }
    // Runs pending database migrations to update the schema without data loss.
        function run_migrations(): void {
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
        function e(?string $string): string {
            return htmlspecialchars((string) $string, ENT_QUOTES, "UTF-8");
        }
    // Sanitizes input data to prevent XSS attacks.
        function sanitize_input(array $data): array {
            $sanitized = [];
            foreach ($data as $key => $value) {
                $sanitized[$key] = is_string($value) ? trim(strip_tags($value)) : $value;
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
        function redirect(string $url): void {
            header("Location: $url");
            exit();
        }
// </helpers>

// <view-initialization>
    // Initialization
        $errors = [];
        $messages = [];
        $pdo = get_db_connection();

        // Initialize session messages array if not set
        if (!isset($_SESSION['messages'])) {
            $_SESSION['messages'] = [];
        }
// </view-initialization>

// <post-request-handling>
    // Handle POST requests
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Verify CSRF token on ALL POST requests
            if (!isset($_POST['csrf_token']) || !hash_equals(csrf_token(), $_POST['csrf_token'])) {
                die('CSRF token validation failed. Request aborted.');
            }

            $action = $_POST['action'] ?? '';

            switch ($action) {
                // Add your custom POST handlers here
                // case 'custom_action':
                //     // Handle custom action
                //     break;

                default:
                    $errors[] = 'Invalid action specified.';
                    break;
            }

            // Redirect to prevent form resubmission
            $redirect_url = $_POST['redirect_url'] ?? '/';
            redirect($redirect_url);
        }
// </post-request-handling>

// <routing>
    // File path
        $request_uri = $_SERVER['REQUEST_URI'];
        $path = parse_url($request_uri, PHP_URL_PATH);
        $path = trim($path, '/');

    // Define routes grouped by category
    // [name of url / slug] => ['page' => [title of switch case logic in html], 'title' => 'Page Title'],
        $route_categories = [
            'public' => [
                '' => ['page' => 'home', 'title' => 'Masco - Fitness App'],
                'home' => ['page' => 'home', 'title' => 'Masco - Fitness App'],
                'feature' => ['page' => 'feature', 'title' => 'Features - Masco'],
                'about' => ['page' => 'about', 'title' => 'About - Masco'],
                'courses' => ['page' => 'courses', 'title' => 'Courses - Masco'],
                'testimonial' => ['page' => 'testimonial', 'title' => 'Testimonials - Masco'],
                'contact' => ['page' => 'contact', 'title' => 'Contact - Masco'],
                'login' => ['page' => 'login', 'title' => 'Login - Masco'],
                'signup' => ['page' => 'signup', 'title' => 'Sign Up - Masco'],
                'dashboard' => ['page' => 'dashboard', 'title' => 'Dashboard - Masco'],
            ]
        ];

    // Find current route info
        $current_page = 'home';
        $page_category = 'public';
        $page_title = 'MonoPHP';

        foreach ($route_categories as $category => $routes) {
            if (isset($routes[$path])) {
                $current_page = $routes[$path]['page'];
                $page_category = $category;
                $page_title = $routes[$path]['title'];
                break;
            }
        }
// </routing>
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo e($page_title); ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&family=Playfair+Display:wght@400;500;600;700&display=swap" as="style">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&family=Playfair+Display:wght@400;500;600;700&display=swap">
    <style>
        :root {
            /* ========== SHARED CONSTANTS ========== */
            /* TYPOGRAPHY */
            --font-sans: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            --font-serif: "Playfair Display", Georgia, serif;
            --font-mono: "JetBrains Mono", Consolas, monospace;

            --text-xs: 0.75rem;
            --text-sm: 0.875rem;
            --text-base: 1rem;
            --text-lg: 1.125rem;
            --text-xl: 1.25rem;
            --text-2xl: 1.5rem;
            --text-3xl: 1.875rem;
            --text-4xl: 2.25rem;
            --text-5xl: 3rem;
            --text-6xl: 3.75rem;

            --font-light: 300;
            --font-normal: 400;
            --font-medium: 500;
            --font-semibold: 600;
            --font-bold: 700;

            --leading-tight: 1.1;
            --leading-normal: 1.5;
            --leading-relaxed: 1.75;

            /* SPACING */
            --space-xs: 0.5rem;
            --space-sm: 0.75rem;
            --space-md: 1rem;
            --space-lg: 1.5rem;
            --space-xl: 2rem;
            --space-2xl: 3rem;
            --space-3xl: 4rem;
            --space-4xl: 5rem;

            /* LAYOUT */
            --container-sm: 640px;
            --container-md: 768px;
            --container-lg: 1024px;
            --container-xl: 1280px;
            --container-2xl: 1536px;
            --container-3xl: 1920px;

            /* BORDER RADIUS */
            --radius-none: 0;
            --radius-sm: 0.25rem;
            --radius-md: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;
            --radius-full: 9999px;

            /* TRANSITIONS */
            --transition-fast: 0.15s ease;
            --transition-base: 0.25s ease;
            --transition-slow: 0.35s ease;
            --transition-bounce: 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);

            /* Z-INDEX */
            --z-base: 1;
            --z-navbar: 50;
            --z-dropdown: 100;
            --z-modal: 200;
            --z-tooltip: 300;

            /* COMPONENT DIMENSIONS */
            --input-height: 2.5rem;
            --input-padding: var(--space-sm) var(--space-md);
            --btn-height: 2.5rem;
            --btn-padding: var(--space-sm) var(--space-lg);
            --card-padding: var(--space-lg);
        }

        /* ========== DARK THEME (Default) ========== */
        :root, :root[data-theme="dark"] {
            /* BRAND COLORS */
            --primary: #3B82F6;
            --primary-light: #60A5FA;
            --primary-dark: #1D4ED8;
            --primary-transparent: #3B82F61a;

            --secondary: #111827;
            --secondary-light: #1F2937;
            --secondary-dark: #020617;
            --secondary-transparent: #11182780;

            /* TEXT COLORS */
            --text-primary: #E5E7EB;
            --text-secondary: #9CA3AF;
            --text-muted: #6B7280;
            --text-inverse: #ffffff;
            --text-link: #E5E7EB;
            --text-link-hover: #3B82F6;
            --text-link-active: #3B82F6;

            /* BACKGROUNDS */
            --bg-body: #020617;
            --bg-surface: #111827;
            --bg-card: rgba(255, 255, 255, 0.05);
            --bg-card-border: rgba(255, 255, 255, 0.1);
            --bg-input: rgba(0, 0, 0, 0.2);
            --bg-input-focus: rgba(0, 0, 0, 0.4);
            --bg-muted: #1F2937;

            /* BORDERS */
            --border-light: #374151;
            --border-base: #4B5563;
            --border-dark: #6B7280;
            --border-focus: #3B82F6;

            /* MISC */
            --white: #ffffff;
            --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.5);
            --shadow-xl: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            --button-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);

            /* IMAGES */
            --hero-bg: url('/assets/images/hero-background-dark.webp');
            --logo-filter: brightness(0) invert(1);
        }

        /* ========== LIGHT THEME ========== */
        :root[data-theme="light"] {
            /* BRAND COLORS - Modified for light mode if needed, but keeping primary similar */
            --primary: #2563EB; /* Slightly darker blue for contrast on light */
            --primary-light: #3B82F6;
            --primary-dark: #1E40AF;
            --primary-transparent: #2563EB1a;

            --secondary: #F3F4F6;
            --secondary-light: #ffffff;
            --secondary-dark: #E5E7EB;
            --secondary-transparent: #F3F4F680;

            /* TEXT COLORS */
            --text-primary: #111827;
            --text-secondary: #4B5563;
            --text-muted: #6B7280;
            --text-inverse: #111827; /* Inverse of light is dark */
            --text-link: #111827;
            --text-link-hover: #2563EB;
            --text-link-active: #2563EB;

            /* BACKGROUNDS */
            --bg-body: #FDF8F3; /* Cream background */
            --bg-surface: #ffffff;
            --bg-card: rgba(255, 255, 255, 0.7); /* Glass effect on light */
            --bg-card-border: rgba(255, 255, 255, 0.5);
            --bg-input: rgba(255, 255, 255, 0.6);
            --bg-input-focus: rgba(255, 255, 255, 0.9);
            --bg-muted: #F3F4F6;

            /* BORDERS */
            --border-light: #E5E7EB;
            --border-base: #D1D5DB;
            --border-dark: #9CA3AF;
            --border-focus: #2563EB;

            /* MISC */
            --white: #111827; /* Swapping "white" variable might be confusing, let's keep it literal and use semantic names in usage */
            /* Actually, let's keep --white as white and usage should use --text-inverse or similar */
            --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 8px 32px 0 rgba(31, 38, 135, 0.15);
            --button-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);

            /* IMAGES */
            --hero-bg: url('/assets/images/hero-background-light.webp');
            --logo-filter: none;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: var(--font-sans);
            margin: 0;
            background-color: var(--bg-body);
            color: var(--text-primary);
        }

        .btn {
            background: var(--primary);
            color: var(--secondary) !important;
            text-decoration: none;
            padding: var(--space-md) var(--space-xl);
            border-radius: var(--radius-full);
            font-weight: var(--font-semibold);
            font-size: var(--text-base);
            display: inline-block;
            transition: all var(--transition-base);
            border: 2px solid var(--secondary);
            position: relative;
            box-shadow: 4px 4px 0 0 var(--secondary);
        }
        .btn:hover {
            background: var(--primary-light);
            transform: translate(-2px, -2px);
            box-shadow: 6px 6px 0 0 var(--secondary);
        }
        .btn:active {
            transform: translate(2px, 2px);
            box-shadow: 2px 2px 0 0 var(--secondary);
        }
        .container {
            max-width: var(--container-3xl);
            margin: var(--space-4xl) auto;
            padding: var(--space-xl);
        }
    </style>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <script src="https://kit.fontawesome.com/4bf4b74595.js" crossorigin="anonymous"></script>
</head>
<body>

<!--VIEW: public pages-->
<?php if ($page_category === 'public') { ?>
<!-- <public-container>  -->
    <div class="public-container">
    <!--Navbar-->
        <!--// Navbar Style-->
                <style>
                #navbar {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    z-index: var(--z-navbar);
                    background-color: transparent;
                    padding: var(--space-md) var(--space-xl);
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }

                #navbar .navbar-left {
                    display: flex;
                    align-items: center;
                    gap: var(--space-sm);
                }
                #navbar .navbar-left .logo-icon {
                    width: 28px;
                    height: 28px;
                    background: var(--primary);
                    border-radius: 6px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                #navbar .navbar-left .logo-icon svg {
                    width: 16px;
                    height: 16px;
                    fill: var(--secondary);
                }
                #navbar .navbar-left .logo-text {
                    font-size: var(--text-xl);
                    font-weight: var(--font-bold);
                    color: var(--white);
                    text-decoration: none;
                }

                #navbar .navbar-center {
                    display: flex;
                    align-items: center;
                    gap: var(--space-xl);
                }

                #navbar .navbar-center a {
                    color: var(--white);
                    text-decoration: none;
                    font-weight: var(--font-medium);
                    font-size: var(--text-base);
                    transition: color var(--transition-fast);
                }
                #navbar .navbar-center a:hover {
                    color: var(--primary);
                }
                #navbar .navbar-center a.active {
                    color: var(--primary);
                    font-weight: var(--font-semibold);
                }

                #navbar .navbar-right {
                    display: flex;
                    align-items: center;
                    gap: var(--space-lg);
                }
                .theme-toggle {
                    background: transparent;
                    border: none;
                    cursor: pointer;
                    color: var(--text-inverse);
                    padding: 8px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    transition: all var(--transition-fast);
                }
                .theme-toggle:hover {
                    background-color: var(--secondary-transparent);
                    transform: scale(1.1);
                }
                /* Default (Dark) - Show Sun (to switch to light) */
                .theme-toggle .sun-icon { display: block; }
                .theme-toggle .moon-icon { display: none; }

                /* Light Theme - Show Moon (to switch to dark) */
                :root[data-theme="light"] .theme-toggle .sun-icon { display: none; }
                :root[data-theme="light"] .theme-toggle .moon-icon { display: block; }

                #navbar .navbar-right .login-link {
                    color: var(--white);
                    text-decoration: none;
                    font-weight: var(--font-medium);
                    font-size: var(--text-base);
                    transition: color var(--transition-fast);
                }
                #navbar .navbar-right .login-link:hover {
                    color: var(--text-muted);
                }
                #navbar .navbar-right .signup-btn {
                    background: var(--primary);
                    color: var(--secondary) !important;
                    text-decoration: none;
                    padding: var(--space-sm) var(--space-lg);
                    border-radius: var(--radius-full);
                    font-weight: var(--font-semibold);
                    font-size: var(--text-base);
                    transition: all var(--transition-base);
                    box-shadow: var(--button-shadow);
                }
                #navbar .navbar-right .signup-btn:hover {
                    background: var(--primary-light);
                    transform: translateY(-2px);
                }

                @media (max-width: 768px) {
                    #navbar {
                        padding: var(--space-sm) var(--space-md);
                        flex-wrap: wrap;
                    }
                    #navbar .navbar-left {
                        order: 1;
                    }
                    #navbar .navbar-right {
                        order: 2;
                        margin-left: auto;
                        gap: var(--space-sm);
                    }
                    #navbar .navbar-center {
                        order: 3;
                        width: 100%;
                        justify-content: center;
                        gap: var(--space-md);
                        margin-top: var(--space-sm);
                        flex-wrap: wrap;
                    }
                    #navbar .navbar-center a {
                        font-size: var(--text-sm);
                    }
                    #navbar .navbar-right .login-link {
                        display: none;
                    }
                }
                .logo-container img {
                    max-width: 200px;
                    height: auto;
                    filter: var(--logo-filter);
                }
                </style>
        <!--// Navbar HTML-->
                <nav id="navbar">
                    <div class="navbar-left">
                        <!-- <div class="logo-container">
                            <a href="/">
                                <img src="/assets/images/logo-monophp.png" alt="MonoPHP - Fitness App">
                            </a>
                        </div> -->
                        <div class="logo-icon">
                            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
                                <rect x="2" y="6" width="24" height="16" rx="4" fill="currentColor" fill-opacity="0.07"/>
                                <path d="M10 10l-3 4 3 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M18 10l3 4-3 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <rect x="12.5" y="12.5" width="3" height="3" rx="0.6" fill="currentColor"/>
                            </svg>
                        </div>
                        <a href="/" class="logo-text">MonoPHP</a>
                    </div>

                    <div class="navbar-center">
                        <a href="/home" class="<?= $current_page === 'home' ? 'active' : ''; ?>">Home</a>
                        <a href="/feature" class="<?= $current_page === 'feature' ? 'active' : ''; ?>">Feature</a>
                        <a href="/about" class="<?= $current_page === 'about' ? 'active' : ''; ?>">About</a>
                        <a href="/courses" class="<?= $current_page === 'courses' ? 'active' : ''; ?>">Courses</a>
                        <a href="/testimonial" class="<?= $current_page === 'testimonial' ? 'active' : ''; ?>">Testimonial</a>
                    </div>

                    <div class="navbar-right">
                        <!-- Theme Switcher -->
                        <button id="theme-toggle" class="theme-toggle" aria-label="Toggle theme">
                            <!-- Sun Icon -->
                            <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                            <!-- Moon Icon -->
                            <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                        </button>
                        <a href="/login" class="login-link">Login</a>
                        <a href="/signup" class="btn">Sign up free</a>
                    </div>
                </nav>
    <!--Public Page-->
        <!--Home Page-->
            <?php switch ($current_page) { case 'home': ?>
            <!--Hero section-->
                <!--Hero style-->
                    <style>
                    .hero-section {
                        padding: 140px 0 80px;
                        background: var(--hero-bg) no-repeat center center;
                        background-size: cover;
                        min-height: 100vh;
                        align-items: center;
                        position: relative;
                        overflow: hidden;
                        transition: background-image var(--transition-base);
                    }
                    .hero-container {
                        max-width: var(--container-3xl);
                        margin: 0 auto;
                        padding: 0 var(--space-3xl);
                        display: flex;
                        align-items: center;
                        gap: var(--space-xl);
                        position: relative;
                        z-index: 2;
                    }
                    .hero-content {
                        flex: 1;
                        text-align: left;
                    }
                    .hero-image-wrapper {
                        flex: 1;
                        display: flex;
                        justify-content: flex-end;
                        align-items: center;
                        position: relative;
                    }
                    .hero-title {
                        font-family: var(--font-sans);
                        font-size: clamp(2.5rem, 5vw, 4rem);
                        font-weight: var(--font-bold);
                        line-height: 1.15;
                        margin: 0 0 var(--space-lg) 0;
                        color: var(--text-inverse);
                    }
                    .hero-subtitle {
                        font-size: var(--text-lg);
                        line-height: var(--leading-relaxed);
                        color: var(--text-secondary);
                        margin: 0 0 var(--space-xl) 0;
                        max-width: 500px;
                    }
                    /* Social Proof Section */
                    .social-proof {
                        display: flex;
                        align-items: center;
                        gap: var(--space-xl);
                        margin-bottom: var(--space-xl);
                        flex-wrap: wrap;
                    }
                    .social-proof-item {
                        display: flex;
                        align-items: center;
                        gap: var(--space-sm);
                    }
                    .avatar-stack {
                        display: flex;
                    }
                    .avatar-stack .avatar {
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        border: 3px solid var(--bg-cream);
                        margin-left: -12px;
                        object-fit: cover;
                        background: var(--gray-200);
                    }
                    .avatar-stack .avatar:first-child {
                        margin-left: 0;
                    }
                    .social-proof-text {
                        display: flex;
                        flex-direction: column;
                    }
                    .social-proof-number {
                        font-size: var(--text-xl);
                        font-weight: var(--font-bold);
                        color: var(--text-inverse);
                    }
                    .social-proof-label {
                        font-size: var(--text-sm);
                        color: var(--text-muted);
                    }
                    .social-proof-divider {
                        width: 1px;
                        height: 40px;
                        background: var(--border-light);
                    }
                    .rating-stars {
                        display: flex;
                        gap: 2px;
                        color: var(--primary);
                        font-size: var(--text-sm);
                    }
                    /* CTA Button */
                    .hero-cta {
                        background: var(--primary);
                        color: var(--secondary) !important;
                        text-decoration: none;
                        padding: var(--space-md) var(--space-xl);
                        border-radius: var(--radius-full);
                        font-weight: var(--font-semibold);
                        font-size: var(--text-base);
                        display: inline-block;
                        transition: all var(--transition-base);
                        border: 2px solid var(--secondary);
                        position: relative;
                        box-shadow: 4px 4px 0 0 var(--secondary);
                    }
                    .hero-cta:hover {
                        background: var(--primary-light);
                        transform: translate(-2px, -2px);
                        box-shadow: 6px 6px 0 0 var(--secondary);
                    }
                    .hero-cta:active {
                        transform: translate(2px, 2px);
                        box-shadow: 2px 2px 0 0 var(--secondary);
                    }

                    /* Hero Card */
                    .hero-card {
                        background: var(--bg-card);
                        backdrop-filter: blur(12px);
                        -webkit-backdrop-filter: blur(12px);
                        border: 1px solid var(--bg-card-border);
                        border-radius: var(--radius-lg);
                        padding: var(--space-lg);
                        box-shadow: var(--shadow-xl);
                        width: 100%;
                        max-width: 450px;
                        transition: all var(--transition-base);
                    }
                    .video-wrapper {
                        position: relative;
                        padding-bottom: 56.25%; /* 16:9 */
                        height: 0;
                        overflow: hidden;
                        border-radius: var(--radius-md);
                        margin-bottom: var(--space-lg);
                        background: var(--bg-input);
                        border: 1px solid var(--bg-card-border);
                    }
                    .video-wrapper iframe {
                        position: absolute;
                        top: 0;
                        left: 0;
                        width: 100%;
                        height: 100%;
                    }
                    .login-form-wrapper h3 {
                        margin-top: 0;
                        margin-bottom: var(--space-md);
                        color: var(--text-inverse);
                        font-size: var(--text-xl);
                        text-align: center;
                    }
                    .form-group {
                        margin-bottom: var(--space-md);
                    }
                    .form-input {
                        width: 100%;
                        padding: var(--space-md);
                        background: var(--bg-input);
                        border: 1px solid var(--bg-card-border);
                        color: var(--text-inverse);
                        border-radius: var(--radius-md);
                        font-family: var(--font-sans);
                        font-size: var(--text-base);
                        transition: all var(--transition-fast);
                    }
                    .form-input::placeholder {
                        color: var(--text-muted);
                    }
                    .form-input:focus {
                        outline: none;
                        border-color: var(--primary);
                        background: var(--bg-input-focus);
                        box-shadow: 0 0 0 3px var(--primary-transparent);
                    }
                    .btn-full {
                        width: 100%;
                        text-align: center;
                        cursor: pointer;
                        background: var(--primary);
                        color: var(--secondary);
                        border: none;
                        padding: var(--space-md);
                        border-radius: var(--radius-full);
                        font-weight: var(--font-semibold);
                        font-size: var(--text-base);
                        transition: all var(--transition-base);
                        display: block;
                    }
                    .btn-full:hover {
                        background: var(--primary-light);
                    }

                    @media (max-width: 768px) {
                        .hero-section {
                            padding: 100px 0 60px;
                            min-height: auto;
                        }
                        .hero-title {
                            font-size: clamp(2rem, 8vw, 3rem);
                        }
                        .hero-subtitle {
                            font-size: var(--text-base);
                            max-width: 100%;
                        }
                        .social-proof {
                            flex-direction: column;
                            align-items: flex-start;
                            gap: var(--space-md);
                        }
                        .social-proof-divider {
                            display: none;
                        }
                    }

                    @media (max-width: 1024px) {
                        .hero-container {
                            flex-direction: column;
                            gap: var(--space-2xl);
                        }
                        .hero-content {
                            order: 1;
                        }
                        .hero-image-wrapper {
                            order: 2;
                            width: 100%;
                            justify-content: center;
                        }
                    }
                    </style>
                <!--Hero HTML-->
                    <section class="hero-section">
                        <div class="hero-container">
                            <!-- Left Column: Content -->
                            <div class="hero-content">
                                <!-- Main Heading -->
                                <h1 class="hero-title">
                                    Fitness app for<br>your good health
                                </h1>
                                <!-- Subtitle -->
                                <p class="hero-subtitle">
                                    Snaga is a health & fitness tracker app that helps you set out realistic goals that you can accomplish without many hurdles. Sometimes, we keep bigger goals but end up and workout sessions and exercises to help you keep fit.
                                </p>
                                <!-- Social Proof Section -->
                                <div class="social-proof">
                                    <div class="social-proof-item">
                                        <div class="avatar-stack">
                                            <img src="https://i.pravatar.cc/80?img=1" alt="User" class="avatar">
                                            <img src="https://i.pravatar.cc/80?img=2" alt="User" class="avatar">
                                            <img src="https://i.pravatar.cc/80?img=3" alt="User" class="avatar">
                                        </div>
                                        <div class="social-proof-text">
                                            <span class="social-proof-number">64,739</span>
                                            <span class="social-proof-label">Happy Customers</span>
                                        </div>
                                    </div>
                                    <div class="social-proof-divider"></div>
                                    <div class="social-proof-item">
                                        <div class="social-proof-text">
                                            <span class="social-proof-number">4.8/5</span>
                                            <div class="rating-stars">
                                                <span>&#9733;</span>
                                                <span>&#9733;</span>
                                                <span>&#9733;</span>
                                                <span>&#9733;</span>
                                                <span>&#9733;</span>
                                                <span style="margin-left: 4px; color: var(--text-muted);">Rating</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <!-- CTA Button -->
                                <a href="/signup" class="hero-cta">
                                    Start a 10-day free trial
                                </a>
                            </div>
                            <!-- Right Column: Hero Card -->
                            <div class="hero-image-wrapper">
                                <div class="hero-card">
                                    <div class="video-wrapper">
                                        <iframe src="https://www.youtube.com/embed/7blguIsASaw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
                                    </div>
                                    <div class="login-form-wrapper">
                                        <h3>Login to your account</h3>
                                        <form action="/login" method="POST">
                                            <?= csrf_field() ?>
                                            <div class="form-group">
                                                <input type="email" name="email" placeholder="Email address" required class="form-input">
                                            </div>
                                            <div class="form-group">
                                                <input type="password" name="password" placeholder="Password" required class="form-input">
                                            </div>
                                            <button type="submit" class="btn btn-full">Login</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>
        <!--Feature Page-->
            <?php break; case 'feature': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Features</h2>
                    <p>Discover all the amazing features that make Masco the perfect fitness companion for your health journey.</p>
                </section>
        <!--About Page-->
            <?php break; case 'about': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>About Masco</h2>
                    <p>Masco is a health & fitness tracker app that helps you set out realistic goals that you can accomplish without many hurdles.</p>
                </section>
        <!--Courses Page-->
            <?php break; case 'courses': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Courses</h2>
                    <p>Explore our curated fitness courses designed to help you achieve your health and wellness goals.</p>
                </section>
        <!--Testimonial Page-->
            <?php break; case 'testimonial': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Testimonials</h2>
                    <p>Hear from our 64,739 happy customers about their fitness journey with Masco.</p>
                </section>
        <!--Contact Page-->
            <?php break; case 'contact': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Contact Us</h2>
                    <p>Have questions about Masco? We'd love to hear from you. Send us a message and we'll get back to you as soon as possible.</p>
                </section>
        <!--Login Page-->
            <?php break; case 'login': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Login</h2>
                    <p>Welcome back! Sign in to your Masco account.</p>
                </section>
        <!--Signup Page-->
            <?php break; case 'signup': ?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px;">
                    <h2>Sign Up</h2>
                    <p>Create your free Masco account and start your fitness journey today.</p>
                </section>
        <!--Dashboard Page (No Auth)-->
            <?php break; case 'dashboard': ?>
            <!--Dashboard style-->
                <style>
                .dashboard-content {
                    margin-top: 100px;
                    padding: 2rem;
                    min-height: calc(100vh - 200px);
                }

                .dashboard-header {
                    margin-bottom: 2rem;
                    padding-bottom: 1rem;
                    border-bottom: 1px solid #e9ecef;
                }

                .dashboard-header h2 {
                    margin: 0 0 0.5rem 0;
                    color: #333;
                    font-weight: 600;
                    font-size: 1.75rem;
                }

                .dashboard-header p {
                    margin: 0;
                    color: #6c757d;
                    font-size: 1rem;
                }

                .dashboard-cards {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }

                .dashboard-card {
                    background: white;
                    padding: 2rem;
                    border-radius: 12px;
                    border: 1px solid #e9ecef;
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                }

                .dashboard-card:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }

                .card-header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 1rem;
                }

                .card-icon {
                    width: 40px;
                    height: 40px;
                    background: var(--primary);
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-right: 1rem;
                    font-size: 1.2rem;
                }

                .card-title {
                    margin: 0;
                    color: #333;
                    font-weight: 600;
                    font-size: 1.1rem;
                }

                .card-content {
                    color: #6c757d;
                    line-height: 1.6;
                }
                </style>
            <!--Dashboard HTML-->
                <section class="dashboard-content">
                    <div class="dashboard-header">
                        <h2>Dashboard</h2>
                        <p>Welcome to your application dashboard.</p>
                    </div>

                    <div class="dashboard-cards">
                        <div class="dashboard-card">
                            <div class="card-header">
                                <div class="card-icon">📊</div>
                                <h3 class="card-title">Analytics</h3>
                            </div>
                            <div class="card-content">
                                <p>Track performance metrics and gain insights into your platform.</p>
                            </div>
                        </div>

                        <div class="dashboard-card">
                            <div class="card-header">
                                <div class="card-icon">📋</div>
                                <h3 class="card-title">Reports</h3>
                            </div>
                            <div class="card-content">
                                <p>Generate and view detailed reports for your business.</p>
                            </div>
                        </div>

                        <div class="dashboard-card">
                            <div class="card-header">
                                <div class="card-icon">⚙️</div>
                                <h3 class="card-title">Settings</h3>
                            </div>
                            <div class="card-content">
                                <p>Configure and customize your application settings.</p>
                            </div>
                        </div>

                        <div class="dashboard-card">
                            <div class="card-header">
                                <div class="card-icon">📁</div>
                                <h3 class="card-title">Files</h3>
                            </div>
                            <div class="card-content">
                                <p>Manage your files and documents in one place.</p>
                            </div>
                        </div>
                    </div>
                </section>
        <!--404 Page-->
            <?php break; default:?>
            <!--Top section-->
                <section class="content" style="margin-top: 100px; text-align: center;">
                    <h2>404 - Page Not Found</h2>
                    <p>The page you are looking for does not exist.</p>
                    <a href="/" style="color: var(--primary);">Go back to homepage</a>
                </section>
            <?php } ?>
    <!--Footer-->
        <!--Footer style-->
        <!--Footer HTML-->
    </div>
<!-- </public-container>  -->

<?php } ?>

<script>
    (function() {
        const toggle = document.getElementById('theme-toggle');
        const root = document.documentElement;
        
        // Check local storage or system preference
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        if (savedTheme) {
            root.setAttribute('data-theme', savedTheme);
        } else if (prefersDark) {
            root.setAttribute('data-theme', 'dark');
        } else {
            // Default to dark as per original design if no preference
            root.setAttribute('data-theme', 'dark'); 
        }

        if (toggle) {
            toggle.addEventListener('click', () => {
                const currentTheme = root.getAttribute('data-theme');
                const newTheme = currentTheme === 'light' ? 'dark' : 'light';
                
                root.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);
            });
        }
    })();
</script>

</body>
</html>
<!--<EOF>-->
