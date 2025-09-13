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
    // Site settings
        const SITE_APP_VERSION = "1.0.0";
        define('SITE_DOMAIN', getenv('SITE_DOMAIN') ?: 'localhost');
    // File location
        const SITE_DB_FILE = __DIR__ . "/../database/monophp.sqlite";
        const SITE_LOG_FILE = __DIR__ . "/../logs/app.log";
// </config>

// <session-management>
    // Initialize session
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
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com https://code.jquery.com https://kit.fontawesome.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://ka-f.fontawesome.com; font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com https://fonts.googleapis.com;; img-src 'self' https://*.googleusercontent.com data:; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://ka-f.fontawesome.com;");
// </security-headers>

// <error-handling>
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
            $pdo->exec("CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    google_id VARCHAR(255) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    picture TEXT,
                    role VARCHAR(255) DEFAULT 'user',
                    is_paid INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );");
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
                '2025_01_14_100000_create_businesses_table' => "CREATE TABLE IF NOT EXISTS businesses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    address TEXT,
                    phone VARCHAR(50),
                    email VARCHAR(255),
                    website VARCHAR(255),
                    logo_url TEXT,
                    status VARCHAR(50) DEFAULT 'active',
                    is_current INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );",
                '2025_05_01_100000_add_is_current_to_businesses' => "ALTER TABLE businesses ADD COLUMN is_current INTEGER DEFAULT 0;",
                '2025_06_01_100000_add_is_paid_to_users' => "ALTER TABLE users ADD COLUMN is_paid INTEGER DEFAULT 0;"
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

// <authentication>
    // Clear stale OAuth sessions and data
        function clear_oauth_session(): void {
            $keys_to_clear = ['oauth_state', 'oauth_timestamp', 'google_auth_error', 'google_auth_url'];
            foreach ($keys_to_clear as $key) {
                unset($_SESSION[$key]);
            }
        }
    // Validate user session
        function is_valid_session(): bool {
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
        function init_oauth_session(): void {
            // Clear any existing OAuth data
            clear_oauth_session();

            // Clear any error messages
            unset($_SESSION['error']);
        }
    // Checks if a user is currently logged in.
        function is_logged_in(): bool {
            return isset($_SESSION["user"]);
        }
    // Gets the current user's data from the session.
        function get_user(): ?array {
            return $_SESSION["user"] ?? null;
        }
        
    // Refreshes the current user's data from the database
        function refresh_user_data(): bool {
            if (!isset($_SESSION["user"]) || !isset($_SESSION["user"]["id"])) {
                return false;
            }
            
            $pdo = get_db_connection();
            $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
            $stmt->execute([$_SESSION["user"]["id"]]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                // Update session with fresh data from database
                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'google_id' => $user['google_id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'picture' => $user['picture'],
                    'role' => $user['role'] ?? 'user',
                    'is_paid' => $user['is_paid'] ?? 0,
                    'created_at' => $user['created_at'],
                    'updated_at' => $user['updated_at']
                ];
                return true;
            }
            
            return false;
        }
        
    // Checks if the current user is a paid user
        function is_paid_user(): bool {
            $user = get_user();
            return ($user && isset($user['is_paid']) && $user['is_paid'] == 1);
        }
// </authentication>

// <business-management>
    // Create a new business for the current user
        function create_business(array $data): ?int {
            $pdo = get_db_connection();
            $user = get_user();

            if (!$user) {
                return null;
            }

            try {
                $stmt = $pdo->prepare("
                    INSERT INTO businesses (user_id, name, description, address, phone, email, website, logo_url)
                    VALUES (:user_id, :name, :description, :address, :phone, :email, :website, :logo_url)
                ");

                $stmt->execute([
                    ':user_id' => $user['id'],
                    ':name' => $data['name'],
                    ':description' => $data['description'] ?? null,
                    ':address' => $data['address'] ?? null,
                    ':phone' => $data['phone'] ?? null,
                    ':email' => $data['email'] ?? null,
                    ':website' => $data['website'] ?? null,
                    ':logo_url' => $data['logo_url'] ?? null
                ]);

                return (int) $pdo->lastInsertId();
            } catch (PDOException $e) {
                error_log("Failed to create business: " . $e->getMessage());
                return null;
            }
        }
    // Get all businesses for the current user
        function get_user_businesses(): array {
            $pdo = get_db_connection();
            $user = get_user();

            if (!$user) {
                return [];
            }

            try {
                $stmt = $pdo->prepare("
                    SELECT * FROM businesses
                    WHERE user_id = :user_id AND status = 'active'
                    ORDER BY created_at DESC
                ");

                $stmt->execute([':user_id' => $user['id']]);
                return $stmt->fetchAll();
            } catch (PDOException $e) {
                error_log("Failed to get businesses: " . $e->getMessage());
                return [];
            }
        }
    // Get a specific business by ID (only if owned by current user)
        function get_business_by_id(int $business_id): ?array {
            $pdo = get_db_connection();
            $user = get_user();

            if (!$user) {
                return null;
            }

            try {
                $stmt = $pdo->prepare("
                    SELECT * FROM businesses
                    WHERE id = :id AND user_id = :user_id AND status = 'active'
                ");

                $stmt->execute([
                    ':id' => $business_id,
                    ':user_id' => $user['id']
                ]);

                return $stmt->fetch() ?: null;
            } catch (PDOException $e) {
                error_log("Failed to get business: " . $e->getMessage());
                return null;
            }
        }
    // Update a business
        function update_business(int $business_id, array $data): bool {
            $pdo = get_db_connection();
            $user = get_user();

            if (!$user) {
                return false;
            }

            try {
                $stmt = $pdo->prepare("
                    UPDATE businesses
                    SET name = :name, description = :description, address = :address,
                        phone = :phone, email = :email, website = :website,
                        logo_url = :logo_url, updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id AND user_id = :user_id
                ");

                return $stmt->execute([
                    ':id' => $business_id,
                    ':user_id' => $user['id'],
                    ':name' => $data['name'],
                    ':description' => $data['description'] ?? null,
                    ':address' => $data['address'] ?? null,
                    ':phone' => $data['phone'] ?? null,
                    ':email' => $data['email'] ?? null,
                    ':website' => $data['website'] ?? null,
                    ':logo_url' => $data['logo_url'] ?? null
                ]);
            } catch (PDOException $e) {
                error_log("Failed to update business: " . $e->getMessage());
                return false;
            }
        }
    // Delete a business (soft delete by setting status to 'deleted')
        function delete_business(int $business_id): bool {
            $pdo = get_db_connection();
            $user = get_user();

            if (!$user) {
                return false;
            }

            try {
                $stmt = $pdo->prepare("
                    UPDATE businesses
                    SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id AND user_id = :user_id
                ");

                return $stmt->execute([
                    ':id' => $business_id,
                    ':user_id' => $user['id']
                ]);
            } catch (PDOException $e) {
                error_log("Failed to delete business: " . $e->getMessage());
                return false;
            }
        }
    // Set current business in database
        function set_current_business(int $business_id): bool {
            $business = get_business_by_id($business_id);
            $user = get_user();
            
            if (!$business || !$user) {
                return false;
            }
            
            $pdo = get_db_connection();
            
            try {
                // Begin transaction
                $pdo->beginTransaction();
                
                // First, reset all businesses for this user
                $stmt = $pdo->prepare("UPDATE businesses SET is_current = 0 WHERE user_id = :user_id");
                $stmt->execute([':user_id' => $user['id']]);
                
                // Then set the selected business as current
                $stmt = $pdo->prepare("UPDATE businesses SET is_current = 1 WHERE id = :id AND user_id = :user_id");
                $success = $stmt->execute([
                    ':id' => $business_id,
                    ':user_id' => $user['id']
                ]);
                
                // Also store in session for backward compatibility during transition
                $_SESSION['current_business'] = $business;
                
                // Commit transaction
                $pdo->commit();
                
                return $success;
            } catch (PDOException $e) {
                // Rollback transaction on error
                $pdo->rollBack();
                error_log("Failed to set current business: " . $e->getMessage());
                return false;
            }
        }
    // Get current business from database
        function get_current_business(): ?array {
            $user = get_user();
            
            if (!$user) {
                return null;
            }
            
            $pdo = get_db_connection();
            
            try {
                $stmt = $pdo->prepare("
                    SELECT * FROM businesses
                    WHERE user_id = :user_id AND is_current = 1 AND status = 'active'
                    LIMIT 1
                ");
                
                $stmt->execute([':user_id' => $user['id']]);
                $business = $stmt->fetch();
                
                return $business ?: null;
            } catch (PDOException $e) {
                error_log("Failed to get current business: " . $e->getMessage());
                // Fallback to session for backward compatibility during transition
                return $_SESSION['current_business'] ?? null;
            }
        }
    // Clear current business from database
        function clear_current_business(): bool {
            $user = get_user();
            
            if (!$user) {
                return false;
            }
            
            $pdo = get_db_connection();
            
            try {
                $stmt = $pdo->prepare("UPDATE businesses SET is_current = 0 WHERE user_id = :user_id");
                $success = $stmt->execute([':user_id' => $user['id']]);
                
                // Also clear from session for backward compatibility
                unset($_SESSION['current_business']);
                
                return $success;
            } catch (PDOException $e) {
                error_log("Failed to clear current business: " . $e->getMessage());
                return false;
            }
        }
// </business-management>

// <google-oauth>
    // Google OAuth - Configuration
        function get_google_config(): array {
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
        function get_google_auth_url(): string {
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
        function exchange_code_for_token(string $code): ?array {
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
        function get_google_user_info(string $access_token): ?array {
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
        function create_or_update_google_user(array $google_user): ?array {
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
                        'is_paid' => $user['is_paid'] ?? 0,
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
                        'is_paid' => 0,
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
    // Initialization
        $errors = [];
        $messages = [];
        $user = get_user();
        $pdo = get_db_connection();
        
        // Initialize session messages array if not set
        if (!isset($_SESSION['messages'])) {
            $_SESSION['messages'] = [];
        }
// </view-initialization>

// <post-request-handling>
    // Handle POST requests for business operations
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Verify CSRF token on ALL POST requests
            if (!isset($_POST['csrf_token']) || !hash_equals(csrf_token(), $_POST['csrf_token'])) {
                die('CSRF token validation failed. Request aborted.');
            }

            // Ensure user is logged in for business operations
            if (!is_logged_in()) {
                $errors[] = 'You must be logged in to perform this action.';
            } else {
                $action = $_POST['action'] ?? '';

                switch ($action) {
                    case 'create_business':
                        $business_data = [
                            'name' => trim($_POST['name'] ?? ''),
                            'description' => trim($_POST['description'] ?? ''),
                            'address' => trim($_POST['address'] ?? ''),
                            'phone' => trim($_POST['phone'] ?? ''),
                            'email' => trim($_POST['email'] ?? ''),
                            'website' => trim($_POST['website'] ?? ''),
                            'logo_url' => trim($_POST['logo_url'] ?? '')
                        ];

                        // Validate required fields
                        if (empty($business_data['name'])) {
                            $errors[] = 'Business name is required.';
                        } elseif (strlen($business_data['name']) > 255) {
                            $errors[] = 'Business name must be less than 255 characters.';
                        } else {
                            $business_id = create_business($business_data);
                            if ($business_id) {
                                $messages[] = 'Business created successfully!';
                                // Set as current business if it's the first one
                                $user_businesses = get_user_businesses();
                                if (count($user_businesses) === 1) {
                                    set_current_business($business_id);
                                }
                            } else {
                                $errors[] = 'Failed to create business. Please try again.';
                            }
                        }
                        break;

                    case 'update_business':
                        $business_id = (int) ($_POST['business_id'] ?? 0);
                        $business_data = [
                            'name' => trim($_POST['name'] ?? ''),
                            'description' => trim($_POST['description'] ?? ''),
                            'address' => trim($_POST['address'] ?? ''),
                            'phone' => trim($_POST['phone'] ?? ''),
                            'email' => trim($_POST['email'] ?? ''),
                            'website' => trim($_POST['website'] ?? ''),
                            'logo_url' => trim($_POST['logo_url'] ?? '')
                        ];

                        // Validate required fields
                        if ($business_id <= 0) {
                            $errors[] = 'Invalid business ID.';
                        } elseif (empty($business_data['name'])) {
                            $errors[] = 'Business name is required.';
                        } elseif (strlen($business_data['name']) > 255) {
                            $errors[] = 'Business name must be less than 255 characters.';
                        } else {
                            // Check if business exists and belongs to user
                            $existing_business = get_business_by_id($business_id);
                            if (!$existing_business) {
                                $errors[] = 'Business not found or access denied.';
                            } else {
                                $success = update_business($business_id, $business_data);
                                if ($success) {
                                    $messages[] = 'Business updated successfully!';
                                    // Update current business in session if it's the active one
                                    $current_business = get_current_business();
                                    if ($current_business && $current_business['id'] == $business_id) {
                                        set_current_business($business_id);
                                    }
                                } else {
                                    $errors[] = 'Failed to update business. Please try again.';
                                }
                            }
                        }
                        break;

                    case 'delete_business':
                        $business_id = (int) ($_POST['business_id'] ?? 0);

                        if ($business_id <= 0) {
                            $errors[] = 'Invalid business ID.';
                        } else {
                            // Check if business exists and belongs to user
                            $existing_business = get_business_by_id($business_id);
                            if (!$existing_business) {
                                $errors[] = 'Business not found or access denied.';
                            } else {
                                $success = delete_business($business_id);
                                if ($success) {
                                    $messages[] = 'Business deleted successfully!';
                                    // Clear current business if it was the deleted one
                                    $current_business = get_current_business();
                                    if ($current_business && $current_business['id'] == $business_id) {
                                        clear_current_business();
                                    }
                                } else {
                                    $errors[] = 'Failed to delete business. Please try again.';
                                }
                            }
                        }
                        break;

                    case 'set_current_business':
                        $business_id = (int) ($_POST['business_id'] ?? 0);

                        if ($business_id <= 0) {
                            $errors[] = 'Invalid business ID.';
                        } else {
                            $success = set_current_business($business_id);
                            if ($success) {
                                $messages[] = 'Business switched successfully!';
                            } else {
                                $errors[] = 'Failed to switch business. Business not found or access denied.';
                            }
                        }
                        break;

                    default:
                        $errors[] = 'Invalid action specified.';
                        break;
                }
            }

            // Redirect to prevent form resubmission
            $redirect_url = $_POST['redirect_url'] ?? '/business';
            redirect($redirect_url);
        }
// </post-request-handling>

// <oauth-flow>
    // File path
        $request_uri = $_SERVER['REQUEST_URI'];
        $path = parse_url($request_uri, PHP_URL_PATH);
        $path = trim($path, '/');
    // Validate existing session
        if (isset($_SESSION['user']) && !is_valid_session()) {
            // Invalid session, clear it
            $_SESSION = [];
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
                                    'is_paid' => $db_user['is_paid'] ?? 0,
                                    'created_at' => $db_user['created_at'],
                                    'updated_at' => $db_user['updated_at']
                                ];
                                $_SESSION['login_time'] = time();
                                $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                                
                                // No need to restore from cookie as current business is stored in database
                                // The get_current_business() function will automatically fetch from database

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
            // No need to save business ID to cookie as it's now stored in the database
            
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
            $expire_time = time() - 3600; // Set expiration to the past
            
            // Clear potential OAuth cookies
            setcookie('oauth_state', '', $expire_time, '/', '', isset($_SERVER['HTTPS']), true);
            setcookie('google_auth', '', $expire_time, '/', '', isset($_SERVER['HTTPS']), true);
            
            // Destroy session
            session_destroy();

            // Redirect with cache busting
            header('Location: /?t=' . time());
            exit;
        }
// </oauth-flow>

// <routing>
    // Define routes grouped by category
    // [name of url / slug] => ['page' => [title of switch case logic in html], 'title' => 'Dashboard - MonoPHP', 'paid_only' => true/false],
    // 'dashboard' => ['page' => 'dashboard', 'title' => 'Dashboard - MonoPHP', 'paid_only' => false],
        $route_categories = [
            'public' => [
                '' => ['page' => 'home', 'title' => 'MonoPHP', 'paid_only' => false],
                'home' => ['page' => 'home', 'title' => 'MonoPHP', 'paid_only' => false],
                'about' => ['page' => 'about', 'title' => 'About - MonoPHP', 'paid_only' => false],
                'contact' => ['page' => 'contact', 'title' => 'Contact - MonoPHP', 'paid_only' => false]
            ],
            'dashboard' => [
                'dashboard' => ['page' => 'dashboard', 'title' => 'Dashboard - MonoPHP', 'paid_only' => false],
                'business' => ['page' => 'business', 'title' => 'Dashboard - MonoPHP', 'paid_only' => true],
                'user-management/teams' => ['page' => 'teams', 'title' => 'Admin dan Karyawan - MonoPHP', 'paid_only' => true],
                'user-management/customers' => ['page' => 'customers', 'title' => 'Dashboard - MonoPHP', 'paid_only' => true],
                'settings' => ['page' => 'settings', 'title' => 'Settings - MonoPHP', 'paid_only' => true]
            ],
            'other' => [
                'auth/google/callback' => ['page' => 'oauth_callback', 'title' => 'MonoPHP', 'paid_only' => false],
                'logout' => ['page' => 'logout', 'title' => 'MonoPHP', 'paid_only' => false]
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
    // Check if user is logged in
        $is_logged_in = is_logged_in();
        
    // Refresh user data from database if logged in
        if ($is_logged_in) {
            refresh_user_data();
        }
        
    // Protect dashboard pages
        if ($page_category === 'dashboard' && !$is_logged_in) {
            redirect('/');
        }
        
    // Protect paid-only features
        if (isset($route_categories[$page_category][$path]['paid_only']) && 
            $route_categories[$page_category][$path]['paid_only'] === true && 
            !is_paid_user()) {
            // Set a message to inform the user why they were redirected
            $_SESSION['messages'][] = 'This feature is only available for paid users. Please upgrade your account to access it.';
            redirect('/dashboard');
        }
    // Set user data for dashboard pages
        $user = ($page_category === 'dashboard' && $is_logged_in) ? $_SESSION['user'] : null;
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
    <link rel="preload" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&display=swap" as="style">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&display=swap">
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
        --font-sans: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
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
            /* padding-top: var(--space-lg); */
        }
        .container {
            max-width: var(--container-2xl);
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
    <div class="public-container" style="max-width: var(--container-2xl); margin: var(--space-4xl) auto; padding: var(--space-xl);">
    <!--Navbar-->
        <!--// Navbar Style-->
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
        <!--// Navbar HTML-->
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
                            <a href="/about" class="<?= $current_page === 'about' ? 'active' : ''; ?>">About</a>
                        </div>
                        <div class="menu-item">
                            <a href="/contact" class="<?= $current_page === 'contact' ? 'active' : ''; ?>">Contact</a>
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
    <!--Public Page-->
        <!--Home Page-->
            <?php switch ($current_page) { case 'home': ?>
            <!--Hero section-->
                <!--Hero style-->
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
                <!--Hero HTML-->
                    <section class="hero-container">
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
                    </section>
        <!--About Page-->
            <?php break; case 'about': ?>
            <!--Top section-->
                <section class="content">
                    <h2>About MonoPHP</h2>
                    <p>MonoPHP is a minimalist PHP framework inspired by the philosophy of keeping things simple and effective. Built with modern web development practices in mind, it provides just enough structure to build robust applications without the bloat.</p>
                </section>
        <!--Contact Page-->
            <?php break; case 'contact': ?>
            <!--Top section-->
                <section class="content">
                    <h2>Contact Us</h2>
                    <p>Have questions about MonoPHP? We'd love to hear from you. Send us a message and we'll get back to you as soon as possible.</p>
                </section>
        <!--404 Page-->
            <?php break; default:?>
            <!--Top section-->
                404
            <?php } ?>
    <!--Footer-->
        <!--Footer style-->
        <!--Footer HTML-->
    </div>
<!-- </public-container>  -->

<!--VIEW: dashboard pages-->
<?php } elseif($page_category === 'dashboard') { ?>
<!-- <dashboard-container>  -->
    <div class="dashboard-container">
    <!--Sidebar-->
        <!--// Sidebar Style-->
            <style>
            .sidebar {
                width: 280px;
                background: #f8f9fb;
                color: #333;
                display: flex;
                flex-direction: column;
                position: fixed;
                height: 100vh;
                left: 0;
                top: 0;
                z-index: 1000;
            }

            .sidebar-header {
                padding: 1.5rem 1.5rem 1rem 1.5rem;
                border-bottom: none;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            .sidebar-header img {
                width: 200px;
                height: auto;
                display: block;
                align-items: center;
                justify-content: center;
            }

            .sidebar-header h3 {
                margin: 0;
                color: #111827;
                font-weight: 600;
                font-size: 1.125rem;
            }

            .workspace-selector {
                padding: 0 1.5rem 1rem 1.5rem;
                margin-bottom: 0.5rem;
            }

            .workspace-btn {
                display: flex;
                align-items: center;
                justify-content: space-between;
                width: 100%;
                padding: 0.75rem 1rem;
                /* background: #f3f4f6; */
                border: 0px;
                border-radius: 8px;
                /* color: #374151; */
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
            }

            .workspace-btn:hover {
                background: #e5e7eb;
            }

            .business-selector {
                position: relative;
            }

            .business-dropdown {
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: white;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                margin-top: 0.5rem;
                z-index: 1001;
                max-height: 300px;
                overflow-y: auto;
            }

            .business-dropdown .dropdown-item {
                display: flex;
                align-items: center;
                padding: 0.75rem 1rem;
                color: #374151;
                text-decoration: none;
                font-size: 0.875rem;
                transition: background 0.2s ease;
                border: none;
                width: 100%;
                text-align: left;
            }

            .business-dropdown .dropdown-item:hover {
                background: #f9fafb;
            }

            .business-dropdown .dropdown-divider {
                height: 1px;
                background: #e5e7eb;
                margin: 0.5rem 0;
            }

            .business-item:focus {
                outline: none;
                background: #f3f4f6;
            }

            .workspace-icon {
                width: 24px;
                height: 24px;
                background: #6b7280;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 0.75rem;
                font-weight: bold;
                margin-right: 0.75rem;
            }

            .progress-bar {
                width: 100%;
                height: 4px;
                background: #bfdbfe;
                border-radius: 2px;
                margin-top: 0.5rem;
                overflow: hidden;
            }

            .progress-fill {
                width: 100%;
                height: 100%;
                background: #3b82f6;
                border-radius: 2px;
            }

            .sidebar-nav {
                flex: 1;
                padding: 0 0 0 12px;
            }

            .sidebar-nav ul {
                list-style: none;
                margin: 0;
                padding: 0;
            }

            .sidebar-nav li {
                margin: 0;
            }

            .nav-link {
                display: flex;
                align-items: center;
                padding: var(--space-md);
                color: #6b7280;
                text-decoration: none;
                transition: all 0.2s ease;
                font-weight: 500;
                font-size: 0.875rem;
                border-radius: 8px;
                /*width: 200px;*/
            }

            .nav-link:hover {
                background: var(--gray-100);
                color: var(--primary-dark);
            }

            .nav-link.active {
                background: var(--primary-transparent);
                color: var(--primary-dark);
            }

            .nav-link i {
                 margin-right: 0.75rem;
                 font-size: 1rem;
                 width: 16px;
                 /*display: flex;*/
                 justify-content: center;
             }

             .nav-item {
                 position: relative;
             }

             .nav-link.has-submenu {
                 display: flex;
                 justify-content: space-between;
                 align-items: center;
             }
             a.nav-link.has-submenu {
                 margin-right: -1rem;
             }

             .submenu-toggle {
                 font-size: 0.75rem;
                 transition: transform 0.2s ease;
                 margin-left: auto;
             }

             .nav-item.open .submenu-toggle {
                 transform: rotate(180deg);
             }

             .submenu {
                 max-height: 0;
                 overflow: hidden;
                 transition: max-height 0.3s ease;
             }

             .nav-item.open .submenu {
                 max-height: 300px;
             }

             .submenu li {
                 list-style: none;
             }

             .submenu .nav-link {
                 padding: 0.5rem 1rem 0.5rem 3rem;
                 font-size: 0.875rem;
                 color: #6b7280;
             }

             .submenu .nav-link:hover {
                 background: var(--gray-100);
                 color: var(--primary-dark);
             }

             .submenu .nav-link.active {
                 background: rgba(59, 130, 246, 0.1);
                 color: #3b82f6;
             }

            .beta-badge {
                background: #e0e7ff;
                color: #5b21b6;
                font-size: 0.75rem;
                padding: 0.125rem 0.5rem;
                border-radius: 12px;
                margin-left: auto;
                font-weight: 500;
            }

            .sidebar-footer {
                padding: 1rem 1.5rem;
                border-top: 1px solid #e5e7eb;
            }


            .search-icon {
                margin-right: 0.5rem;
                font-size: 0.875rem;
                color: #6b7280;
            }

            .user-profile {
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }

            .user-avatar {
                width: 32px;
                height: 32px;
                background: #f59e0b;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 0.875rem;
            }

            .user-info {
                flex: 1;
            }

            .user-name {
                 font-weight: 600;
                 color: #111827;
                 font-size: 0.875rem;
                 margin: 0;
             }

             .user-profile {
                 position: relative;
                 cursor: pointer;
             }

             .user-dropdown {
                 position: absolute;
                 bottom: 100%;
                 left: 0;
                 right: 0;
                 background: white;
                 border: 1px solid #e5e7eb;
                 border-radius: 8px;
                 box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                 margin-bottom: 0.5rem;
                 display: none;
                 z-index: 1001;
             }

             .user-dropdown.show {
                 display: block;
             }

             .dropdown-item {
                 display: flex;
                 align-items: center;
                 padding: 0.75rem 1rem;
                 color: #374151;
                 text-decoration: none;
                 font-size: 0.875rem;
                 font-weight: 500;
                 border-bottom: 1px solid #f3f4f6;
                 transition: background 0.2s ease;
             }

             .dropdown-item:last-child {
                 border-bottom: none;
             }

             .dropdown-item:hover {
                 background: #f9fafb;
             }

             .dropdown-item:first-child {
                 border-radius: 8px 8px 0 0;
             }

             .dropdown-item:last-child {
                 border-radius: 0 0 8px 8px;
             }

             .dropdown-icon {
                 margin-right: 0.75rem;
                 font-size: 0.875rem;
                 width: 14px;
                 display: inline-flex;
                 justify-content: center;
             }
             
             /* Business info in sidebar styles */
             .business-info-sidebar {
                 padding: 0.75rem 1.5rem;
                 margin-bottom: 0.5rem;
                 border-bottom: 1px solid #e5e7eb;
             }
             
             .business-info-sidebar h4 {
                 margin: 0 0 0.5rem 0;
                 color: #111827;
                 font-weight: 600;
                 font-size: 0.95rem;
             }
             
             .business-info-sidebar .business-address {
                 font-size: 0.8rem;
                 color: #6b7280;
                 margin: 0;
                 display: flex;
                 align-items: center;
                 gap: 0.5rem;
             }
             
             .business-setup-sidebar {
                 padding: 0.75rem 1.5rem;
                 margin-bottom: 0.5rem;
                 border-bottom: 1px solid #e5e7eb;
             }
             
             .business-setup-btn {
                 display: flex;
                 align-items: center;
                 gap: 0.5rem;
                 padding: 0.5rem 0.75rem;
                 background: #f3f4f6;
                 border-radius: 6px;
                 color: #3b82f6;
                 font-size: 0.85rem;
                 font-weight: 500;
                 text-decoration: none;
                 transition: all 0.2s ease;
             }
             
             .business-setup-btn:hover {
                 background: #e5e7eb;
                 color: #2563eb;
             }
             </style>

             <script>
             function toggleBusinessDropdown() {
                 $('#businessDropdown').toggle();
             }

             // Close dropdown when clicking outside
             $(document).on('click', function(event) {
                 const $selector = $('.business-selector');
                 const $dropdown = $('#businessDropdown');

                 if ($selector.length && $dropdown.length && !$selector.is(event.target) && $selector.has(event.target).length === 0) {
                     $dropdown.hide();
                 }
             });
             </script>
        <!--// Sidebar HTML-->
            <div class="sidebar">
                <div class="sidebar-header">
                    <a href="/">
                            <img src="/assets/images/logo.png" alt="Aplikasi Emas Pintar">
                        </a>
                </div>
                
                <?php
                // <business-info-sidebar>
                $current_business = get_current_business();
                if ($current_business): ?>
                <div class="business-info-sidebar">
                    <h4><?= e($current_business['name']) ?></h4>
                    <?php if (!empty($current_business['address'])): ?>
                    <p class="business-address"><i class="fas fa-map-marker-alt"></i> <?= e($current_business['address']) ?></p>
                    <?php endif; ?>
                </div>
                <?php else: ?>
                <div class="business-setup-sidebar">
                    <a href="/business" class="business-setup-btn">
                        <i class="fas fa-plus-circle"></i> Setup Business
                    </a>
                </div>
                <?php endif; ?>
                <!-- </business-info-sidebar> -->

                <nav class="sidebar-nav">
                    <ul>
                        <li class="nav-item"><a href="/dashboard" class="nav-link <?= $current_page === 'dashboard' ? 'active' : ''; ?>"><i class="fas fa-home"></i>Dashboard</a></li>


                        <?php if (is_paid_user()): // Only show these menus for paid users ?>
                        
                        <li class="nav-item"><a href="/business" class="nav-link <?= $current_page === 'business' ? 'active' : ''; ?>"><i class="fas fa-building"></i>Business</a></li>
                        
                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'teams' && 'customers' ? 'active' : ''; ?>">
                                <span><i class="fas fa-users"></i>Manajemen User</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="/user-management/teams" class="nav-link <?= $current_page === 'teams' ? 'active' : ''; ?>">Admin dan Karyawan</a></li>
                                <li><a href="/user-management/customers" class="nav-link <?= $current_page === 'customers' ? 'active' : ''; ?>">Customer</a></li>
                            </ul>
                        </li>

                        <li class="nav-item"><a href="#" class="nav-link <?= $current_page === 'produk' ? 'active' : ''; ?>"><i class="fas fa-boxes-stacked"></i>Produk</a></li>
                       
                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'plans' ? 'active' : ''; ?>">
                                <span><i class="fas fa-store"></i>Stock Emas</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Kepemilikan Barang</a></li>
                                <li><a href="#" class="nav-link">Jual & Beli</a></li>
                                <li><a href="#" class="nav-link">Biaya Operasional</a></li>
                                <li><a href="#" class="nav-link">Biaya Non Operasional</a></li>
                            </ul>
                        </li>

                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'plans' ? 'active' : ''; ?>">
                                <span><i class="fas fa-hand-holding-dollar"></i>Buyback Emas</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Kepemilikan Barang</a></li>
                                <li><a href="#" class="nav-link">Jual & Beli</a></li>
                                <li><a href="#" class="nav-link">Biaya Operasional</a></li>
                                <li><a href="#" class="nav-link">Biaya Non Operasional</a></li>
                            </ul>
                        </li>

                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'plans' ? 'active' : ''; ?>">
                                <span><i class="fas fa-truck"></i>Pengiriman Internal</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Shipments</a></li>
                                <li><a href="#" class="nav-link">Masuk Jogja</a></li>
                                <li><a href="#" class="nav-link">Keluar Jogja</a></li>
                            </ul>
                        </li>

                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'plans' ? 'active' : ''; ?>">
                                <span><i class="fas fa-handshake"></i>Serah Terima</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Jogja</a></li>
                                <li><a href="#" class="nav-link">Jabodetabek</a></li>
                            </ul>
                        </li>

                        <li class="nav-item">
                            <a href="#" class="nav-link has-submenu <?= $current_page === 'plans' ? 'active' : ''; ?>">
                                <span><i class="fas fa-cash-register"></i>Keuangan</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Modal</a></li>
                                <li><a href="#" class="nav-link">Bagi Hasil</a></li>
                                <li><a href="#" class="nav-link">Fee Akad Wakala</a></li>
                                <li><a href="#" class="nav-link">Pengeluaran Global</a></li>
                                <li><a href="#" class="nav-link">Laporan Keuangan</a></li>
                                <li><a href="#" class="nav-link">Rekonsiliasi</a></li>
                            </ul>
                        </li>

                        <li class="nav-item">
                            <a href="settings" class="nav-link has-submenu <?= $current_page === 'settings' ? 'active' : ''; ?>">
                                <span><i class="fas fa-gear"></i>Settings</span>
                                <i class="fas fa-chevron-down submenu-toggle"></i>
                            </a>
                            <ul class="submenu">
                                <li><a href="#" class="nav-link">Harga</a></li>
                                <li><a href="#" class="nav-link">Katalog</a></li>
                                <li><a href="#" class="nav-link">Akun Finansial</a></li>
                                <li><a href="#" class="nav-link">Lokasi</a></li>
                            </ul>
                        </li>
                        <?php endif; ?>

                        

                    </ul>
                </nav>

                <div class="sidebar-footer">
                    <div class="user-profile" id="userProfile">
                        <div class="user-dropdown" id="userDropdown">
                            <a href="#" class="dropdown-item">
                                <i class="fas fa-user dropdown-icon"></i>
                                Account
                            </a>
                            <a href="/logout" class="dropdown-item">
                                <i class="fas fa-sign-out-alt dropdown-icon"></i>
                                Logout
                            </a>
                        </div>
                        <div class="user-avatar"><img style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;" src="<?= e($user['picture'] ?? 'Guest'); ?>" alt="User Avatar"></div>
                        <div class="user-info">
                            <div class="user-name"><?= e($user['name'] ?? 'Guest'); ?></div>
                        </div>
                    </div>
                </div>
            </div>
        <!--// Sidebar Script-->
            <!--User Profile Dropdown Script-->
            <script>
            $(function() {
                // Restore sidebar state on page load, but only if it's relevant to the current page
                var openSubmenu = localStorage.getItem('openSubmenu');
                var currentPage = '<?= $current_page ?>';
                
                if (openSubmenu) {
                    $('.nav-item').each(function() {
                        var $navItem = $(this);
                        var $link = $navItem.find('.nav-link.has-submenu');
                        var linkText = $link.find('span').text().trim();
                        
                        // Check if this submenu contains the current page
                        var containsCurrentPage = false;
                        $navItem.find('.submenu .nav-link').each(function() {
                            var href = $(this).attr('href');
                            if (href && href.includes(currentPage)) {
                                containsCurrentPage = true;
                            }
                        });
                        
                        // Only open the submenu if it matches stored value AND contains current page
                        if (linkText === openSubmenu && containsCurrentPage) {
                            $navItem.addClass('open');
                        }
                    });
                }

                // Toggle dropdown when user profile is clicked
                $('#userProfile').click(function(e) {
                    e.stopPropagation();
                    $('#userDropdown').toggleClass('show');
                });

                // Close dropdown when clicking outside
                $(document).click(function() {
                    $('#userDropdown').removeClass('show');
                });

                // Prevent dropdown from closing when clicking inside it
                $('#userDropdown').click(function(e) {
                    e.stopPropagation();
                });

                // Function to check if current page belongs to any submenu
                function isCurrentPageInSubmenu() {
                    var currentPage = '<?= $current_page ?>';
                    var found = false;
                    
                    $('.submenu .nav-link').each(function() {
                        var href = $(this).attr('href');
                        if (href && href.includes(currentPage)) {
                            found = true;
                            return false; // break the loop
                        }
                    });
                    
                    return found;
                }
                
                // Close all submenus if current page doesn't belong to any submenu
                if (!isCurrentPageInSubmenu()) {
                    $('.nav-item.open').removeClass('open');
                    localStorage.removeItem('openSubmenu');
                }
                
                // Submenu toggle functionality
                $('.nav-link.has-submenu').click(function(e) {
                    e.preventDefault();

                    var $navItem = $(this).parent('.nav-item');
                    var $submenu = $navItem.find('.submenu');
                    var linkText = $(this).find('span').text().trim();

                    // Close other open submenus
                    $('.nav-item.open').not($navItem).removeClass('open');

                    // Toggle current submenu
                    $navItem.toggleClass('open');

                    // Save state to localStorage
                    if ($navItem.hasClass('open')) {
                        localStorage.setItem('openSubmenu', linkText);
                    } else {
                        localStorage.removeItem('openSubmenu');
                    }
                });

                // Handle submenu item clicks
                $('.submenu .nav-link').click(function(e) {
                    e.stopPropagation();

                    // Save the parent submenu state before navigation
                    var $parentNavItem = $(this).closest('.nav-item');
                    var $parentLink = $parentNavItem.find('.nav-link.has-submenu');
                    var parentLinkText = $parentLink.find('span').text().trim();
                    var clickedHref = $(this).attr('href');
                    
                    // Only save state if this is a navigation within the same submenu section
                    if (clickedHref) {
                        localStorage.setItem('openSubmenu', parentLinkText);
                    }

                    // Remove active class from all submenu items
                    $('.submenu .nav-link').removeClass('active');

                    // Add active class to clicked item
                    $(this).addClass('active');
                });
            });
            </script>
    <!--Dashboard Page-->
        <!--Style-->
            <style>
            .dashboard-content {
                flex: 1;
                margin-left: 280px;
                margin-right: -12px;
                padding: 1rem 0rem 1rem 1rem;
                position: relative;
                top: 0;
                height: 100vh;
                background: #f8f9fa;
                overflow: hidden;
            }

            .dashboard-content-wrapper {
                background: white;
                border-radius: 16px;
                border: 1px solid #e9ecef;
                padding: 2rem;
                height: calc(100vh - 6rem);
                overflow-y: auto;
            }

            /* Override container margin for dashboard layout */
            .container {
                margin: 0 auto !important;
                padding: 0 !important;
                max-width: none !important;
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
                background: #f8f9fa;
                padding: 2rem;
                border-radius: 12px;
                border: 1px solid #e9ecef;
                transition: transform 0.2s ease, background-color 0.2s ease;
            }

            .dashboard-card:hover {
                transform: translateY(-2px);
                background: white;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }

            .card-header {
                display: flex;
                align-items: center;
                margin-bottom: 1rem;
            }

            .card-icon {
                width: 40px;
                height: 40px;
                background: #007bff;
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

            .content-body {
                background: white;
                padding: 2rem;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                border: 1px solid #e9ecef;
            }

            .placeholder-content {
                text-align: center;
                padding: 3rem;
                color: #6c757d;
            }

            @media (max-width: 768px) {
                .sidebar {
                    width: 100%;
                    height: auto;
                    position: relative;
                }

                .dashboard-content {
                    margin-left: 0;
                    padding: 1rem;
                }

                .dashboard-layout {
                    flex-direction: column;
                }
            }
            </style>
        <!--Dashboard Page-->
            <?php switch ($current_page) { case 'dashboard':
            ?>
            <div class="dashboard-content">
                <div class="dashboard-content-wrapper">
                    <?php if (isset($_SESSION['messages']) && !empty($_SESSION['messages'])): ?>
                        <div class="messages" style="background-color: #d4edda; color: #155724; padding: 1rem; margin-bottom: 1rem; border-radius: 4px; border-left: 4px solid #28a745;">
                            <?php foreach ($_SESSION['messages'] as $message): ?>
                                <p style="margin: 0.5rem 0;"><?= e($message) ?></p>
                            <?php endforeach; ?>
                        </div>
                        <?php 
                        // Clear messages after displaying them
                        $_SESSION['messages'] = [];
                        ?>
                    <?php endif; ?>
                    
                    <div class="dashboard-header">
                        <h2>Welcome to Your Dashboard</h2>
                        <p>Manage your business and access available features.</p>
                    </div>
                    
                    <?php if (!is_paid_user()): // Show upgrade banner for free users ?>
                    <div class="upgrade-banner" style="background: linear-gradient(135deg, #4a6cf7, #2541b2); color: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <h3 style="margin-top: 0; font-size: 1.5rem;">Upgrade to Paid Plan</h3>
                        <p style="margin-bottom: 1rem;">Unlock all features including User Management, Product Management, Stock Management, and more!</p>
                        <p style="margin-bottom: 1rem;">With the paid plan, you'll get:</p>
                        <ul style="margin-bottom: 1.5rem; padding-left: 1.5rem;">
                            <li>Complete user management system</li>
                            <li>Product inventory and tracking</li>
                            <li>Stock management tools</li>
                            <li>Financial reporting</li>
                            <li>And much more!</li>
                        </ul>
                        <p style="font-size: 0.9rem; margin-bottom: 0;">Contact the administrator to upgrade your account to a paid plan.</p>
                    </div>
                    <?php else: ?>

                        <div class="dashboard-cards">

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">👥</div>
                            <h3 class="card-title">Members</h3>
                        </div>
                        <div class="card-content">
                            <p>Manage your community members, their profiles, and access levels.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📋</div>
                            <h3 class="card-title">Plans</h3>
                        </div>
                        <div class="card-content">
                            <p>Create and manage subscription plans for your members.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📄</div>
                            <h3 class="card-title">Gated Content</h3>
                        </div>
                        <div class="card-content">
                            <p>Control access to premium content based on membership levels.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">🔧</div>
                            <h3 class="card-title">Components</h3>
                        </div>
                        <div class="card-content">
                            <p>Customize and configure various components of your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">👥</div>
                            <h3 class="card-title">Community</h3>
                        </div>
                        <div class="card-content">
                            <p>Foster engagement and build connections within your community.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>


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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

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
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                </div>


                    <?php endif; ?>

                    

            </div>
        <!--<Toko Page>-->
            <?php break; case 'business':?>
            <?php
                // Get user's businesses and current business
                $user_businesses = get_user_businesses();
                $current_business = get_current_business();
                $edit_business = null;

                // Check if we're editing a business
                if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
                    $edit_business = get_business_by_id((int)$_GET['edit']);
                }
            ?>
            <div class="dashboard-content">
                <div class="dashboard-header">
                    <h2>Business Management</h2>
                    <p>Manage your businesses and switch between them for multitenant operations.</p>
                </div>



                <div class="content-body">
                     <!-- Current Business Display -->
                <?php if ($current_business): ?>
                <div class="current-business-banner" style="background: var(--primary-color); padding: 1rem; border-radius: 8px; margin-bottom: 2rem;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div>
                            <h4 style="margin: 0; font-size: 1.1rem;">Current Business</h4>
                            <h3 style="margin: 0.25rem 0 0 0; font-size: 1.5rem;"><?= e($current_business['name']) ?></h3>
                        </div>
                        <div style="text-align: right; opacity: 0.9;">
                            <small>ID: <?= $current_business['id'] ?></small><br>
                            <small>Created: <?= date('M j, Y', strtotime($current_business['created_at'])) ?></small>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                    <!-- Create Business Button (only show if no business exists) -->
                    <?php if (!$edit_business && empty($user_businesses)): ?>
                    <div style="margin-bottom: 2rem; text-align: right;">
                        <button id="createBusinessBtn"
                                style="background: #007bff; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 600; display: inline-flex; align-items: center; gap: 0.5rem;">
                            <i class="fas fa-plus"></i> Create Your Business
                        </button>
                    </div>
                    <?php endif; ?>

                    <!-- Edit Business Form (only shown when editing) -->
                    <?php if ($edit_business): ?>
                    <div class="business-form-section" style="background: #f8f9fa; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
                        <h3 style="margin-top: 0; color: #333;">Edit Business</h3>

                        <form method="POST" style="display: grid; gap: 1rem;">
                            <?= csrf_field() ?>
                            <input type="hidden" name="action" value="update_business">
                            <input type="hidden" name="business_id" value="<?= $edit_business['id'] ?>">
                            <input type="hidden" name="redirect_url" value="/business">

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div>
                                    <label for="name" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Business Name *</label>
                                    <input type="text" id="name" name="name" required
                                           value="<?= e($edit_business['name']) ?>"
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                </div>

                                <div>
                                    <label for="email" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Business Email</label>
                                    <input type="email" id="email" name="email"
                                           value="<?= e($edit_business['email']) ?>"
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                </div>
                            </div>

                            <div>
                                <label for="description" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Description</label>
                                <textarea id="description" name="description" rows="3"
                                          style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; resize: vertical;"><?= e($edit_business['description']) ?></textarea>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div>
                                    <label for="phone" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Phone</label>
                                    <input type="tel" id="phone" name="phone"
                                           value="<?= e($edit_business['phone']) ?>"
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                </div>

                                <div>
                                    <label for="website" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Website</label>
                                    <input type="url" id="website" name="website"
                                           value="<?= e($edit_business['website']) ?>"
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                </div>
                            </div>

                            <div>
                                <label for="address" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Address</label>
                                <textarea id="address" name="address" rows="2"
                                          style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; resize: vertical;"><?= e($edit_business['address']) ?></textarea>
                            </div>

                            <div>
                                <label for="logo_url" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Logo URL</label>
                                <input type="url" id="logo_url" name="logo_url"
                                       value="<?= e($edit_business['logo_url']) ?>"
                                       style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                            </div>

                            <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                                <button type="submit"
                                        style="background: #007bff; color: white; padding: 0.75rem 2rem; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 600;">
                                    Update Business
                                </button>

                                <a href="/business"
                                   style="background: #6c757d; color: white; padding: 0.75rem 2rem; border: none; border-radius: 6px; font-size: 1rem; text-decoration: none; font-weight: 600; display: inline-block;">
                                    Cancel
                                </a>
                            </div>
                        </form>
                    </div>
                    <?php endif; ?>

                    <!-- Business Information -->
                    <div class="business-info-section">
                        <h3 style="color: #333; margin-bottom: 1.5rem;">Your Business</h3>

                        <?php if (empty($user_businesses)): ?>
                            <div style="text-align: center; padding: 3rem; background: #f8f9fa; border-radius: 12px; color: #6c757d;">
                                <h4 style="margin-bottom: 1rem;">No business yet</h4>
                                <p>Create your business to get started with your operations.</p>
                            </div>
                        <?php else: ?>
                            <div style="display: grid; gap: 1rem;">
                                <?php foreach ($user_businesses as $business): ?>
                                    <?php
                                    $current_business_id = isset($_SESSION['current_business']['id']) ? $_SESSION['current_business']['id'] : 0;
                                    $is_current = $current_business_id == $business['id'];
                                    $border_style = $is_current ? '2px solid #28a745' : '1px solid #e9ecef';
                                    $badge = $is_current ? '<span style="position: absolute; top: 10px; right: 10px; background: #28a745; color: white; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">Current</span>' : '';
                                    ?>
                                    <div class="business-card" style="background: white; border: <?= $border_style ?>; border-radius: 12px; padding: 1.5rem; position: relative;">
                                    <?= $badge ?>

                                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                                            <div style="flex: 1;">
                                                <h4 style="margin: 0 0 0.5rem 0; color: #333; font-size: 1.25rem;"><?= e($business['name']) ?></h4>
                                                <?php if ($business['description']): ?>
                                                    <p style="margin: 0 0 0.5rem 0; color: #6c757d;"><?= e($business['description']) ?></p>
                                                <?php endif; ?>

                                                <div style="display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 0.75rem; font-size: 0.875rem; color: #6c757d;">
                                                    <?php if ($business['email']): ?>
                                                        <span>📧 <?= e($business['email']) ?></span>
                                                    <?php endif; ?>
                                                    <?php if ($business['phone']): ?>
                                                        <span>📞 <?= e($business['phone']) ?></span>
                                                    <?php endif; ?>
                                                    <?php if ($business['website']): ?>
                                                        <span>🌐 <a href="<?= e($business['website']) ?>" target="_blank" style="color: #007bff;"><?= e($business['website']) ?></a></span>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>

                                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                            <a href="/business?edit=<?= $business['id'] ?>"
                                               style="background: #007bff; color: white; padding: 0.5rem 1rem; border-radius: 4px; font-size: 0.875rem; text-decoration: none; font-weight: 500;">
                                                Edit Business
                                            </a>
                                            <?php if (!$is_current): ?>
                                            <form method="POST" style="display: inline;">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="action" value="set_current_business">
                                                <input type="hidden" name="business_id" value="<?= $business['id'] ?>">
                                                <button type="submit"
                                                       style="background: #28a745; color: white; padding: 0.5rem 1rem; border-radius: 4px; font-size: 0.875rem; border: none; cursor: pointer; font-weight: 500;">
                                                    Set as Current Business
                                                </button>
                                            </form>
                                            <?php endif; ?>
                                        </div>

                                        <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #e9ecef; font-size: 0.75rem; color: #6c757d;">
                                            Created: <?= date('M j, Y g:i A', strtotime($business['created_at'])) ?> |
                                            Updated: <?= date('M j, Y g:i A', strtotime($business['updated_at'])) ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Create Business Modal -->
                <div id="createBusinessModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                    <div style="background: white; border-radius: 12px; width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; position: relative;">
                        <div style="padding: 2rem; border-bottom: 1px solid #e9ecef; display: flex; justify-content: space-between; align-items: center;">
                            <h3 style="margin: 0; color: #333;">Create Your Business</h3>
                            <button id="closeModalBtn" style="background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #6c757d; padding: 0; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center;">
                                &times;
                            </button>
                        </div>

                        <div style="padding: 2rem;">
                            <form id="createBusinessForm" method="POST" style="display: grid; gap: 1rem;">
                                <?= csrf_field() ?>
                                <input type="hidden" name="action" value="create_business">
                                <input type="hidden" name="redirect_url" value="/business">

                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                    <div>
                                        <label for="modal_name" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Business Name *</label>
                                        <input type="text" id="modal_name" name="name" required
                                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                    </div>

                                    <div>
                                        <label for="modal_email" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Business Email</label>
                                        <input type="email" id="modal_email" name="email"
                                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                    </div>
                                </div>

                                <div>
                                    <label for="modal_description" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Description</label>
                                    <textarea id="modal_description" name="description" rows="3"
                                              style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; resize: vertical;"></textarea>
                                </div>

                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                    <div>
                                        <label for="modal_phone" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Phone</label>
                                        <input type="tel" id="modal_phone" name="phone"
                                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                    </div>

                                    <div>
                                        <label for="modal_website" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Website</label>
                                        <input type="url" id="modal_website" name="website"
                                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                    </div>
                                </div>

                                <div>
                                    <label for="modal_address" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Address</label>
                                    <textarea id="modal_address" name="address" rows="2"
                                              style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; resize: vertical;"></textarea>
                                </div>

                                <div>
                                    <label for="modal_logo_url" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333;">Logo URL</label>
                                    <input type="url" id="modal_logo_url" name="logo_url"
                                           style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem;">
                                </div>

                                <div style="display: flex; gap: 1rem; margin-top: 1rem; justify-content: flex-end;">
                                    <button type="button" id="cancelModalBtn"
                                            style="background: #6c757d; color: white; padding: 0.75rem 2rem; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 600;">
                                        Cancel
                                    </button>
                                    <button type="submit"
                                            style="background: #007bff; color: white; padding: 0.75rem 2rem; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 600;">
                                        Create Business
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <script>
                $(document).ready(function() {
                    // Open modal when create button is clicked
                    $('#createBusinessBtn').click(function() {
                        $('#createBusinessModal').css('display', 'flex');
                        $('body').css('overflow', 'hidden'); // Prevent background scrolling
                    });

                    // Close modal functions
                    function closeModal() {
                        $('#createBusinessModal').hide();
                        $('body').css('overflow', 'auto'); // Restore scrolling
                        // Reset form
                        $('#createBusinessForm')[0].reset();
                    }

                    // Close modal when X button is clicked
                    $('#closeModalBtn').click(closeModal);

                    // Close modal when Cancel button is clicked
                    $('#cancelModalBtn').click(closeModal);

                    // Close modal when clicking outside the modal content
                    $('#createBusinessModal').click(function(e) {
                        if (e.target === this) {
                            closeModal();
                        }
                    });

                    // Close modal with Escape key
                    $(document).keydown(function(e) {
                        if (e.key === 'Escape' && $('#createBusinessModal').is(':visible')) {
                            closeModal();
                        }
                    });
                });
                </script>
            </div> <!--</Business Management Page>-->
        <!--Manajemen User - Parent Page-->
            <!--<Manajemen User - Admin dan Karyawan Page>-->
                <?php break; case 'teams':?>
                <div class="dashboard-content">
                    <div class="dashboard-header">
                        <h2>Admin dan Karyawan</h2>
                        <p>Here's what's happening with your account today.</p>
                    </div>
                    <div class="content-body">
                        <!-- Content will go here -->
                        <div class="placeholder-content">
                            <p>Main content area - ready for your content!</p>
                        </div>
                    </div>
                </div> <!--</Manajemen User - Admin dan Karyawan Page>-->
            <!--<Manajemen User - Customers Page>-->
                <?php break; case 'customers':?>
                <div class="dashboard-content">
                    <div class="dashboard-header">
                        <h2>Customers</h2>
                        <p>Here's what's happening with your account today.</p>
                    </div>
                    <div class="content-body">
                        <!-- Content will go here -->
                        <div class="placeholder-content">
                            <p>Main content area - ready for your content!</p>
                        </div>
                    </div>
                </div><!--</Manajemen User - Customer Page>-->
        <!--Settings Page-->
            <?php break; case 'settings':?>
            <div class="dashboard-content">
                <div class="dashboard-header">
                    <h2>Settings, <?= e($user['name']); ?>!</h2>
                    <p>Here's what's happening with your account today.</p>
                </div>
                <div class="content-body">
                    <!-- Content will go here -->
                    <div class="placeholder-content">
                        <p>Main content area - ready for your content!</p>
                    </div>
                </div>
            </div>
        <!--404 Page-->
            <?php break; default:?>
            <div>
                Error 404
            </div>
            <?php } ?>
    <!--Footer Page-->
    </div>
<!-- </dashboard-container>  -->

<!--VIEW: other pages-->
<?php } else { ?>
<!-- <other-container>  -->
    <div class="other-container">
    </div>
<!-- </other-container>  -->

<?php } ?>
</body>
</html>
<!--<EOF>-->
