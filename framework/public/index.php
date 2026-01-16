<?php
/**
 * ============================================================================
 * MONOPHP - Single File Index.PHP Framework
 * ============================================================================
 * Version: 0.2
 * Total Lines: ~4000
 * Last Structure Update: 2026-01-16
 *
 * HOW TO USE THIS FILE (FOR AI AGENTS):
 * -------------------------------------
 * 1. Read the TABLE OF CONTENTS below to find sections
 * 2. Search for section markers: ===[SECTION:name]===
 * 3. Search for function markers: @FUNC function_name
 * 4. Search for view markers: ===[VIEW:page-name]===
 * 5. Search for style markers: ===[STYLES:name]===
 *
 * TABLE OF CONTENTS
 * -----------------
 * @TOC-START
 *
 * === CORE INFRASTRUCTURE ===
 * SECTION:init           Lines 66-78       Initial settings, strict types
 * SECTION:env            Lines 80-112      Environment file loading
 * SECTION:config         Lines 114-124     Site configuration constants
 * SECTION:session        Lines 126-150     Session management
 * SECTION:flash          Lines 152-221     Flash messages
 * SECTION:security       Lines 223-234     CSRF tokens, CSP headers
 * SECTION:validation     Lines 236-423     Validation layer
 * SECTION:error          Lines 425-560     Error/exception handlers
 *
 * === DATABASE LAYER ===
 * SECTION:database       Lines 562-633     DB connection, migrations
 * SECTION:seeds          Lines 635-777     Database seeding
 * SECTION:query-builder  Lines 779-1151    Query helpers + soft deletes
 *
 * === SECURITY FEATURES ===
 * SECTION:rate-limit     Lines 1153-1304   Rate limiting
 * SECTION:password-reset Lines 1306-1438   Password reset tokens
 * SECTION:remember-me    Lines 1440-1594   Remember me tokens
 *
 * === UTILITIES ===
 * SECTION:logging        Lines 1596-1699   Structured logging
 * SECTION:cache          Lines 1701-1879   File-based caching
 * SECTION:api            Lines 1881-2019   JSON API helpers
 * SECTION:authorization  Lines 2021-2134   Policy-based auth
 * SECTION:uploads        Lines 2136-2297   File uploads
 * SECTION:helpers        Lines 2299-2353   Core utility functions
 * SECTION:form-helpers   Lines 2355-2621   Form generation
 *
 * === APPLICATION ===
 * SECTION:view-init      Lines 2623-2636   View initialization
 * SECTION:post           Lines 2638-2666   POST request handlers
 * SECTION:routes         Lines 2668-2719   Route definitions
 * SECTION:html-head      Lines 2722-3027   DOCTYPE, CSS, base styles
 *
 * === VIEWS & STYLES ===
 * STYLES:navbar          Lines 3035-3187   Navigation styles
 * VIEW:home              Lines 3228-3544   Homepage with hero
 * VIEW:feature           Lines 3546-3554   Features page
 * VIEW:about             Lines 3556-3737   About page
 * VIEW:courses           Lines 3739-3747   Courses page
 * VIEW:testimonial       Lines 3749-3757   Testimonials page
 * VIEW:contact           Lines 3759-3767   Contact page
 * VIEW:login             Lines 3769-3777   Login page
 * VIEW:signup            Lines 3779-3787   Signup page
 * VIEW:dashboard         Lines 3789-3922   Dashboard page
 * VIEW:404               Lines 3924-3933   404 page
 * SECTION:scripts        Lines 3943-3974   Theme toggle script
 *
 * @TOC-END
 *
 * FUNCTION INDEX (75+ functions)
 * ------------------------------
 * @FUNC-INDEX-START
 *
 * === Core ===
 * @FUNC load_env()                    Environment variables from .env
 * @FUNC getErrorTypeName()            Human-readable error type
 * @FUNC getCodeContext()              Code context around error line
 * @FUNC get_db_connection()           PDO database connection
 * @FUNC initialize_database()         Initialize core tables
 * @FUNC run_migrations()              Run pending migrations
 * @FUNC e()                           HTML escape for safe output
 * @FUNC sanitize_input()              Sanitize array input for XSS
 * @FUNC csrf_token()                  Get current CSRF token
 * @FUNC csrf_field()                  Generate CSRF hidden input
 * @FUNC redirect()                    Redirect to URL and exit
 *
 * === Flash Messages ===
 * @FUNC flash()                       Add flash message to session
 * @FUNC get_flashes()                 Get and clear flash messages
 * @FUNC has_flash()                   Check for flash messages
 * @FUNC flash_render()                Render flash messages as HTML
 *
 * === Validation ===
 * @FUNC validate()                    Validate data against rules
 * @FUNC validate_rule()               Validate single field/rule
 * @FUNC validation_errors_flat()      Flatten errors to simple list
 * @FUNC validation_first_error()      Get first error for field
 *
 * === Query Builder ===
 * @FUNC db_find()                     Find record by ID
 * @FUNC db_first()                    Find first matching record
 * @FUNC db_all()                      Get all matching records
 * @FUNC db_insert()                   Insert record, return ID
 * @FUNC db_update()                   Update record by ID
 * @FUNC db_delete()                   Delete record by ID
 * @FUNC db_count()                    Count matching records
 * @FUNC db_exists()                   Check if record exists
 * @FUNC db_query()                    Execute raw SELECT query
 * @FUNC db_execute()                  Execute raw INSERT/UPDATE/DELETE
 * @FUNC db_soft_delete()              Soft delete (set deleted_at)
 * @FUNC db_restore()                  Restore soft-deleted record
 * @FUNC db_all_with_deleted()         Include soft-deleted records
 * @FUNC db_only_deleted()             Get only soft-deleted records
 * @FUNC db_is_deleted()               Check if record is deleted
 *
 * === Rate Limiting ===
 * @FUNC rate_limit()                  Check if action is rate limited
 * @FUNC rate_limit_hit()              Record an attempt
 * @FUNC rate_limit_clear()            Clear rate limit for key
 * @FUNC rate_limit_remaining()        Get remaining attempts
 * @FUNC rate_limit_retry_after()      Seconds until retry allowed
 *
 * === Password Reset ===
 * @FUNC create_password_reset()       Generate reset token
 * @FUNC validate_reset_token()        Check if token is valid
 * @FUNC complete_password_reset()     Reset password with token
 * @FUNC password_reset_url()          Generate reset URL
 *
 * === Remember Me ===
 * @FUNC create_remember_token()       Create persistent login token
 * @FUNC validate_remember_token()     Auto-login from cookie
 * @FUNC clear_remember_token()        Remove token and cookie
 * @FUNC clear_all_remember_tokens()   Logout everywhere
 *
 * === Logging ===
 * @FUNC log_debug()                   Debug level log
 * @FUNC log_info()                    Info level log
 * @FUNC log_warning()                 Warning level log
 * @FUNC log_error()                   Error level log
 * @FUNC log_exception()               Log exception with trace
 * @FUNC log_request()                 Log HTTP request details
 *
 * === Caching ===
 * @FUNC cache_get()                   Get value from cache
 * @FUNC cache_set()                   Store value in cache
 * @FUNC cache_has()                   Check if key exists
 * @FUNC cache_forget()                Remove item from cache
 * @FUNC cache_flush()                 Clear all cached items
 * @FUNC cache_remember()              Get or compute and store
 *
 * === API ===
 * @FUNC is_api_request()              Check if API request
 * @FUNC api_cors()                    Set CORS headers
 * @FUNC api_response()                Send JSON response
 * @FUNC api_success()                 Send success response
 * @FUNC api_error()                   Send error response
 * @FUNC api_paginate()                Send paginated response
 * @FUNC api_input()                   Get JSON input from body
 *
 * === Authorization ===
 * @FUNC define_policy()               Register authorization policy
 * @FUNC can()                         Check if user can do action
 * @FUNC cannot()                      Check if user cannot do action
 * @FUNC authorize()                   Authorize or die/redirect
 * @FUNC is_admin()                    Check if user is admin
 * @FUNC is_owner()                    Check if user owns resource
 *
 * === File Uploads ===
 * @FUNC upload_file()                 Upload file with validation
 * @FUNC delete_uploaded_file()        Delete an uploaded file
 * @FUNC get_upload_url()              Get full URL for file
 * @FUNC upload_image()                Upload image (convenience)
 * @FUNC upload_document()             Upload document (convenience)
 *
 * === Form Helpers ===
 * @FUNC form_open()                   Open form with CSRF
 * @FUNC form_close()                  Close form tag
 * @FUNC form_text()                   Text input
 * @FUNC form_email()                  Email input
 * @FUNC form_password()               Password input
 * @FUNC form_textarea()               Textarea
 * @FUNC form_select()                 Select dropdown
 * @FUNC form_checkbox()               Checkbox input
 * @FUNC form_radio()                  Radio input
 * @FUNC form_hidden()                 Hidden input
 * @FUNC form_submit()                 Submit button
 * @FUNC form_file()                   File input
 * @FUNC old()                         Get old input value
 *
 * === Database Seeding ===
 * @FUNC get_seeds()                   Get seed data definitions
 * @FUNC seed_table()                  Seed a single table
 * @FUNC run_seeds()                   Run all database seeds
 * @FUNC is_database_empty()           Check if DB has no users
 *
 * @FUNC-INDEX-END
 *
 * ============================================================================
 */

// ===[SECTION:init]===
// PURPOSE: Initialize PHP settings and detect development mode
// DEPENDENCIES: None
// EXPORTS: $is_development
    // Strict types
        declare(strict_types=1);
    // Define development mode
        // $is_development = false;
        $is_development =
            $_SERVER["SERVER_NAME"] === "localhost" ||
            $_SERVER["SERVER_ADDR"] === "127.0.0.1" ||
            $_SERVER["REMOTE_ADDR"] === "127.0.0.1";
// ===[/SECTION:init]===

// ===[SECTION:env]===
// PURPOSE: Load environment variables from .env file
// DEPENDENCIES: None
// EXPORTS: Environment variables via putenv() and $_ENV
    // Locate env file
        const SITE_ENV_FILE = __DIR__ . "/../.env";
    /**
     * @FUNC load_env
     * @brief Load environment variables from .env file into putenv() and $_ENV
     * @return void
     */
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
// ===[/SECTION:env]===

// ===[SECTION:config]===
// PURPOSE: Define site configuration constants
// DEPENDENCIES: SECTION:env (for getenv)
// EXPORTS: SITE_APP_VERSION, SITE_DOMAIN, SITE_DB_FILE, SITE_LOG_FILE
    // Site settings
        const SITE_APP_VERSION = "1.0.0";
        define('SITE_DOMAIN', getenv('SITE_DOMAIN') ?: 'localhost');
    // File location
        const SITE_DB_FILE = __DIR__ . "/../database/monophp.sqlite";
        const SITE_LOG_FILE = __DIR__ . "/../logs/app.log";
// ===[/SECTION:config]===

// ===[SECTION:session]===
// PURPOSE: Configure and start PHP session with secure cookie parameters
// DEPENDENCIES: SECTION:config (for SITE_DOMAIN)
// EXPORTS: Active session, $session_domain
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
// ===[/SECTION:session]===

// ===[SECTION:flash]===
// PURPOSE: Flash messages that persist through redirects (like Rails flash)
// DEPENDENCIES: SECTION:session
// EXPORTS: flash(), get_flashes(), has_flash()

    /**
     * @FUNC flash
     * @brief Add a flash message to the session
     * @param string $type Message type (success, error, warning, info)
     * @param string $message The message content
     * @return void
     */
        function flash(string $type, string $message): void {
            if (!isset($_SESSION['_flash'])) {
                $_SESSION['_flash'] = [];
            }
            if (!isset($_SESSION['_flash'][$type])) {
                $_SESSION['_flash'][$type] = [];
            }
            $_SESSION['_flash'][$type][] = $message;
        }

    /**
     * @FUNC get_flashes
     * @brief Get all flash messages and clear them from session
     * @return array Associative array of flash messages by type
     */
        function get_flashes(): array {
            $flashes = $_SESSION['_flash'] ?? [];
            unset($_SESSION['_flash']);
            return $flashes;
        }

    /**
     * @FUNC has_flash
     * @brief Check if there are any flash messages (optionally of a specific type)
     * @param string|null $type Optional message type to check
     * @return bool True if flash messages exist
     */
        function has_flash(?string $type = null): bool {
            if ($type === null) {
                return !empty($_SESSION['_flash']);
            }
            return !empty($_SESSION['_flash'][$type]);
        }

    /**
     * @FUNC flash_render
     * @brief Render flash messages as HTML
     * @return string HTML output of flash messages
     */
        function flash_render(): string {
            $flashes = get_flashes();
            if (empty($flashes)) {
                return '';
            }

            $html = '<div class="flash-messages">';
            foreach ($flashes as $type => $messages) {
                foreach ($messages as $message) {
                    $html .= '<div class="flash flash-' . e($type) . '">';
                    $html .= '<span class="flash-message">' . e($message) . '</span>';
                    $html .= '<button class="flash-close" onclick="this.parentElement.remove()">&times;</button>';
                    $html .= '</div>';
                }
            }
            $html .= '</div>';
            return $html;
        }
// ===[/SECTION:flash]===

// ===[SECTION:security]===
// PURPOSE: Set CSRF token and Content Security Policy headers
// DEPENDENCIES: SECTION:session (for $_SESSION)
// EXPORTS: $csrf_token, CSP header
    // csrf
        if (empty($_SESSION["csrf_token"])) {
            $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
        }
        $csrf_token = $_SESSION["csrf_token"];
    // csp
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com https://code.jquery.com https://kit.fontawesome.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://ka-f.fontawesome.com; font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com https://fonts.googleapis.com; img-src 'self' https://*.googleusercontent.com https://i.pravatar.cc data:; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://ka-f.fontawesome.com; frame-src 'self' https://www.youtube.com;");
// ===[/SECTION:security]===

// ===[SECTION:validation]===
// PURPOSE: Centralized validation layer (like Rails ActiveModel::Validations)
// DEPENDENCIES: SECTION:database (for unique/exists rules)
// EXPORTS: validate(), validate_rule()

    /**
     * @FUNC validate
     * @brief Validate data against a set of rules
     * @param array $data Input data to validate
     * @param array $rules Validation rules (field => 'rule1|rule2:param')
     * @return array Array of error messages (empty if valid)
     */
        function validate(array $data, array $rules): array {
            $errors = [];

            foreach ($rules as $field => $rule_string) {
                $rules_list = explode('|', $rule_string);
                $value = $data[$field] ?? null;
                $field_label = ucfirst(str_replace('_', ' ', $field));

                foreach ($rules_list as $rule) {
                    $error = validate_rule($field, $field_label, $value, $rule, $data);
                    if ($error !== null) {
                        $errors[$field][] = $error;
                    }
                }
            }

            return $errors;
        }

    /**
     * @FUNC validate_rule
     * @brief Validate a single field against a single rule
     * @param string $field Field name
     * @param string $label Human-readable field label
     * @param mixed $value Field value
     * @param string $rule Rule string (e.g., 'min:8')
     * @param array $data Full data array (for confirmed rule)
     * @return string|null Error message or null if valid
     */
        function validate_rule(string $field, string $label, mixed $value, string $rule, array $data): ?string {
            // Parse rule and parameter
            $parts = explode(':', $rule, 2);
            $rule_name = $parts[0];
            $param = $parts[1] ?? null;

            switch ($rule_name) {
                case 'required':
                    if ($value === null || $value === '' || (is_array($value) && empty($value))) {
                        return "{$label} is required.";
                    }
                    break;

                case 'email':
                    if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        return "{$label} must be a valid email address.";
                    }
                    break;

                case 'min':
                    if ($value !== null && $value !== '' && strlen((string)$value) < (int)$param) {
                        return "{$label} must be at least {$param} characters.";
                    }
                    break;

                case 'max':
                    if ($value !== null && $value !== '' && strlen((string)$value) > (int)$param) {
                        return "{$label} must not exceed {$param} characters.";
                    }
                    break;

                case 'numeric':
                    if ($value !== null && $value !== '' && !is_numeric($value)) {
                        return "{$label} must be a number.";
                    }
                    break;

                case 'integer':
                    if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_INT)) {
                        return "{$label} must be an integer.";
                    }
                    break;

                case 'confirmed':
                    $confirmation_field = $field . '_confirmation';
                    if ($value !== ($data[$confirmation_field] ?? null)) {
                        return "{$label} confirmation does not match.";
                    }
                    break;

                case 'unique':
                    if ($value !== null && $value !== '' && $param) {
                        $pdo = get_db_connection();
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM {$param} WHERE {$field} = :value");
                        $stmt->execute([':value' => $value]);
                        if ($stmt->fetchColumn() > 0) {
                            return "{$label} is already taken.";
                        }
                    }
                    break;

                case 'exists':
                    if ($value !== null && $value !== '' && $param) {
                        $pdo = get_db_connection();
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM {$param} WHERE {$field} = :value");
                        $stmt->execute([':value' => $value]);
                        if ($stmt->fetchColumn() == 0) {
                            return "{$label} does not exist.";
                        }
                    }
                    break;

                case 'in':
                    if ($value !== null && $value !== '' && $param) {
                        $allowed = explode(',', $param);
                        if (!in_array($value, $allowed, true)) {
                            return "{$label} must be one of: " . implode(', ', $allowed) . ".";
                        }
                    }
                    break;

                case 'regex':
                    if ($value !== null && $value !== '' && $param) {
                        if (!preg_match($param, (string)$value)) {
                            return "{$label} format is invalid.";
                        }
                    }
                    break;

                case 'url':
                    if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_URL)) {
                        return "{$label} must be a valid URL.";
                    }
                    break;

                case 'alpha':
                    if ($value !== null && $value !== '' && !ctype_alpha($value)) {
                        return "{$label} must contain only letters.";
                    }
                    break;

                case 'alphanumeric':
                    if ($value !== null && $value !== '' && !ctype_alnum($value)) {
                        return "{$label} must contain only letters and numbers.";
                    }
                    break;

                case 'date':
                    if ($value !== null && $value !== '') {
                        $date = date_parse($value);
                        if ($date['error_count'] > 0 || !checkdate($date['month'] ?? 0, $date['day'] ?? 0, $date['year'] ?? 0)) {
                            return "{$label} must be a valid date.";
                        }
                    }
                    break;
            }

            return null;
        }

    /**
     * @FUNC validation_errors_flat
     * @brief Flatten validation errors array to a simple list
     * @param array $errors Nested errors array from validate()
     * @return array Flat array of error messages
     */
        function validation_errors_flat(array $errors): array {
            $flat = [];
            foreach ($errors as $field_errors) {
                foreach ($field_errors as $error) {
                    $flat[] = $error;
                }
            }
            return $flat;
        }

    /**
     * @FUNC validation_first_error
     * @brief Get the first validation error for a field
     * @param array $errors Validation errors array
     * @param string $field Field name
     * @return string|null First error message or null
     */
        function validation_first_error(array $errors, string $field): ?string {
            return $errors[$field][0] ?? null;
        }
// ===[/SECTION:validation]===

// ===[SECTION:error]===
// PURPOSE: Setup custom error and exception handlers for dev/production
// DEPENDENCIES: SECTION:config (for SITE_LOG_FILE), SECTION:init (for $is_development)
// EXPORTS: Custom error handlers, getErrorTypeName(), getCodeContext()
    // Setup error log
        $error_log_path = SITE_LOG_FILE;
        if (!file_exists($error_log_path)) {
            touch($error_log_path);
            chmod($error_log_path, 0640);
        }
    /**
     * @FUNC getErrorTypeName
     * @brief Convert PHP error number to human-readable name
     * @param int $errno PHP error constant
     * @return string Human-readable error type name
     */
        function getErrorTypeName($errno) {
            return match ($errno) { E_ERROR => "Fatal Error", E_WARNING => "Warning", E_PARSE => "Parse Error", E_NOTICE => "Notice", E_CORE_ERROR => "Core Error", E_CORE_WARNING => "Core Warning", E_COMPILE_ERROR => "Compile Error", E_COMPILE_WARNING => "Compile Warning", E_USER_ERROR => "User Error", E_USER_WARNING => "User Warning", E_USER_NOTICE => "User Notice", E_RECOVERABLE_ERROR => "Recoverable Error", E_DEPRECATED => "Deprecated", E_USER_DEPRECATED => "User Deprecated", default => "Unknown Error", };
        }
    /**
     * @FUNC getCodeContext
     * @brief Get source code lines surrounding an error location
     * @param string $file Path to the file
     * @param int $line Line number of the error
     * @param int $context_lines Number of lines to show before/after
     * @return string Formatted code context with line numbers
     */
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
// ===[/SECTION:error]===

// ===[SECTION:database]===
// PURPOSE: Database connection, table initialization, and migrations
// DEPENDENCIES: SECTION:config (for SITE_DB_FILE)
// EXPORTS: get_db_connection(), initialize_database(), run_migrations()

    /**
     * @FUNC get_db_connection
     * @brief Create and configure PDO SQLite database connection
     * @return PDO Configured database connection
     */
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
    /**
     * @FUNC initialize_database
     * @brief Create migrations table if it doesn't exist
     * @uses FUNC:get_db_connection
     * @return void
     */
        function initialize_database(): void {
            $pdo = get_db_connection();
            $pdo->exec("CREATE TABLE IF NOT EXISTS migrations (
                    version TEXT UNIQUE NOT NULL,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );");
        }
    /**
     * @FUNC run_migrations
     * @brief Execute pending database migrations
     * @uses FUNC:get_db_connection
     * @return void
     */
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
// ===[/SECTION:database]===

// ===[SECTION:seeds]===
// PURPOSE: Database seeding for development (like Rails db:seed)
// DEPENDENCIES: SECTION:database
// EXPORTS: run_seeds(), seed_table(), get_seeds()

    /**
     * @FUNC get_seeds
     * @brief Get seed data definitions
     * @return array Seed data by table
     */
        function get_seeds(): array {
            return [
                'users' => [
                    [
                        'name' => 'Admin User',
                        'email' => 'admin@example.com',
                        'password' => password_hash('password123', PASSWORD_DEFAULT),
                        'role' => 'admin',
                        'is_paid' => 1,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ],
                    [
                        'name' => 'Demo User',
                        'email' => 'demo@example.com',
                        'password' => password_hash('demo123', PASSWORD_DEFAULT),
                        'role' => 'user',
                        'is_paid' => 0,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ],
                    [
                        'name' => 'Paid User',
                        'email' => 'paid@example.com',
                        'password' => password_hash('paid123', PASSWORD_DEFAULT),
                        'role' => 'user',
                        'is_paid' => 1,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ]
                ],
                'businesses' => [
                    [
                        'user_id' => 1,
                        'name' => 'Demo Business',
                        'description' => 'A sample business for demonstration',
                        'address' => '123 Main St, City, Country',
                        'phone' => '+1 234 567 8900',
                        'email' => 'contact@demobusiness.com',
                        'website' => 'https://demobusiness.com',
                        'status' => 'active',
                        'is_current' => 1,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ]
                ]
            ];
        }

    /**
     * @FUNC seed_table
     * @brief Seed a single table with records
     * @param string $table Table name
     * @param array $records Array of records to insert
     * @return int Number of records inserted
     */
        function seed_table(string $table, array $records): int {
            $pdo = get_db_connection();
            $count = 0;

            foreach ($records as $record) {
                $columns = array_keys($record);
                $placeholders = array_map(fn($col) => ":{$col}", $columns);

                $sql = "INSERT INTO {$table} (" . implode(', ', $columns) . ") VALUES (" . implode(', ', $placeholders) . ")";

                $params = [];
                foreach ($record as $column => $value) {
                    $params[":{$column}"] = $value;
                }

                try {
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute($params);
                    $count++;
                } catch (PDOException $e) {
                    // Skip duplicates (unique constraint violations)
                    if (strpos($e->getMessage(), 'UNIQUE constraint failed') === false) {
                        throw $e;
                    }
                }
            }

            return $count;
        }

    /**
     * @FUNC run_seeds
     * @brief Run all database seeds
     * @param bool $fresh If true, clear tables before seeding
     * @return array Results by table
     */
        function run_seeds(bool $fresh = false): array {
            global $is_development;

            // Only allow seeding in development mode
            if (!$is_development) {
                return ['error' => 'Seeding is only allowed in development mode.'];
            }

            $seeds = get_seeds();
            $results = [];
            $pdo = get_db_connection();

            if ($fresh) {
                // Clear tables in reverse order (to handle foreign keys)
                $tables = array_keys($seeds);
                foreach (array_reverse($tables) as $table) {
                    $pdo->exec("DELETE FROM {$table}");
                    // Reset auto-increment for SQLite
                    $pdo->exec("DELETE FROM sqlite_sequence WHERE name = '{$table}'");
                }
            }

            foreach ($seeds as $table => $records) {
                $count = seed_table($table, $records);
                $results[$table] = $count;
            }

            return $results;
        }

    /**
     * @FUNC is_database_empty
     * @brief Check if database has no user records
     * @return bool True if empty
     */
        function is_database_empty(): bool {
            $pdo = get_db_connection();
            $result = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
            return (int)$result === 0;
        }
// ===[/SECTION:seeds]===

// ===[SECTION:query-builder]===
// PURPOSE: Simple query builder helpers (like Rails ActiveRecord basics)
// DEPENDENCIES: SECTION:database (for get_db_connection)
// EXPORTS: db_find(), db_first(), db_all(), db_insert(), db_update(), db_delete(), db_count(), db_exists()

    /**
     * @FUNC db_find
     * @brief Find a record by its ID
     * @param string $table Table name
     * @param int $id Record ID
     * @return array|null Record data or null if not found
     */
        function db_find(string $table, int $id): ?array {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("SELECT * FROM {$table} WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $id]);
            $result = $stmt->fetch();
            return $result ?: null;
        }

    /**
     * @FUNC db_first
     * @brief Find the first record matching conditions
     * @param string $table Table name
     * @param array $where Associative array of conditions
     * @return array|null Record data or null if not found
     */
        function db_first(string $table, array $where = []): ?array {
            $pdo = get_db_connection();

            $sql = "SELECT * FROM {$table}";
            $params = [];

            if (!empty($where)) {
                $conditions = [];
                foreach ($where as $column => $value) {
                    if ($value === null) {
                        $conditions[] = "{$column} IS NULL";
                    } else {
                        $conditions[] = "{$column} = :{$column}";
                        $params[":{$column}"] = $value;
                    }
                }
                $sql .= " WHERE " . implode(' AND ', $conditions);
            }

            $sql .= " LIMIT 1";

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetch();
            return $result ?: null;
        }

    /**
     * @FUNC db_all
     * @brief Get all records matching conditions
     * @param string $table Table name
     * @param array $where Associative array of conditions
     * @param string $order Order by clause (e.g., 'created_at DESC')
     * @param int $limit Maximum records to return (0 = no limit)
     * @param int $offset Number of records to skip
     * @return array Array of records
     */
        function db_all(string $table, array $where = [], string $order = '', int $limit = 0, int $offset = 0): array {
            $pdo = get_db_connection();

            $sql = "SELECT * FROM {$table}";
            $params = [];

            if (!empty($where)) {
                $conditions = [];
                foreach ($where as $column => $value) {
                    if ($value === null) {
                        $conditions[] = "{$column} IS NULL";
                    } else {
                        $conditions[] = "{$column} = :{$column}";
                        $params[":{$column}"] = $value;
                    }
                }
                $sql .= " WHERE " . implode(' AND ', $conditions);
            }

            if ($order !== '') {
                $sql .= " ORDER BY {$order}";
            }

            if ($limit > 0) {
                $sql .= " LIMIT {$limit}";
                if ($offset > 0) {
                    $sql .= " OFFSET {$offset}";
                }
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll();
        }

    /**
     * @FUNC db_insert
     * @brief Insert a new record and return its ID
     * @param string $table Table name
     * @param array $data Associative array of column => value
     * @return int The new record's ID
     */
        function db_insert(string $table, array $data): int {
            $pdo = get_db_connection();

            // Auto-add timestamps if columns exist
            $now = date('Y-m-d H:i:s');
            if (!isset($data['created_at'])) {
                $data['created_at'] = $now;
            }
            if (!isset($data['updated_at'])) {
                $data['updated_at'] = $now;
            }

            $columns = array_keys($data);
            $placeholders = array_map(fn($col) => ":{$col}", $columns);

            $sql = "INSERT INTO {$table} (" . implode(', ', $columns) . ") VALUES (" . implode(', ', $placeholders) . ")";

            $params = [];
            foreach ($data as $column => $value) {
                $params[":{$column}"] = $value;
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

            return (int) $pdo->lastInsertId();
        }

    /**
     * @FUNC db_update
     * @brief Update a record by ID
     * @param string $table Table name
     * @param int $id Record ID
     * @param array $data Associative array of column => value
     * @return bool True on success
     */
        function db_update(string $table, int $id, array $data): bool {
            $pdo = get_db_connection();

            // Auto-update timestamp
            if (!isset($data['updated_at'])) {
                $data['updated_at'] = date('Y-m-d H:i:s');
            }

            $sets = [];
            $params = [':id' => $id];

            foreach ($data as $column => $value) {
                $sets[] = "{$column} = :{$column}";
                $params[":{$column}"] = $value;
            }

            $sql = "UPDATE {$table} SET " . implode(', ', $sets) . " WHERE id = :id";

            $stmt = $pdo->prepare($sql);
            return $stmt->execute($params);
        }

    /**
     * @FUNC db_delete
     * @brief Delete a record by ID (hard delete)
     * @param string $table Table name
     * @param int $id Record ID
     * @return bool True on success
     */
        function db_delete(string $table, int $id): bool {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("DELETE FROM {$table} WHERE id = :id");
            return $stmt->execute([':id' => $id]);
        }

    /**
     * @FUNC db_count
     * @brief Count records matching conditions
     * @param string $table Table name
     * @param array $where Associative array of conditions
     * @return int Number of matching records
     */
        function db_count(string $table, array $where = []): int {
            $pdo = get_db_connection();

            $sql = "SELECT COUNT(*) FROM {$table}";
            $params = [];

            if (!empty($where)) {
                $conditions = [];
                foreach ($where as $column => $value) {
                    if ($value === null) {
                        $conditions[] = "{$column} IS NULL";
                    } else {
                        $conditions[] = "{$column} = :{$column}";
                        $params[":{$column}"] = $value;
                    }
                }
                $sql .= " WHERE " . implode(' AND ', $conditions);
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return (int) $stmt->fetchColumn();
        }

    /**
     * @FUNC db_exists
     * @brief Check if a record exists matching conditions
     * @param string $table Table name
     * @param array $where Associative array of conditions
     * @return bool True if record exists
     */
        function db_exists(string $table, array $where): bool {
            return db_count($table, $where) > 0;
        }

    /**
     * @FUNC db_query
     * @brief Execute a raw SQL query with parameters
     * @param string $sql SQL query with placeholders
     * @param array $params Associative array of parameters
     * @return array Array of results
     */
        function db_query(string $sql, array $params = []): array {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll();
        }

    /**
     * @FUNC db_execute
     * @brief Execute a raw SQL statement (INSERT, UPDATE, DELETE)
     * @param string $sql SQL statement with placeholders
     * @param array $params Associative array of parameters
     * @return int Number of affected rows
     */
        function db_execute(string $sql, array $params = []): int {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->rowCount();
        }

    // ========== SOFT DELETES ==========
    // Convention: tables with soft deletes have a `deleted_at` column

    /**
     * @FUNC db_soft_delete
     * @brief Soft delete a record by setting deleted_at timestamp
     * @param string $table Table name
     * @param int $id Record ID
     * @return bool True on success
     */
        function db_soft_delete(string $table, int $id): bool {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');
            $stmt = $pdo->prepare("UPDATE {$table} SET deleted_at = :deleted_at, updated_at = :updated_at WHERE id = :id");
            return $stmt->execute([':id' => $id, ':deleted_at' => $now, ':updated_at' => $now]);
        }

    /**
     * @FUNC db_restore
     * @brief Restore a soft-deleted record
     * @param string $table Table name
     * @param int $id Record ID
     * @return bool True on success
     */
        function db_restore(string $table, int $id): bool {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("UPDATE {$table} SET deleted_at = NULL, updated_at = :updated_at WHERE id = :id");
            return $stmt->execute([':id' => $id, ':updated_at' => date('Y-m-d H:i:s')]);
        }

    /**
     * @FUNC db_all_with_deleted
     * @brief Get all records including soft-deleted ones
     * @param string $table Table name
     * @param array $where Conditions
     * @param string $order Order by clause
     * @param int $limit Limit
     * @return array Array of records
     */
        function db_all_with_deleted(string $table, array $where = [], string $order = '', int $limit = 0): array {
            $pdo = get_db_connection();

            $sql = "SELECT * FROM {$table}";
            $params = [];

            if (!empty($where)) {
                $conditions = [];
                foreach ($where as $column => $value) {
                    if ($value === null) {
                        $conditions[] = "{$column} IS NULL";
                    } else {
                        $conditions[] = "{$column} = :{$column}";
                        $params[":{$column}"] = $value;
                    }
                }
                $sql .= " WHERE " . implode(' AND ', $conditions);
            }

            if ($order !== '') {
                $sql .= " ORDER BY {$order}";
            }

            if ($limit > 0) {
                $sql .= " LIMIT {$limit}";
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll();
        }

    /**
     * @FUNC db_only_deleted
     * @brief Get only soft-deleted records
     * @param string $table Table name
     * @param array $where Additional conditions
     * @return array Array of deleted records
     */
        function db_only_deleted(string $table, array $where = []): array {
            $pdo = get_db_connection();

            $sql = "SELECT * FROM {$table} WHERE deleted_at IS NOT NULL";
            $params = [];

            if (!empty($where)) {
                foreach ($where as $column => $value) {
                    if ($value === null) {
                        $sql .= " AND {$column} IS NULL";
                    } else {
                        $sql .= " AND {$column} = :{$column}";
                        $params[":{$column}"] = $value;
                    }
                }
            }

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll();
        }

    /**
     * @FUNC db_force_delete
     * @brief Permanently delete a record (bypasses soft delete)
     * @param string $table Table name
     * @param int $id Record ID
     * @return bool True on success
     */
        function db_force_delete(string $table, int $id): bool {
            return db_delete($table, $id);
        }

    /**
     * @FUNC db_is_deleted
     * @brief Check if a record is soft-deleted
     * @param string $table Table name
     * @param int $id Record ID
     * @return bool True if deleted
     */
        function db_is_deleted(string $table, int $id): bool {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("SELECT deleted_at FROM {$table} WHERE id = :id");
            $stmt->execute([':id' => $id]);
            $record = $stmt->fetch();
            return $record && $record['deleted_at'] !== null;
        }
// ===[/SECTION:query-builder]===

// ===[SECTION:rate-limit]===
// PURPOSE: Rate limiting to prevent brute force attacks (like Rails Rack::Attack)
// DEPENDENCIES: SECTION:database, SECTION:query-builder
// EXPORTS: rate_limit(), rate_limit_hit(), rate_limit_clear(), rate_limit_cleanup()

    /**
     * @FUNC rate_limit_init
     * @brief Create rate_limits table if it doesn't exist
     * @return void
     */
        function rate_limit_init(): void {
            $pdo = get_db_connection();
            $pdo->exec("CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                identifier TEXT NOT NULL,
                attempts INTEGER DEFAULT 1,
                first_attempt_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE(action, identifier)
            )");
        }
        rate_limit_init();

    /**
     * @FUNC rate_limit
     * @brief Check if an action is rate limited
     * @param string $action Action name (e.g., 'login', 'api')
     * @param string $identifier Identifier (IP, user_id, etc.)
     * @param int $max_attempts Maximum attempts allowed
     * @param int $decay_seconds Time window in seconds
     * @return bool True if limited (block action), false if allowed
     */
        function rate_limit(string $action, string $identifier, int $max_attempts = 5, int $decay_seconds = 300): bool {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');

            // Clean up expired entries
            $pdo->prepare("DELETE FROM rate_limits WHERE expires_at < :now")
                ->execute([':now' => $now]);

            // Check current attempts
            $stmt = $pdo->prepare("SELECT attempts FROM rate_limits WHERE action = :action AND identifier = :identifier");
            $stmt->execute([':action' => $action, ':identifier' => $identifier]);
            $record = $stmt->fetch();

            if ($record && (int)$record['attempts'] >= $max_attempts) {
                return true; // Rate limited
            }

            return false; // Not limited
        }

    /**
     * @FUNC rate_limit_hit
     * @brief Record an attempt for rate limiting
     * @param string $action Action name
     * @param string $identifier Identifier
     * @param int $decay_seconds Time window
     * @return int Current attempt count
     */
        function rate_limit_hit(string $action, string $identifier, int $decay_seconds = 300): int {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');
            $expires_at = date('Y-m-d H:i:s', time() + $decay_seconds);

            // Try to update existing record
            $stmt = $pdo->prepare("UPDATE rate_limits SET attempts = attempts + 1, expires_at = :expires_at
                                   WHERE action = :action AND identifier = :identifier");
            $stmt->execute([
                ':action' => $action,
                ':identifier' => $identifier,
                ':expires_at' => $expires_at
            ]);

            if ($stmt->rowCount() === 0) {
                // Insert new record
                $stmt = $pdo->prepare("INSERT INTO rate_limits (action, identifier, attempts, first_attempt_at, expires_at)
                                       VALUES (:action, :identifier, 1, :now, :expires_at)");
                $stmt->execute([
                    ':action' => $action,
                    ':identifier' => $identifier,
                    ':now' => $now,
                    ':expires_at' => $expires_at
                ]);
                return 1;
            }

            // Get current count
            $stmt = $pdo->prepare("SELECT attempts FROM rate_limits WHERE action = :action AND identifier = :identifier");
            $stmt->execute([':action' => $action, ':identifier' => $identifier]);
            $record = $stmt->fetch();
            return (int)($record['attempts'] ?? 0);
        }

    /**
     * @FUNC rate_limit_clear
     * @brief Clear rate limit for an action and identifier
     * @param string $action Action name
     * @param string $identifier Identifier
     * @return void
     */
        function rate_limit_clear(string $action, string $identifier): void {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE action = :action AND identifier = :identifier");
            $stmt->execute([':action' => $action, ':identifier' => $identifier]);
        }

    /**
     * @FUNC rate_limit_remaining
     * @brief Get remaining attempts before rate limit
     * @param string $action Action name
     * @param string $identifier Identifier
     * @param int $max_attempts Maximum attempts allowed
     * @return int Remaining attempts
     */
        function rate_limit_remaining(string $action, string $identifier, int $max_attempts = 5): int {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("SELECT attempts FROM rate_limits WHERE action = :action AND identifier = :identifier");
            $stmt->execute([':action' => $action, ':identifier' => $identifier]);
            $record = $stmt->fetch();

            if (!$record) {
                return $max_attempts;
            }

            return max(0, $max_attempts - (int)$record['attempts']);
        }

    /**
     * @FUNC rate_limit_retry_after
     * @brief Get seconds until rate limit expires
     * @param string $action Action name
     * @param string $identifier Identifier
     * @return int Seconds until retry allowed (0 if not limited)
     */
        function rate_limit_retry_after(string $action, string $identifier): int {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("SELECT expires_at FROM rate_limits WHERE action = :action AND identifier = :identifier");
            $stmt->execute([':action' => $action, ':identifier' => $identifier]);
            $record = $stmt->fetch();

            if (!$record) {
                return 0;
            }

            $expires = strtotime($record['expires_at']);
            $now = time();

            return max(0, $expires - $now);
        }
// ===[/SECTION:rate-limit]===

// ===[SECTION:password-reset]===
// PURPOSE: Password reset token flow (like Rails has_secure_password)
// DEPENDENCIES: SECTION:database, SECTION:query-builder
// EXPORTS: password_reset_init(), create_password_reset(), validate_reset_token(), complete_password_reset()

    /**
     * @FUNC password_reset_init
     * @brief Create password_resets table if it doesn't exist
     * @return void
     */
        function password_reset_init(): void {
            $pdo = get_db_connection();
            $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )");
        }
        password_reset_init();

    /**
     * @FUNC create_password_reset
     * @brief Generate a password reset token for an email
     * @param string $email User's email address
     * @param int $expires_hours Hours until token expires (default 1)
     * @return string|null Token if user exists, null otherwise
     */
        function create_password_reset(string $email, int $expires_hours = 1): ?string {
            // Check if user exists
            $user = db_first('users', ['email' => $email]);
            if (!$user) {
                return null;
            }

            $pdo = get_db_connection();

            // Delete any existing tokens for this email
            $stmt = $pdo->prepare("DELETE FROM password_resets WHERE email = :email");
            $stmt->execute([':email' => $email]);

            // Generate new token
            $token = bin2hex(random_bytes(32));
            $expires_at = date('Y-m-d H:i:s', time() + ($expires_hours * 3600));

            // Insert new token
            $stmt = $pdo->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (:email, :token, :expires_at)");
            $stmt->execute([
                ':email' => $email,
                ':token' => $token,
                ':expires_at' => $expires_at
            ]);

            return $token;
        }

    /**
     * @FUNC validate_reset_token
     * @brief Check if a password reset token is valid
     * @param string $token The reset token
     * @return array|null Token record if valid, null otherwise
     */
        function validate_reset_token(string $token): ?array {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');

            $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE token = :token AND expires_at > :now");
            $stmt->execute([':token' => $token, ':now' => $now]);
            $record = $stmt->fetch();

            return $record ?: null;
        }

    /**
     * @FUNC complete_password_reset
     * @brief Reset password using a valid token
     * @param string $token The reset token
     * @param string $new_password The new password
     * @return bool True if successful, false otherwise
     */
        function complete_password_reset(string $token, string $new_password): bool {
            $reset = validate_reset_token($token);
            if (!$reset) {
                return false;
            }

            $pdo = get_db_connection();

            // Update user's password
            $hashed = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password = :password, updated_at = :updated_at WHERE email = :email");
            $result = $stmt->execute([
                ':password' => $hashed,
                ':email' => $reset['email'],
                ':updated_at' => date('Y-m-d H:i:s')
            ]);

            if ($result) {
                // Delete the used token
                $stmt = $pdo->prepare("DELETE FROM password_resets WHERE token = :token");
                $stmt->execute([':token' => $token]);
                return true;
            }

            return false;
        }

    /**
     * @FUNC password_reset_url
     * @brief Generate the password reset URL
     * @param string $token The reset token
     * @return string Full reset URL
     */
        function password_reset_url(string $token): string {
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? SITE_DOMAIN;
            return "{$protocol}://{$host}/reset-password?token=" . urlencode($token);
        }

    /**
     * @FUNC cleanup_expired_resets
     * @brief Remove expired password reset tokens
     * @return int Number of deleted tokens
     */
        function cleanup_expired_resets(): int {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');
            $stmt = $pdo->prepare("DELETE FROM password_resets WHERE expires_at < :now");
            $stmt->execute([':now' => $now]);
            return $stmt->rowCount();
        }
// ===[/SECTION:password-reset]===

// ===[SECTION:remember-me]===
// PURPOSE: Persistent "remember me" login tokens (like Rails remember_token)
// DEPENDENCIES: SECTION:database, SECTION:query-builder
// EXPORTS: remember_me_init(), create_remember_token(), validate_remember_token(), clear_remember_token()

    /**
     * @FUNC remember_me_init
     * @brief Create remember_tokens table if it doesn't exist
     * @return void
     */
        function remember_me_init(): void {
            $pdo = get_db_connection();
            $pdo->exec("CREATE TABLE IF NOT EXISTS remember_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )");
        }
        remember_me_init();

    /**
     * @FUNC create_remember_token
     * @brief Create a persistent login token and set cookie
     * @param int $user_id User's ID
     * @param int $days Days until expiry (default 30)
     * @return string The generated token
     */
        function create_remember_token(int $user_id, int $days = 30): string {
            $pdo = get_db_connection();

            // Generate secure token
            $token = bin2hex(random_bytes(32));
            $expires_at = date('Y-m-d H:i:s', time() + ($days * 86400));

            // Store in database
            $stmt = $pdo->prepare("INSERT INTO remember_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)");
            $stmt->execute([
                ':user_id' => $user_id,
                ':token' => $token,
                ':expires_at' => $expires_at
            ]);

            // Set cookie
            $cookie_domain = SITE_DOMAIN === 'localhost' ? '' : SITE_DOMAIN;
            setcookie(
                'remember_token',
                $token,
                [
                    'expires' => time() + ($days * 86400),
                    'path' => '/',
                    'domain' => $cookie_domain,
                    'secure' => isset($_SERVER['HTTPS']),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );

            return $token;
        }

    /**
     * @FUNC validate_remember_token
     * @brief Check cookie and auto-login if valid
     * @return array|null User data if valid, null otherwise
     */
        function validate_remember_token(): ?array {
            if (!isset($_COOKIE['remember_token'])) {
                return null;
            }

            $token = $_COOKIE['remember_token'];
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');

            // Find valid token
            $stmt = $pdo->prepare("SELECT user_id FROM remember_tokens WHERE token = :token AND expires_at > :now");
            $stmt->execute([':token' => $token, ':now' => $now]);
            $record = $stmt->fetch();

            if (!$record) {
                // Invalid token, clear cookie
                clear_remember_token();
                return null;
            }

            // Get user data
            $user = db_find('users', (int)$record['user_id']);
            if (!$user) {
                clear_remember_token();
                return null;
            }

            return $user;
        }

    /**
     * @FUNC clear_remember_token
     * @brief Remove remember token from database and clear cookie
     * @return void
     */
        function clear_remember_token(): void {
            if (isset($_COOKIE['remember_token'])) {
                $token = $_COOKIE['remember_token'];

                // Delete from database
                $pdo = get_db_connection();
                $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE token = :token");
                $stmt->execute([':token' => $token]);
            }

            // Clear cookie
            $cookie_domain = SITE_DOMAIN === 'localhost' ? '' : SITE_DOMAIN;
            setcookie(
                'remember_token',
                '',
                [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => $cookie_domain,
                    'secure' => isset($_SERVER['HTTPS']),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]
            );
        }

    /**
     * @FUNC clear_all_remember_tokens
     * @brief Remove all remember tokens for a user (logout everywhere)
     * @param int $user_id User's ID
     * @return int Number of deleted tokens
     */
        function clear_all_remember_tokens(int $user_id): int {
            $pdo = get_db_connection();
            $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);
            return $stmt->rowCount();
        }

    /**
     * @FUNC cleanup_expired_remember_tokens
     * @brief Remove expired remember tokens
     * @return int Number of deleted tokens
     */
        function cleanup_expired_remember_tokens(): int {
            $pdo = get_db_connection();
            $now = date('Y-m-d H:i:s');
            $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE expires_at < :now");
            $stmt->execute([':now' => $now]);
            return $stmt->rowCount();
        }
// ===[/SECTION:remember-me]===

// ===[SECTION:logging]===
// PURPOSE: Structured logging with levels (like Rails.logger)
// DEPENDENCIES: SECTION:config (for SITE_LOG_FILE)
// EXPORTS: log_debug(), log_info(), log_warning(), log_error(), log_write()

    /**
     * @FUNC log_write
     * @brief Internal log writer with level and context
     * @param string $level Log level (DEBUG, INFO, WARNING, ERROR)
     * @param string $message Log message
     * @param array $context Additional context data
     * @return void
     */
        function log_write(string $level, string $message, array $context = []): void {
            $log_file = SITE_LOG_FILE;
            $date = date('Y-m-d H:i:s');
            $context_str = !empty($context) ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES) : '';

            $log_entry = "[{$date}] [{$level}] {$message}{$context_str}" . PHP_EOL;

            file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
        }

    /**
     * @FUNC log_debug
     * @brief Log debug-level message
     * @param string $message Log message
     * @param array $context Additional context
     * @return void
     */
        function log_debug(string $message, array $context = []): void {
            global $is_development;
            // Only log debug in development mode
            if ($is_development) {
                log_write('DEBUG', $message, $context);
            }
        }

    /**
     * @FUNC log_info
     * @brief Log info-level message
     * @param string $message Log message
     * @param array $context Additional context
     * @return void
     */
        function log_info(string $message, array $context = []): void {
            log_write('INFO', $message, $context);
        }

    /**
     * @FUNC log_warning
     * @brief Log warning-level message
     * @param string $message Log message
     * @param array $context Additional context
     * @return void
     */
        function log_warning(string $message, array $context = []): void {
            log_write('WARNING', $message, $context);
        }

    /**
     * @FUNC log_error
     * @brief Log error-level message
     * @param string $message Log message
     * @param array $context Additional context
     * @return void
     */
        function log_error(string $message, array $context = []): void {
            log_write('ERROR', $message, $context);
        }

    /**
     * @FUNC log_exception
     * @brief Log an exception with stack trace
     * @param Throwable $e The exception
     * @param array $context Additional context
     * @return void
     */
        function log_exception(Throwable $e, array $context = []): void {
            $context = array_merge($context, [
                'exception' => get_class($e),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ]);
            log_error($e->getMessage(), $context);
        }

    /**
     * @FUNC log_request
     * @brief Log current HTTP request details
     * @param array $extra Extra data to include
     * @return void
     */
        function log_request(array $extra = []): void {
            $context = array_merge([
                'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ], $extra);
            log_info('HTTP Request', $context);
        }
// ===[/SECTION:logging]===

// ===[SECTION:cache]===
// PURPOSE: Simple file-based caching (like Rails.cache)
// DEPENDENCIES: SECTION:config
// EXPORTS: cache_get(), cache_set(), cache_has(), cache_forget(), cache_flush(), cache_remember()

    // Cache directory
    define('CACHE_DIR', __DIR__ . '/../cache');

    /**
     * @FUNC cache_init
     * @brief Create cache directory if it doesn't exist
     * @return void
     */
        function cache_init(): void {
            if (!is_dir(CACHE_DIR)) {
                mkdir(CACHE_DIR, 0755, true);
            }
        }
        cache_init();

    /**
     * @FUNC cache_key_to_path
     * @brief Convert cache key to file path
     * @param string $key Cache key
     * @return string File path
     */
        function cache_key_to_path(string $key): string {
            $safe_key = preg_replace('/[^a-zA-Z0-9_-]/', '_', $key);
            return CACHE_DIR . '/' . $safe_key . '.cache';
        }

    /**
     * @FUNC cache_get
     * @brief Get value from cache
     * @param string $key Cache key
     * @param mixed $default Default value if not found/expired
     * @return mixed Cached value or default
     */
        function cache_get(string $key, mixed $default = null): mixed {
            $path = cache_key_to_path($key);

            if (!file_exists($path)) {
                return $default;
            }

            $content = file_get_contents($path);
            $data = unserialize($content);

            // Check expiration
            if ($data['expires_at'] !== null && time() > $data['expires_at']) {
                unlink($path);
                return $default;
            }

            return $data['value'];
        }

    /**
     * @FUNC cache_set
     * @brief Store value in cache
     * @param string $key Cache key
     * @param mixed $value Value to cache
     * @param int $ttl Time to live in seconds (0 = forever)
     * @return bool Success
     */
        function cache_set(string $key, mixed $value, int $ttl = 3600): bool {
            $path = cache_key_to_path($key);
            $expires_at = $ttl > 0 ? time() + $ttl : null;

            $data = [
                'value' => $value,
                'expires_at' => $expires_at,
                'created_at' => time()
            ];

            return file_put_contents($path, serialize($data), LOCK_EX) !== false;
        }

    /**
     * @FUNC cache_has
     * @brief Check if cache key exists and is not expired
     * @param string $key Cache key
     * @return bool True if exists and valid
     */
        function cache_has(string $key): bool {
            $path = cache_key_to_path($key);

            if (!file_exists($path)) {
                return false;
            }

            $content = file_get_contents($path);
            $data = unserialize($content);

            if ($data['expires_at'] !== null && time() > $data['expires_at']) {
                unlink($path);
                return false;
            }

            return true;
        }

    /**
     * @FUNC cache_forget
     * @brief Remove item from cache
     * @param string $key Cache key
     * @return bool True if deleted
     */
        function cache_forget(string $key): bool {
            $path = cache_key_to_path($key);

            if (file_exists($path)) {
                return unlink($path);
            }

            return false;
        }

    /**
     * @FUNC cache_flush
     * @brief Clear all cached items
     * @return int Number of items deleted
     */
        function cache_flush(): int {
            $count = 0;
            $files = glob(CACHE_DIR . '/*.cache');

            foreach ($files as $file) {
                if (unlink($file)) {
                    $count++;
                }
            }

            return $count;
        }

    /**
     * @FUNC cache_remember
     * @brief Get from cache or compute and store
     * @param string $key Cache key
     * @param int $ttl Time to live in seconds
     * @param callable $callback Function to compute value if not cached
     * @return mixed Cached or computed value
     */
        function cache_remember(string $key, int $ttl, callable $callback): mixed {
            if (cache_has($key)) {
                return cache_get($key);
            }

            $value = $callback();
            cache_set($key, $value, $ttl);
            return $value;
        }

    /**
     * @FUNC cache_increment
     * @brief Increment a numeric cache value
     * @param string $key Cache key
     * @param int $amount Amount to increment
     * @return int New value
     */
        function cache_increment(string $key, int $amount = 1): int {
            $value = (int)cache_get($key, 0);
            $value += $amount;
            cache_set($key, $value, 0); // No expiration on increment
            return $value;
        }

    /**
     * @FUNC cache_decrement
     * @brief Decrement a numeric cache value
     * @param string $key Cache key
     * @param int $amount Amount to decrement
     * @return int New value
     */
        function cache_decrement(string $key, int $amount = 1): int {
            return cache_increment($key, -$amount);
        }
// ===[/SECTION:cache]===

// ===[SECTION:api]===
// PURPOSE: JSON API response helpers (like Rails API mode)
// DEPENDENCIES: SECTION:helpers
// EXPORTS: api_response(), api_error(), api_paginate(), is_api_request(), api_cors()

    /**
     * @FUNC is_api_request
     * @brief Check if current request expects JSON response
     * @return bool True if API request
     */
        function is_api_request(): bool {
            $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
            $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
            $uri = $_SERVER['REQUEST_URI'] ?? '';

            return str_contains($accept, 'application/json') ||
                   str_contains($content_type, 'application/json') ||
                   str_starts_with($uri, '/api/');
        }

    /**
     * @FUNC api_cors
     * @brief Set CORS headers for API responses
     * @param string $origin Allowed origin (default: *)
     * @param array $methods Allowed methods
     * @return void
     */
        function api_cors(string $origin = '*', array $methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']): void {
            header("Access-Control-Allow-Origin: {$origin}");
            header("Access-Control-Allow-Methods: " . implode(', ', $methods));
            header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
            header("Access-Control-Max-Age: 86400");

            // Handle preflight
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                http_response_code(204);
                exit();
            }
        }

    /**
     * @FUNC api_response
     * @brief Send JSON API response
     * @param mixed $data Response data
     * @param int $status HTTP status code
     * @return never
     */
        function api_response(mixed $data, int $status = 200): never {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            exit();
        }

    /**
     * @FUNC api_success
     * @brief Send success response with data
     * @param mixed $data Response data
     * @param string|null $message Success message
     * @param int $status HTTP status code
     * @return never
     */
        function api_success(mixed $data = null, ?string $message = null, int $status = 200): never {
            $response = ['success' => true];
            if ($message !== null) {
                $response['message'] = $message;
            }
            if ($data !== null) {
                $response['data'] = $data;
            }
            api_response($response, $status);
        }

    /**
     * @FUNC api_error
     * @brief Send error response
     * @param string $message Error message
     * @param int $status HTTP status code
     * @param array $errors Validation errors
     * @return never
     */
        function api_error(string $message, int $status = 400, array $errors = []): never {
            $response = [
                'success' => false,
                'error' => $message
            ];
            if (!empty($errors)) {
                $response['errors'] = $errors;
            }
            api_response($response, $status);
        }

    /**
     * @FUNC api_paginate
     * @brief Send paginated response
     * @param array $data Items for current page
     * @param int $total Total number of items
     * @param int $page Current page number
     * @param int $per_page Items per page
     * @return never
     */
        function api_paginate(array $data, int $total, int $page = 1, int $per_page = 15): never {
            $last_page = (int)ceil($total / $per_page);

            api_response([
                'success' => true,
                'data' => $data,
                'meta' => [
                    'current_page' => $page,
                    'per_page' => $per_page,
                    'total' => $total,
                    'last_page' => $last_page,
                    'from' => ($page - 1) * $per_page + 1,
                    'to' => min($page * $per_page, $total)
                ]
            ]);
        }

    /**
     * @FUNC api_input
     * @brief Get JSON input from request body
     * @return array Decoded JSON data
     */
        function api_input(): array {
            $json = file_get_contents('php://input');
            return json_decode($json, true) ?? [];
        }

    /**
     * @FUNC api_auth_check
     * @brief Check API authentication (session-based)
     * @return void Dies with 401 if not authenticated
     */
        function api_auth_check(): void {
            if (!isset($_SESSION['user'])) {
                api_error('Unauthorized', 401);
            }
        }
// ===[/SECTION:api]===

// ===[SECTION:authorization]===
// PURPOSE: Policy-based authorization (like Rails Pundit/CanCanCan)
// DEPENDENCIES: SECTION:helpers (for get_user)
// EXPORTS: define_policy(), can(), cannot(), authorize()

    // Global policies storage
    $GLOBALS['_policies'] = [];

    /**
     * @FUNC define_policy
     * @brief Register an authorization policy
     * @param string $ability Ability name (e.g., 'business.edit')
     * @param callable $callback Function(user, ...args) returning bool
     * @return void
     */
        function define_policy(string $ability, callable $callback): void {
            $GLOBALS['_policies'][$ability] = $callback;
        }

    /**
     * @FUNC can
     * @brief Check if current user can perform ability
     * @param string $ability Ability name
     * @param mixed ...$args Additional arguments for policy
     * @return bool True if authorized
     */
        function can(string $ability, mixed ...$args): bool {
            // Get current user
            $user = $_SESSION['user'] ?? null;

            // No user = no permissions
            if (!$user) {
                return false;
            }

            // Check if policy exists
            if (!isset($GLOBALS['_policies'][$ability])) {
                // No policy defined = denied by default
                return false;
            }

            // Call the policy with user and arguments
            return (bool)call_user_func($GLOBALS['_policies'][$ability], $user, ...$args);
        }

    /**
     * @FUNC cannot
     * @brief Check if current user cannot perform ability
     * @param string $ability Ability name
     * @param mixed ...$args Additional arguments for policy
     * @return bool True if NOT authorized
     */
        function cannot(string $ability, mixed ...$args): bool {
            return !can($ability, ...$args);
        }

    /**
     * @FUNC authorize
     * @brief Authorize or die/redirect with error
     * @param string $ability Ability name
     * @param mixed ...$args Additional arguments for policy
     * @return void Dies if not authorized
     */
        function authorize(string $ability, mixed ...$args): void {
            if (cannot($ability, ...$args)) {
                if (is_api_request()) {
                    api_error('Forbidden', 403);
                } else {
                    flash('error', 'You are not authorized to perform this action.');
                    redirect('/');
                }
            }
        }

    /**
     * @FUNC is_admin
     * @brief Check if current user is admin
     * @return bool True if admin
     */
        function is_admin(): bool {
            $user = $_SESSION['user'] ?? null;
            return $user && ($user['role'] ?? '') === 'admin';
        }

    /**
     * @FUNC is_owner
     * @brief Check if current user owns a resource
     * @param array $resource Resource with user_id field
     * @return bool True if owner
     */
        function is_owner(array $resource): bool {
            $user = $_SESSION['user'] ?? null;
            return $user && isset($resource['user_id']) && (int)$user['id'] === (int)$resource['user_id'];
        }

    // ========== DEFAULT POLICIES ==========
    // These can be overridden or extended

    // Admin can do anything
    define_policy('admin.*', fn($user) => ($user['role'] ?? '') === 'admin');

    // Business policies
    define_policy('business.view', fn($user, $business) =>
        (int)$user['id'] === (int)$business['user_id'] || ($user['role'] ?? '') === 'admin'
    );

    define_policy('business.edit', fn($user, $business) =>
        (int)$user['id'] === (int)$business['user_id']
    );

    define_policy('business.delete', fn($user, $business) =>
        (int)$user['id'] === (int)$business['user_id'] || ($user['role'] ?? '') === 'admin'
    );
// ===[/SECTION:authorization]===

// ===[SECTION:uploads]===
// PURPOSE: File upload handling (like Rails ActiveStorage)
// DEPENDENCIES: SECTION:helpers
// EXPORTS: upload_file(), delete_uploaded_file(), get_upload_url()

    // Upload directory
    define('UPLOAD_DIR', __DIR__ . '/uploads');

    /**
     * @FUNC upload_init
     * @brief Create uploads directory if it doesn't exist
     * @return void
     */
        function upload_init(): void {
            if (!is_dir(UPLOAD_DIR)) {
                mkdir(UPLOAD_DIR, 0755, true);
            }
        }
        upload_init();

    /**
     * @FUNC upload_file
     * @brief Upload a file with validation
     * @param array $file $_FILES array element
     * @param string $directory Subdirectory within uploads
     * @param array $allowed_extensions Allowed file extensions
     * @param int $max_size Maximum file size in bytes
     * @return string|array Path on success, errors array on failure
     */
        function upload_file(
            array $file,
            string $directory = '',
            array $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'],
            int $max_size = 5242880 // 5MB
        ): string|array {
            $errors = [];

            // Check for upload errors
            if ($file['error'] !== UPLOAD_ERR_OK) {
                return ['Upload failed: ' . upload_error_message($file['error'])];
            }

            // Check file size
            if ($file['size'] > $max_size) {
                $max_mb = round($max_size / 1048576, 1);
                return ["File size exceeds maximum allowed ({$max_mb}MB)."];
            }

            // Get and validate extension
            $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($extension, $allowed_extensions)) {
                return ['File type not allowed. Allowed: ' . implode(', ', $allowed_extensions)];
            }

            // Create target directory
            $target_dir = UPLOAD_DIR;
            if ($directory !== '') {
                $target_dir .= '/' . trim($directory, '/');
                if (!is_dir($target_dir)) {
                    mkdir($target_dir, 0755, true);
                }
            }

            // Generate unique filename
            $filename = bin2hex(random_bytes(16)) . '.' . $extension;
            $target_path = $target_dir . '/' . $filename;

            // Move uploaded file
            if (!move_uploaded_file($file['tmp_name'], $target_path)) {
                return ['Failed to save uploaded file.'];
            }

            // Return relative path from uploads
            $relative_path = '/uploads';
            if ($directory !== '') {
                $relative_path .= '/' . trim($directory, '/');
            }
            $relative_path .= '/' . $filename;

            return $relative_path;
        }

    /**
     * @FUNC upload_error_message
     * @brief Get human-readable upload error message
     * @param int $error_code PHP upload error code
     * @return string Error message
     */
        function upload_error_message(int $error_code): string {
            return match($error_code) {
                UPLOAD_ERR_INI_SIZE => 'File exceeds server upload limit.',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form upload limit.',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded.',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder.',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
                UPLOAD_ERR_EXTENSION => 'Upload blocked by extension.',
                default => 'Unknown upload error.'
            };
        }

    /**
     * @FUNC delete_uploaded_file
     * @brief Delete an uploaded file
     * @param string $path Relative path from uploads
     * @return bool True if deleted
     */
        function delete_uploaded_file(string $path): bool {
            // Convert relative path to absolute
            $absolute_path = __DIR__ . $path;

            // Security check: ensure path is within uploads
            $real_path = realpath($absolute_path);
            $upload_real = realpath(UPLOAD_DIR);

            if ($real_path === false || !str_starts_with($real_path, $upload_real)) {
                return false;
            }

            if (file_exists($real_path)) {
                return unlink($real_path);
            }

            return false;
        }

    /**
     * @FUNC get_upload_url
     * @brief Get full URL for uploaded file
     * @param string $path Relative path
     * @return string Full URL
     */
        function get_upload_url(string $path): string {
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? SITE_DOMAIN;
            return "{$protocol}://{$host}{$path}";
        }

    /**
     * @FUNC upload_image
     * @brief Upload an image file (convenience wrapper)
     * @param array $file $_FILES array element
     * @param string $directory Subdirectory
     * @param int $max_size Maximum size
     * @return string|array Path or errors
     */
        function upload_image(array $file, string $directory = 'images', int $max_size = 5242880): string|array {
            return upload_file($file, $directory, ['jpg', 'jpeg', 'png', 'gif', 'webp'], $max_size);
        }

    /**
     * @FUNC upload_document
     * @brief Upload a document file (convenience wrapper)
     * @param array $file $_FILES array element
     * @param string $directory Subdirectory
     * @param int $max_size Maximum size
     * @return string|array Path or errors
     */
        function upload_document(array $file, string $directory = 'documents', int $max_size = 10485760): string|array {
            return upload_file($file, $directory, ['pdf', 'doc', 'docx', 'txt', 'csv', 'xlsx'], $max_size);
        }
// ===[/SECTION:uploads]===

// ===[SECTION:helpers]===
// PURPOSE: Utility functions for HTML escaping, input sanitization, CSRF, redirects
// DEPENDENCIES: SECTION:session (for $_SESSION)
// EXPORTS: e(), sanitize_input(), csrf_token(), csrf_field(), redirect()

    /**
     * @FUNC e
     * @brief Escape string for safe HTML output
     * @param string|null $string Input string
     * @return string HTML-escaped string
     */
        function e(?string $string): string {
            return htmlspecialchars((string) $string, ENT_QUOTES, "UTF-8");
        }
    /**
     * @FUNC sanitize_input
     * @brief Sanitize array data to prevent XSS attacks
     * @param array $data Input data array
     * @return array Sanitized data array
     */
        function sanitize_input(array $data): array {
            $sanitized = [];
            foreach ($data as $key => $value) {
                $sanitized[$key] = is_string($value) ? trim(strip_tags($value)) : $value;
            }
            return $sanitized;
        }
    /**
     * @FUNC csrf_token
     * @brief Get current CSRF token from session
     * @return string CSRF token
     */
        function csrf_token(): string {
            return $_SESSION['csrf_token'];
        }
    /**
     * @FUNC csrf_field
     * @brief Generate hidden input field with CSRF token
     * @uses FUNC:csrf_token, FUNC:e
     * @return string HTML hidden input element
     */
        function csrf_field(): string {
            return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
        }
    /**
     * @FUNC redirect
     * @brief Redirect to URL and exit script
     * @param string $url Target URL
     * @return void (exits)
     */
        function redirect(string $url): void {
            header("Location: $url");
            exit();
        }
// ===[/SECTION:helpers]===

// ===[SECTION:form-helpers]===
// PURPOSE: Form generation helpers (like Rails form_with, form_for)
// DEPENDENCIES: SECTION:helpers (for e(), csrf_field())
// EXPORTS: form_open(), form_close(), form_text(), form_email(), form_password(), etc.

    /**
     * @FUNC form_open
     * @brief Open a form tag with CSRF token
     * @param string $action Form action URL
     * @param string $method HTTP method (post, get)
     * @param array $attrs Additional attributes
     * @return string Opening form tag with CSRF field
     */
        function form_open(string $action = '', string $method = 'post', array $attrs = []): string {
            $attrs_str = form_attrs($attrs);
            $html = "<form action=\"" . e($action) . "\" method=\"" . e($method) . "\"{$attrs_str}>";
            if (strtolower($method) === 'post') {
                $html .= csrf_field();
            }
            return $html;
        }

    /**
     * @FUNC form_close
     * @brief Close a form tag
     * @return string Closing form tag
     */
        function form_close(): string {
            return '</form>';
        }

    /**
     * @FUNC form_attrs
     * @brief Convert attributes array to HTML string
     * @param array $attrs Attributes array
     * @return string HTML attributes string
     */
        function form_attrs(array $attrs): string {
            if (empty($attrs)) return '';

            $parts = [];
            foreach ($attrs as $key => $value) {
                if ($value === true) {
                    $parts[] = e($key);
                } elseif ($value !== false && $value !== null) {
                    $parts[] = e($key) . '="' . e($value) . '"';
                }
            }
            return $parts ? ' ' . implode(' ', $parts) : '';
        }

    /**
     * @FUNC form_label
     * @brief Generate a label element
     * @param string $for For attribute (input id)
     * @param string $text Label text
     * @param array $attrs Additional attributes
     * @return string Label HTML
     */
        function form_label(string $for, string $text, array $attrs = []): string {
            $attrs_str = form_attrs($attrs);
            return "<label for=\"" . e($for) . "\"{$attrs_str}>" . e($text) . "</label>";
        }

    /**
     * @FUNC form_text
     * @brief Generate a text input
     * @param string $name Input name
     * @param string $value Input value
     * @param array $attrs Additional attributes
     * @return string Input HTML
     */
        function form_text(string $name, string $value = '', array $attrs = []): string {
            $attrs = array_merge(['type' => 'text', 'name' => $name, 'id' => $name, 'value' => $value], $attrs);
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_email
     * @brief Generate an email input
     * @param string $name Input name
     * @param string $value Input value
     * @param array $attrs Additional attributes
     * @return string Input HTML
     */
        function form_email(string $name, string $value = '', array $attrs = []): string {
            $attrs = array_merge(['type' => 'email', 'name' => $name, 'id' => $name, 'value' => $value], $attrs);
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_password
     * @brief Generate a password input
     * @param string $name Input name
     * @param array $attrs Additional attributes
     * @return string Input HTML
     */
        function form_password(string $name, array $attrs = []): string {
            $attrs = array_merge(['type' => 'password', 'name' => $name, 'id' => $name], $attrs);
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_number
     * @brief Generate a number input
     * @param string $name Input name
     * @param string $value Input value
     * @param array $attrs Additional attributes
     * @return string Input HTML
     */
        function form_number(string $name, string $value = '', array $attrs = []): string {
            $attrs = array_merge(['type' => 'number', 'name' => $name, 'id' => $name, 'value' => $value], $attrs);
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_textarea
     * @brief Generate a textarea
     * @param string $name Textarea name
     * @param string $value Textarea content
     * @param array $attrs Additional attributes
     * @return string Textarea HTML
     */
        function form_textarea(string $name, string $value = '', array $attrs = []): string {
            $attrs = array_merge(['name' => $name, 'id' => $name], $attrs);
            $attrs_str = form_attrs($attrs);
            return "<textarea{$attrs_str}>" . e($value) . "</textarea>";
        }

    /**
     * @FUNC form_select
     * @brief Generate a select dropdown
     * @param string $name Select name
     * @param array $options Options array (value => label)
     * @param string|array|null $selected Selected value(s)
     * @param array $attrs Additional attributes
     * @return string Select HTML
     */
        function form_select(string $name, array $options, $selected = null, array $attrs = []): string {
            $attrs = array_merge(['name' => $name, 'id' => $name], $attrs);
            $attrs_str = form_attrs($attrs);

            $html = "<select{$attrs_str}>";
            foreach ($options as $value => $label) {
                $is_selected = is_array($selected) ? in_array($value, $selected) : ($value == $selected);
                $selected_attr = $is_selected ? ' selected' : '';
                $html .= "<option value=\"" . e($value) . "\"{$selected_attr}>" . e($label) . "</option>";
            }
            $html .= "</select>";

            return $html;
        }

    /**
     * @FUNC form_checkbox
     * @brief Generate a checkbox input
     * @param string $name Input name
     * @param string $value Checkbox value
     * @param bool $checked Whether checked
     * @param array $attrs Additional attributes
     * @return string Checkbox HTML
     */
        function form_checkbox(string $name, string $value = '1', bool $checked = false, array $attrs = []): string {
            $attrs = array_merge(['type' => 'checkbox', 'name' => $name, 'id' => $name, 'value' => $value], $attrs);
            if ($checked) {
                $attrs['checked'] = true;
            }
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_radio
     * @brief Generate a radio input
     * @param string $name Input name
     * @param string $value Radio value
     * @param bool $checked Whether checked
     * @param array $attrs Additional attributes
     * @return string Radio HTML
     */
        function form_radio(string $name, string $value, bool $checked = false, array $attrs = []): string {
            $id = $name . '_' . $value;
            $attrs = array_merge(['type' => 'radio', 'name' => $name, 'id' => $id, 'value' => $value], $attrs);
            if ($checked) {
                $attrs['checked'] = true;
            }
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC form_hidden
     * @brief Generate a hidden input
     * @param string $name Input name
     * @param string $value Input value
     * @return string Hidden input HTML
     */
        function form_hidden(string $name, string $value): string {
            return "<input type=\"hidden\" name=\"" . e($name) . "\" value=\"" . e($value) . "\">";
        }

    /**
     * @FUNC form_submit
     * @brief Generate a submit button
     * @param string $text Button text
     * @param array $attrs Additional attributes
     * @return string Submit button HTML
     */
        function form_submit(string $text = 'Submit', array $attrs = []): string {
            $attrs = array_merge(['type' => 'submit'], $attrs);
            $attrs_str = form_attrs($attrs);
            return "<button{$attrs_str}>" . e($text) . "</button>";
        }

    /**
     * @FUNC form_button
     * @brief Generate a button element
     * @param string $text Button text
     * @param array $attrs Additional attributes
     * @return string Button HTML
     */
        function form_button(string $text, array $attrs = []): string {
            $attrs = array_merge(['type' => 'button'], $attrs);
            $attrs_str = form_attrs($attrs);
            return "<button{$attrs_str}>" . e($text) . "</button>";
        }

    /**
     * @FUNC form_file
     * @brief Generate a file input
     * @param string $name Input name
     * @param array $attrs Additional attributes
     * @return string File input HTML
     */
        function form_file(string $name, array $attrs = []): string {
            $attrs = array_merge(['type' => 'file', 'name' => $name, 'id' => $name], $attrs);
            return "<input" . form_attrs($attrs) . ">";
        }

    /**
     * @FUNC old
     * @brief Get old input value from session
     * @param string $field Field name
     * @param mixed $default Default value if not found
     * @return mixed Old value or default
     */
        function old(string $field, mixed $default = ''): mixed {
            return $_SESSION['_old_input'][$field] ?? $default;
        }

    /**
     * @FUNC flash_old_input
     * @brief Store input for old() function (call before redirect)
     * @param array $data Input data to store
     * @return void
     */
        function flash_old_input(array $data): void {
            $_SESSION['_old_input'] = $data;
        }

    /**
     * @FUNC clear_old_input
     * @brief Clear old input from session
     * @return void
     */
        function clear_old_input(): void {
            unset($_SESSION['_old_input']);
        }
// ===[/SECTION:form-helpers]===

// ===[SECTION:view-init]===
// PURPOSE: Initialize view-related variables for rendering
// DEPENDENCIES: SECTION:database (for get_db_connection), SECTION:session
// EXPORTS: $errors, $messages, $pdo
    // Initialization
        $errors = [];
        $messages = [];
        $pdo = get_db_connection();

        // Initialize session messages array if not set
        if (!isset($_SESSION['messages'])) {
            $_SESSION['messages'] = [];
        }
// ===[/SECTION:view-init]===

// ===[SECTION:post]===
// PURPOSE: Handle all POST form submissions with CSRF validation
// DEPENDENCIES: SECTION:helpers (for csrf_token, redirect, sanitize_input)
// EXPORTS: POST action handlers
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
// ===[/SECTION:post]===

// ===[SECTION:routes]===
// PURPOSE: Define URL routes and map to page handlers
// DEPENDENCIES: None
// EXPORTS: $route_categories, $current_page, $page_category, $page_title
//
// ROUTE INDEX:
// @ROUTE /              => VIEW:home        (public)
// @ROUTE /home          => VIEW:home        (public)
// @ROUTE /feature       => VIEW:feature     (public)
// @ROUTE /about         => VIEW:about       (public)
// @ROUTE /courses       => VIEW:courses     (public)
// @ROUTE /testimonial   => VIEW:testimonial (public)
// @ROUTE /contact       => VIEW:contact     (public)
// @ROUTE /login         => VIEW:login       (public)
// @ROUTE /signup        => VIEW:signup      (public)
// @ROUTE /dashboard     => VIEW:dashboard   (public)
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
// ===[/SECTION:routes]===
?>

<!-- ===[SECTION:html-head]=== -->
<!-- PURPOSE: HTML document head with meta tags, fonts, and CSS -->
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
    <!-- ===[STYLES:variables]=== -->
    <!-- PURPOSE: CSS custom properties (design tokens) for theming -->
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
        /* ===[/STYLES:variables]=== */

        /* ===[STYLES:base]=== */
        /* PURPOSE: Base element styles, reset, common components */
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

        /* ===[STYLES:flash]=== */
        /* PURPOSE: Flash message styles for notifications */
        .flash-messages {
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: var(--z-tooltip);
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            max-width: 400px;
        }
        .flash {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: var(--space-md) var(--space-lg);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            animation: flash-in 0.3s ease-out;
        }
        @keyframes flash-in {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        .flash-message {
            flex: 1;
            font-size: var(--text-sm);
            font-weight: var(--font-medium);
        }
        .flash-close {
            background: transparent;
            border: none;
            font-size: var(--text-xl);
            cursor: pointer;
            opacity: 0.7;
            transition: opacity var(--transition-fast);
            margin-left: var(--space-md);
            line-height: 1;
        }
        .flash-close:hover {
            opacity: 1;
        }
        .flash-success {
            background: #10B981;
            color: #ffffff;
        }
        .flash-error {
            background: #EF4444;
            color: #ffffff;
        }
        .flash-warning {
            background: #F59E0B;
            color: #ffffff;
        }
        .flash-info {
            background: var(--primary);
            color: #ffffff;
        }
        /* ===[/STYLES:flash]=== */
        /* ===[/STYLES:base]=== */
    </style>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <script src="https://kit.fontawesome.com/4bf4b74595.js" crossorigin="anonymous"></script>
</head>
<!-- ===[/SECTION:html-head]=== -->
<body>
<?php echo flash_render(); ?>

<!--VIEW: public pages-->
<?php if ($page_category === 'public') { ?>
<!-- <public-container>  -->
    <div class="public-container">
    <!-- ===[STYLES:navbar]=== -->
    <!-- PURPOSE: Navigation bar styles for all public pages -->
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
    <!-- ===[/STYLES:navbar]=== -->
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
        <!-- ===[VIEW:home]=== -->
        <!-- ROUTE: /, /home -->
        <!-- AUTH: None -->
        <!-- CONTAINS: Hero section with login form, social proof -->
            <?php switch ($current_page) { case 'home': ?>
            <!-- ===[STYLES:hero]=== -->
            <!-- PURPOSE: Hero section styles for homepage -->
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
            <!-- ===[/STYLES:hero]=== -->
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
        <!-- ===[/VIEW:home]=== -->

        <!-- ===[VIEW:feature]=== -->
        <!-- ROUTE: /feature -->
        <!-- AUTH: None -->
            <?php break; case 'feature': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Features</h2>
                    <p>Discover all the amazing features that make Masco the perfect fitness companion for your health journey.</p>
                </section>
        <!-- ===[/VIEW:feature]=== -->

        <!-- ===[VIEW:about]=== -->
        <!-- ROUTE: /about -->
        <!-- AUTH: None -->
            <?php break; case 'about': ?>
                <style>
                    .about-hero {
                        padding: 120px 20px 60px;
                        text-align: center;
                        background: linear-gradient(135deg, var(--bg-surface) 0%, var(--bg-body) 100%);
                    }
                    .about-hero h1 {
                        font-size: 3rem;
                        color: var(--text-primary);
                        margin-bottom: 16px;
                    }
                    .about-hero .tagline {
                        font-size: 1.25rem;
                        color: var(--text-secondary);
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    .about-section {
                        max-width: 900px;
                        margin: 0 auto;
                        padding: 60px 20px;
                    }
                    .about-section h2 {
                        font-size: 2rem;
                        color: var(--text-primary);
                        margin-bottom: 24px;
                        text-align: center;
                    }
                    .about-mission {
                        background: var(--primary);
                        color: #ffffff;
                        text-align: center;
                        max-width: 100%;
                        padding: 80px 20px;
                    }
                    .about-mission h2 {
                        color: #ffffff;
                    }
                    .about-mission p {
                        font-size: 1.25rem;
                        max-width: 800px;
                        margin: 0 auto;
                        line-height: 1.8;
                        color: #ffffff;
                    }
                    .about-story p {
                        font-size: 1.1rem;
                        color: var(--text-secondary);
                        line-height: 1.8;
                        margin-bottom: 20px;
                    }
                    .values-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 30px;
                        margin-top: 40px;
                    }
                    .value-card {
                        background: var(--bg-card);
                        border: 1px solid var(--bg-card-border);
                        border-radius: 12px;
                        padding: 30px;
                        text-align: center;
                        transition: transform 0.2s, box-shadow 0.2s;
                    }
                    .value-card:hover {
                        transform: translateY(-4px);
                        box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
                    }
                    .value-card .icon {
                        width: 60px;
                        height: 60px;
                        background: var(--primary);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin: 0 auto 20px;
                        font-size: 1.5rem;
                    }
                    .value-card h3 {
                        font-size: 1.25rem;
                        color: var(--text-primary);
                        margin-bottom: 12px;
                    }
                    .value-card p {
                        font-size: 0.95rem;
                        color: var(--text-secondary);
                        line-height: 1.6;
                    }
                    @media (max-width: 768px) {
                        .about-hero h1 {
                            font-size: 2rem;
                        }
                        .about-hero .tagline {
                            font-size: 1rem;
                        }
                        .about-section {
                            padding: 40px 16px;
                        }
                        .about-mission {
                            padding: 50px 16px;
                        }
                        .values-grid {
                            grid-template-columns: 1fr;
                        }
                    }
                </style>

                <!-- Hero Banner -->
                <section class="about-hero">
                    <h1>About MonoPHP</h1>
                    <p class="tagline">Building powerful web applications with simplicity at the core</p>
                </section>

                <!-- Mission Statement -->
                <section class="about-mission">
                    <h2>Our Mission</h2>
                    <p>To empower developers of all skill levels to build secure, fast, and maintainable web applications without the complexity of modern frameworks. We believe great software doesn't require thousands of dependencies.</p>
                </section>

                <!-- Our Story -->
                <section class="about-section about-story">
                    <h2>Our Story</h2>
                    <p>MonoPHP was born from a simple observation: modern web development had become unnecessarily complex. Developers were spending more time configuring build tools, managing dependencies, and learning framework-specific patterns than actually building features their users needed.</p>
                    <p>We asked ourselves: what if we could strip away the complexity and get back to basics? What if a single PHP file could contain everything needed for a fully functional, secure web application?</p>
                    <p>The result is MonoPHP - a philosophy as much as a framework. By embracing vanilla PHP, vanilla CSS, and minimal JavaScript, we've created a development experience that's refreshingly straightforward. No build steps, no dependency hell, no framework lock-in. Just clean, readable code that does exactly what you expect.</p>
                </section>

                <!-- Our Values -->
                <section class="about-section about-values">
                    <h2>Our Values</h2>
                    <div class="values-grid">
                        <div class="value-card">
                            <div class="icon">
                                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="12" y1="8" x2="12" y2="12"></line>
                                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                </svg>
                            </div>
                            <h3>Simplicity</h3>
                            <p>Less is more. Every line of code should earn its place. We reject unnecessary abstraction and embrace clarity.</p>
                        </div>
                        <div class="value-card">
                            <div class="icon">
                                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                </svg>
                            </div>
                            <h3>Security</h3>
                            <p>Security is not an afterthought. CSRF protection, prepared statements, and secure sessions are built into our DNA.</p>
                        </div>
                        <div class="value-card">
                            <div class="icon">
                                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                                </svg>
                            </div>
                            <h3>Speed</h3>
                            <p>No build steps, no compilation, no waiting. Edit your file, refresh your browser. Development should be instant.</p>
                        </div>
                        <div class="value-card">
                            <div class="icon">
                                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="9" cy="7" r="4"></circle>
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                </svg>
                            </div>
                            <h3>Accessibility</h3>
                            <p>Great tools should be available to everyone. No expensive IDE required, no proprietary platforms, just open code.</p>
                        </div>
                    </div>
                </section>
        <!-- ===[/VIEW:about]=== -->

        <!-- ===[VIEW:courses]=== -->
        <!-- ROUTE: /courses -->
        <!-- AUTH: None -->
            <?php break; case 'courses': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Courses</h2>
                    <p>Explore our curated fitness courses designed to help you achieve your health and wellness goals.</p>
                </section>
        <!-- ===[/VIEW:courses]=== -->

        <!-- ===[VIEW:testimonial]=== -->
        <!-- ROUTE: /testimonial -->
        <!-- AUTH: None -->
            <?php break; case 'testimonial': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Testimonials</h2>
                    <p>Hear from our 64,739 happy customers about their fitness journey with Masco.</p>
                </section>
        <!-- ===[/VIEW:testimonial]=== -->

        <!-- ===[VIEW:contact]=== -->
        <!-- ROUTE: /contact -->
        <!-- AUTH: None -->
            <?php break; case 'contact': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Contact Us</h2>
                    <p>Have questions about Masco? We'd love to hear from you. Send us a message and we'll get back to you as soon as possible.</p>
                </section>
        <!-- ===[/VIEW:contact]=== -->

        <!-- ===[VIEW:login]=== -->
        <!-- ROUTE: /login -->
        <!-- AUTH: None -->
            <?php break; case 'login': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Login</h2>
                    <p>Welcome back! Sign in to your Masco account.</p>
                </section>
        <!-- ===[/VIEW:login]=== -->

        <!-- ===[VIEW:signup]=== -->
        <!-- ROUTE: /signup -->
        <!-- AUTH: None -->
            <?php break; case 'signup': ?>
                <section class="content" style="margin-top: 100px;">
                    <h2>Sign Up</h2>
                    <p>Create your free Masco account and start your fitness journey today.</p>
                </section>
        <!-- ===[/VIEW:signup]=== -->

        <!-- ===[VIEW:dashboard]=== -->
        <!-- ROUTE: /dashboard -->
        <!-- AUTH: None (public demo) -->
        <!-- CONTAINS: Dashboard cards with analytics, reports, settings, files -->
            <?php break; case 'dashboard': ?>
            <!-- ===[STYLES:dashboard]=== -->
            <!-- PURPOSE: Dashboard page styles -->
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
            <!-- ===[/STYLES:dashboard]=== -->
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
        <!-- ===[/VIEW:dashboard]=== -->

        <!-- ===[VIEW:404]=== -->
        <!-- ROUTE: (default/fallback) -->
        <!-- AUTH: None -->
            <?php break; default:?>
                <section class="content" style="margin-top: 100px; text-align: center;">
                    <h2>404 - Page Not Found</h2>
                    <p>The page you are looking for does not exist.</p>
                    <a href="/" style="color: var(--primary);">Go back to homepage</a>
                </section>
        <!-- ===[/VIEW:404]=== -->
            <?php } ?>
    <!--Footer-->
        <!--Footer style-->
        <!--Footer HTML-->
    </div>
<!-- </public-container>  -->

<?php } ?>

<!-- ===[SECTION:scripts]=== -->
<!-- PURPOSE: Client-side JavaScript for theme toggle and interactions -->
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
<!-- ===[/SECTION:scripts]=== -->

</body>
</html>
<!--<EOF>-->
