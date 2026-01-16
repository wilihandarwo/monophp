================================================================================
| PROJECT OVERVIEW :: MonoPHP - Single Index.PHP Framework (Rails-Like Edition)
================================================================================

A minimal, vanilla PHP web application with Rails-like features - no frameworks, just pure PHP.

ARCHITECTURE:
- Single-file application (index.php ~4000 lines) handling all routes and logic
- Procedural programming using functions and variables only
- No OOP, no frameworks, no external dependencies (except jQuery)
- SQLite for database
- Authentication: Email/Password or Google OAuth (choose during setup)

TECH STACK:
- Backend: Vanilla PHP 8+ (procedural style)
- Frontend: Vanilla CSS + jQuery
- Database: SQLite (file-based)
- Server: Nginx with PHP-FPM 8.4
- Security: Built-in CSRF, rate limiting, password hashing, session management

================================================================================
| RAILS-LIKE FEATURES (v2.0)
================================================================================

VALIDATION LAYER (like ActiveModel::Validations):
- Centralized validation with chainable rules
- Rules: required, email, min, max, numeric, confirmed, unique, exists, in, regex
- Usage: $errors = validate($_POST, ['email' => 'required|email|unique:users']);

QUERY BUILDER (like ActiveRecord):
- db_find($table, $id)           - Find by ID
- db_first($table, $where)       - Find first matching
- db_all($table, $where, $order) - Get all matching
- db_insert($table, $data)       - Insert and return ID
- db_update($table, $id, $data)  - Update by ID
- db_delete($table, $id)         - Hard delete
- db_soft_delete($table, $id)    - Soft delete (sets deleted_at)
- db_restore($table, $id)        - Restore soft-deleted

FLASH MESSAGES (like Rails flash):
- flash('success', 'Message here')
- get_flashes() / has_flash()
- flash_render() for HTML output
- Survives redirects via session

RATE LIMITING (like Rack::Attack):
- rate_limit($action, $key, $max, $seconds)
- rate_limit_hit($action, $key)
- rate_limit_clear($action, $key)
- Prevents brute force attacks

PASSWORD RESET (like has_secure_password):
- create_password_reset($email)
- validate_reset_token($token)
- complete_password_reset($token, $password)
- Token-based with expiration

REMEMBER ME TOKENS:
- create_remember_token($user_id, $days)
- validate_remember_token()
- clear_remember_token() / clear_all_remember_tokens()
- Persistent login with secure cookies

FORM HELPERS (like form_with):
- form_open($action) with auto CSRF
- form_text(), form_email(), form_password()
- form_select(), form_checkbox(), form_radio()
- form_textarea(), form_file(), form_submit()
- old($field) for repopulating forms

FILE CACHING (like Rails.cache):
- cache_get($key) / cache_set($key, $value, $ttl)
- cache_has($key) / cache_forget($key)
- cache_remember($key, $ttl, $callback)
- cache_flush() to clear all

JSON API SUPPORT (like Rails API mode):
- is_api_request() detection
- api_response($data, $status)
- api_success($data, $message)
- api_error($message, $status)
- api_paginate($data, $total, $page, $per_page)
- api_cors() for CORS headers

AUTHORIZATION POLICIES (like Pundit):
- define_policy($ability, $callback)
- can($ability, ...$args) / cannot()
- authorize($ability) - dies if unauthorized
- is_admin() / is_owner($resource)

FILE UPLOADS (like ActiveStorage):
- upload_file($file, $dir, $extensions, $max_size)
- upload_image() / upload_document()
- delete_uploaded_file($path)
- get_upload_url($path)

STRUCTURED LOGGING (like Rails.logger):
- log_debug(), log_info(), log_warning(), log_error()
- log_exception($e) with stack trace
- log_request() for HTTP request details
- JSON context support

DATABASE SEEDING (like db:seed):
- get_seeds() - define seed data
- seed_table($table, $records)
- run_seeds($fresh) - run all seeds
- Development mode only

================================================================================
| FILE STRUCTURE
================================================================================

/public/index.php          - Main application file (~4000 lines)
/public/uploads/           - User uploaded files
/database/monophp.sqlite   - SQLite database file
/cache/                    - File-based cache storage
/logs/app.log              - Error and application logs
/.env                      - Environment configuration

================================================================================
| DATABASE TABLES
================================================================================

Core tables:
- users: id, name, email, password, picture, role, is_paid, timestamps
- businesses: id, user_id, name, description, address, phone, email, etc.
- migrations: version, applied_at

Auto-created tables:
- rate_limits: action, identifier, attempts, expires_at
- password_resets: email, token, expires_at
- remember_tokens: user_id, token, expires_at

================================================================================
| QUICK EXAMPLES
================================================================================

Validation:
```php
$errors = validate($_POST, [
    'name' => 'required|max:100',
    'email' => 'required|email|unique:users',
    'password' => 'required|min:8|confirmed',
]);
if ($errors) {
    foreach (validation_errors_flat($errors) as $error) {
        flash('error', $error);
    }
    redirect('/signup');
}
```

Query Builder:
```php
$user = db_find('users', 5);
$admins = db_all('users', ['role' => 'admin'], 'created_at DESC', 10);
$id = db_insert('users', ['name' => 'John', 'email' => 'john@example.com']);
db_update('users', $id, ['name' => 'Jane']);
db_soft_delete('users', $id);
```

Authorization:
```php
define_policy('business.edit', fn($user, $business) =>
    $user['id'] === $business['user_id']
);

authorize('business.edit', $business); // Dies if not authorized
```

Form with Flash:
```php
<?= form_open('/contact') ?>
    <?= form_text('name', old('name'), ['placeholder' => 'Name']) ?>
    <?= form_email('email', old('email'), ['placeholder' => 'Email']) ?>
    <?= form_textarea('message', old('message')) ?>
    <?= form_submit('Send Message') ?>
<?= form_close() ?>
```

================================================================================
| INSTALLATION (CLI Generator)
================================================================================

MonoPHP includes a CLI tool to scaffold new projects, similar to `laravel new`.

1. Install the CLI (one-liner):

   curl -s https://raw.githubusercontent.com/wilihandarwo/monophp/main/install.sh | bash

2. Reload your shell:

   source ~/.zshrc   # or ~/.bashrc

3. Create a new project:

   monophp new myproject

4. Select authentication method using arrow keys:

   Select authentication method:  (↑↓ to move, Enter to select)

     ▸ Email & Password
       Google OAuth
       No Auth

5. Start developing:

   cd myproject
   php -S localhost:8000 -t public

The generator will:
- Download the latest MonoPHP template from GitHub
- Prompt you to choose authentication method (Email/Password, Google OAuth, or No Auth)
- Set SITE_DOMAIN to <project-name>.test
- Rename the database file to <project-name>.sqlite
- Initialize a fresh git repository

================================================================================
| UPDATING THE CLI
================================================================================

To update MonoPHP CLI to the latest version:

   monophp update

================================================================================
| DEVELOPMENT PHILOSOPHY
================================================================================

- Keep it simple and minimal
- No over-engineering or unnecessary abstractions
- Direct, readable code that's easy to understand
- Fast development and deployment
- Rails-like conventions without Rails complexity
