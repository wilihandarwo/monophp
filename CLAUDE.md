# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MonoPHP is a single-file PHP web application with Rails-like features, built with vanilla PHP 8+ (procedural style), vanilla CSS, and jQuery. The entire application (~4000 lines) is contained in `public/index.php`.

**Tech Stack:**
- Backend: Vanilla PHP 8+ (procedural, no OOP)
- Frontend: Vanilla CSS + jQuery
- Database: SQLite (`/database/monophp.sqlite`)
- Server: Nginx + PHP-FPM 8.4 (already running at http://localhost:8000)

## Development

**DO NOT run the dev server** - it's already running at http://localhost:8000.

There are no build, lint, or test commands. Edit `public/index.php` directly and refresh the browser.

## AI Agent Navigation

Read the TABLE OF CONTENTS at lines 18-70 of `index.php` for current section line numbers.

**Search markers:**
- Sections: `===[SECTION:name]===`
- Functions: `@FUNC function_name`
- Views: `===[VIEW:name]===`
- Styles: `===[STYLES:name]===`

## Architecture (Section Order)

### Core Infrastructure
| Section | Purpose |
|---------|---------|
| `init` | Strict types, development mode detection |
| `env` | `.env` file parsing |
| `config` | Site constants (SITE_DOMAIN, SITE_DB_FILE, SITE_LOG_FILE) |
| `session` | Cookie params, session init, expiry handling |
| `flash` | Flash messages that survive redirects |
| `security` | CSRF tokens, Content Security Policy |
| `validation` | Centralized validation with rules (required, email, min, max, unique, etc.) |
| `error` | Custom error/exception handlers |

### Database Layer
| Section | Purpose |
|---------|---------|
| `database` | PDO connection, table init, migrations |
| `seeds` | Database seeding for development |
| `query-builder` | `db_find()`, `db_all()`, `db_insert()`, `db_update()`, soft deletes |

### Security Features
| Section | Purpose |
|---------|---------|
| `rate-limit` | Brute force protection (`rate_limit()`, `rate_limit_hit()`) |
| `password-reset` | Token-based password reset flow |
| `remember-me` | Persistent login tokens (30-day cookies) |

### Utilities
| Section | Purpose |
|---------|---------|
| `logging` | Structured logging (`log_info()`, `log_error()`, etc.) |
| `cache` | File-based caching (`cache_get()`, `cache_set()`, `cache_remember()`) |
| `api` | JSON API helpers (`api_response()`, `api_error()`, `api_paginate()`) |
| `authorization` | Policy-based auth (`can()`, `cannot()`, `authorize()`) |
| `uploads` | File upload handling (`upload_file()`, `upload_image()`) |
| `helpers` | Core utilities (`e()`, `csrf_field()`, `redirect()`) |
| `form-helpers` | Form generation (`form_open()`, `form_text()`, `form_select()`) |

### Application
| Section | Purpose |
|---------|---------|
| `view-init` | Initialize `$errors`, `$messages`, `$pdo` |
| `post` | POST request handlers with CSRF validation |
| `routes` | Route definitions in `$route_categories` array |
| `html-head` | DOCTYPE, meta tags, CSS variables, base styles |
| Views | Switch-case based rendering (home, dashboard, etc.) |
| `scripts` | Theme toggle JavaScript |

## Database Schema

**Core tables:**
- `users`: id, name, email, password, picture, role, is_paid, created_at, updated_at
- `businesses`: id, user_id, name, description, address, phone, email, website, logo_url, status, is_current, created_at, updated_at
- `migrations`: version, applied_at

**Auto-created tables:**
- `rate_limits`: action, identifier, attempts, expires_at
- `password_resets`: email, token, expires_at
- `remember_tokens`: user_id, token, expires_at

## Key Patterns

### Validation
```php
$errors = validate($_POST, [
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

### Query Builder
```php
$user = db_find('users', $id);
$users = db_all('users', ['role' => 'admin'], 'created_at DESC', 10);
$id = db_insert('users', ['name' => 'John', 'email' => 'john@test.com']);
db_update('users', $id, ['name' => 'Jane']);
db_soft_delete('users', $id);  // Sets deleted_at
```

### Flash Messages
```php
flash('success', 'Business created!');
redirect('/dashboard');
// In views: <?= flash_render() ?>
```

### Authorization
```php
define_policy('business.edit', fn($user, $business) =>
    $user['id'] === $business['user_id']
);
// Usage:
if (cannot('business.edit', $business)) {
    flash('error', 'Not authorized');
    redirect('/');
}
// Or: authorize('business.edit', $business); // Dies if unauthorized
```

### Rate Limiting
```php
if (rate_limit('login', $_SERVER['REMOTE_ADDR'], 5, 300)) {
    flash('error', 'Too many attempts. Try again later.');
    redirect('/login');
}
rate_limit_hit('login', $_SERVER['REMOTE_ADDR']);
```

### Form Helpers
```php
<?= form_open('/login') ?>
    <?= form_email('email', old('email'), ['placeholder' => 'Email']) ?>
    <?= form_password('password') ?>
    <?= form_checkbox('remember', '1', false) ?> Remember me
    <?= form_submit('Login', ['class' => 'btn']) ?>
<?= form_close() ?>
```

### Caching
```php
$stats = cache_remember('dashboard_stats', 3600, function() {
    return db_count('users');
});
```

### API Responses
```php
if (is_api_request()) {
    api_success(['user' => $user], 'Login successful');
    // or: api_error('Invalid credentials', 401);
}
```

## File Locations

- Main app: `/public/index.php`
- Database: `/database/monophp.sqlite`
- Error logs: `/logs/app.log`
- Cache: `/cache/`
- Uploads: `/public/uploads/`
- Environment: `/.env`
- Archived code: `/parking/` (ignore)

## Adding New Routes

1. Add to `$route_categories` array in `SECTION:routes`
2. Add case to switch statement in views section
3. Set `'paid_only' => true` for premium features

## Adding Migrations

Add to `$migrations` array in `run_migrations()`:
```php
$migrations = [
    '2025_01_16_add_field' => "ALTER TABLE users ADD COLUMN field TEXT DEFAULT 'value';"
];
```
Migrations run automatically on every request.

## Development Rules

1. **DO NOT create new files** - add to `public/index.php`
2. **Use procedural PHP only** - no classes/objects
3. **Use `e()` for all output** - HTML escaping
4. **Use query builder** - `db_*()` functions with prepared statements
5. **Use flash messages** - `flash()` before redirects
6. **Use validation layer** - `validate()` with rules
7. **Place styles near views** - inline `<style>` tags
8. **Use CSS variables** - reference `:root` custom properties
9. **Follow section markers** - `===[SECTION:name]===` convention

## CSS Variables

**Colors:** `--primary`, `--primary-light`, `--primary-dark`, `--secondary`, `--accent`
**Neutrals:** `--gray-50` through `--gray-900`, `--white`, `--black`
**Spacing:** `--space-xs` through `--space-4xl`
**Containers:** `--container-sm` through `--container-2xl`
