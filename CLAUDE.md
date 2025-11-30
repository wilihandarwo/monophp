# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MonoPHP is a single-file PHP web application built with vanilla PHP (no frameworks), vanilla CSS, and jQuery. The entire application logic, routing, views, styles, and scripts are contained in a single `public/index.php` file (~3300 lines).

**Tech Stack:**
- Backend: Vanilla PHP 8+ (procedural style, no OOP)
- Frontend: Vanilla CSS + jQuery
- Database: SQLite (file-based at `/database/monophp.sqlite`)
- Server: Nginx with PHP-FPM 8.4 (already running at http://localhost:8000)

## Development Commands

**DO NOT run the development server** - it's already running at http://localhost:8000.

There are no build, lint, or test commands. Development is done by editing `public/index.php` directly and refreshing the browser.

## Architecture and Code Organization

### Single-File Structure

Everything exists in `/public/index.php` in this order:

1. **Initial Settings** (lines 2-11): Strict types declaration, development mode detection
2. **Environment Loading** (lines 13-38): `.env` file parsing
3. **Configuration** (lines 40-47): Site settings and file paths
4. **Session Management** (lines 49-76): Cookie parameters, session initialization, expiry handling
5. **Security Headers** (lines 78-86): CSRF tokens, Content Security Policy
6. **Error Handling** (lines 88-208): Custom error/exception handlers for dev/production modes
7. **Database** (lines 210-290): Connection handling, table initialization, migrations system
8. **Helpers** (lines 292-700): Utility functions for HTML escaping, input sanitization, CSRF, authentication, user management, business operations
9. **View Initialization** (lines 701-712): Initialize error/message arrays
10. **POST Request Handling** (lines 714-950): Handle form submissions with CSRF validation
11. **Routing** (lines 952-1011): Route definitions, access control, paid feature protection
12. **HTML Head** (lines 1013-1452): DOCTYPE, meta tags, CSS styles, navigation
13. **Views** (lines 1454+): Switch-case based view rendering (home, dashboard, settings, etc.)

### Routing System

Routes are defined in the `$route_categories` array (line 956) grouped by category:

```php
$route_categories = [
    'public' => [
        '' => ['page' => 'home', 'title' => 'MonoPHP', 'paid_only' => false],
        'about' => ['page' => 'about', 'title' => 'About - MonoPHP', 'paid_only' => false],
    ],
    'dashboard' => [
        'dashboard' => ['page' => 'dashboard', 'title' => 'Dashboard - MonoPHP', 'paid_only' => false],
        'business' => ['page' => 'business', 'title' => 'Dashboard - MonoPHP', 'paid_only' => true],
    ],
    'other' => [
        'logout' => ['page' => 'logout', 'title' => 'MonoPHP', 'paid_only' => false]
    ]
];
```

- Routes map URL paths to page identifiers and titles
- `paid_only` flag protects premium features (requires `is_paid_user()`)
- Dashboard routes require authentication (redirects to `/` if not logged in)
- Views are rendered via `switch ($current_page)` statements (line 1454 for public pages, line 2579 for dashboard pages)

### Database Schema

Core tables (initialized in `initialize_database()` at line 224):

- **users**: id, name, email, password, picture, role, is_paid, created_at, updated_at
- **businesses**: id, user_id, name, description, address, phone, email, website, logo_url, status, is_current, created_at, updated_at
- **migrations**: version, applied_at

### Key Helper Functions

Located in the `<helpers>` section (lines 292-700):

- `e(?string $string)`: HTML escape for safe output
- `sanitize_input(array $data)`: XSS prevention
- `csrf_token()`: Get current CSRF token
- `csrf_field()`: Generate CSRF hidden input
- `redirect(string $url)`: Redirect and exit
- `is_logged_in()`: Check authentication status
- `get_user()`: Get current user data from session
- `refresh_user_data()`: Sync session with database
- `is_paid_user()`: Check if user has paid status
- `hash_password(string $password)`: Hash using password_hash
- `verify_password(string $password, string $hash)`: Verify password
- `register_user(string $name, string $email, string $password)`: Create new user
- `login_user(string $email, string $password)`: Authenticate user
- `create_business(array $data)`: Create business for current user
- `get_user_businesses()`: Get all active businesses for current user
- `get_business_by_id(int $business_id)`: Get specific business (ownership verified)
- `update_business(int $business_id, array $data)`: Update business
- `delete_business(int $business_id)`: Soft delete (sets status='deleted')
- `set_current_business(int $business_id)`: Set active business
- `get_current_business()`: Get active business
- `clear_current_business()`: Clear active business

### POST Request Handling

All POST requests (line 716):
1. Validate CSRF token first (dies on failure)
2. Extract `$_POST['action']`
3. Route to appropriate handler (login, register, create_business, update_business, etc.)
4. Validate inputs
5. Execute database operations
6. Set `$errors[]` or `$messages[]` arrays
7. Redirect or fall through to view rendering

### Code Commenting Convention

Code sections use opening/closing comment tags similar to HTML:

```php
// <feature-name>
    // Sub-section
        // Implementation
// </feature-name>
```

This pattern is used throughout to mark logical sections (env, config, routing, helpers, etc.)

### Styling Convention

Styles are placed inline near the corresponding HTML views using `<style>` tags. Reference CSS custom properties defined in `:root` (line 1025):

**Primary colors:**
- `--primary: #B88400` (deep gold for main CTAs, buttons, active nav)
- `--primary-light: #D9A63A` (hover states)
- `--primary-dark: #7A5200` (active/pressed states)

**Secondary colors:**
- `--secondary: #2F2E3A` (charcoal for text, headings)
- `--secondary-light: #4A4756`
- `--secondary-dark: #1E1D25`

**Accent colors:**
- `--accent: #22C55E` (success states, green)
- `--accent-light: #57D987`
- `--accent-dark: #15803D`

**Neutrals:** `--gray-50` through `--gray-900`, `--white`, `--black`

**Spacing:** `--space-xs` through `--space-4xl`

**Container widths:** `--container-sm` through `--container-2xl`

### Security Features

- **CSRF Protection**: All POST requests require valid CSRF token (line 718)
- **Session Security**: HTTPOnly, SameSite=Lax cookies with 24h expiry (line 60)
- **Password Hashing**: Using PHP's `password_hash()` with bcrypt (line 385)
- **Content Security Policy**: Restricts script/style sources (line 85)
- **Input Sanitization**: `htmlspecialchars()` on all output via `e()` helper
- **SQL Injection Prevention**: Prepared statements for all queries
- **Session Regeneration**: On successful login/register (lines 750, 775)

## Important Development Rules

1. **DO NOT create new files** - everything must be added to `public/index.php`
2. **DO NOT run the dev server** - it's already running at http://localhost:8000
3. **Use existing helpers** - don't reinvent utilities that already exist
4. **Keep security in mind** - always use `e()` for output, validate CSRF tokens, use prepared statements
5. **Use procedural PHP only** - no classes, no objects, just functions and variables
6. **Place styles near views** - use inline `<style>` tags within the relevant view section
7. **Reference :root CSS variables** - don't hardcode colors/spacing
8. **Follow commenting convention** - use `// <name>` and `// </name>` to mark sections
9. **Validate before database operations** - check inputs, set `$errors[]`, only proceed if valid
10. **Use strict type declarations** - `declare(strict_types=1);` is enabled

## Environment Configuration

Copy `.env.example` to `.env` and configure:

```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
SITE_DOMAIN=
```

## File Locations

- Main app: `/public/index.php`
- Database: `/database/monophp.sqlite`
- Error logs: `/logs/app.log`
- Environment: `/.env`
- Static assets: `/public/assets/`
- Archived/old code: `/parking/` (ignore this directory)

## Adding New Routes

1. Add route to `$route_categories` array (line 956)
2. Add corresponding case to the appropriate switch statement (line 1454 for public, line 2579 for dashboard)
3. Include HTML, styles, and scripts within that case block
4. Set `'paid_only' => true` if the feature requires paid access

## Adding Database Migrations

Add to the `$migrations` array in `run_migrations()` function (line 260):

```php
$migrations = [
    '2025_12_01_100000_add_column_name' => "ALTER TABLE table_name ADD COLUMN column_name TEXT DEFAULT 'value';"
];
```

Migrations run automatically on every request.

## Development vs Production Mode

Mode is auto-detected based on server environment (line 7):
- **Development** (localhost/127.0.0.1): Errors displayed with code context and stack traces
- **Production**: Errors logged to `/logs/app.log` with timestamps, generic message shown to users
