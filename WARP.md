# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Commands

- Do not start a dev server. The app is already served at http://localhost:8000.
- Environment
  - Copy env and set required values:
    - macOS/Linux: `cp .env.example .env`
    - Required keys: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `SITE_DOMAIN`
- Quick checks
  - PHP syntax check: `php -l public/index.php`
  - Tail errors (production mode writes here): `tail -f logs/app.log`
- Database (SQLite)
  - Open DB: `sqlite3 database/monophp.sqlite`
  - Example queries inside SQLite:
    - List tables: `.tables`
    - Users schema: `.schema users`
    - Sample: `SELECT id,name,email,is_paid FROM users LIMIT 10;`
- No build, lint, or test runners exist. Development is done by editing `public/index.php` and refreshing the browser.

## Architecture overview

MonoPHP is a single-file PHP 8+ application with procedural code, inline styles, and jQuery. The entire app lives in `public/index.php`. Key sections are ordered top-to-bottom so reading the file sequentially reveals the whole system.

- Initial settings and environment
  - Strict types, dev/prod detection.
  - `.env` loader populates `$_ENV`/process env.
  - Constants: app version, `SITE_DOMAIN`, paths for DB and logs.
- Session and security headers
  - Session cookie params (HTTPOnly, SameSite=Lax, 24h), optional domain handling.
  - CSRF token generated and stored in session; helper exposes it.
  - Content-Security-Policy limits origins for scripts/styles/fonts/images.
- Error handling
  - Development: custom error/exception handlers render readable HTML with code context and stack traces.
  - Production: errors grouped and appended to `logs/app.log` with timestamps and basic user-facing 500 page.
- Database layer (SQLite)
  - Connection helper (PDO, file path from config).
  - `initialize_database()` ensures tables exist:
    - `users(id, name, email unique, password, picture, role, is_paid, created_at, updated_at)`
    - `businesses(id, user_id FK→users, fields for profile, status, is_current)`
    - `migrations(version unique, applied_at)`
  - `run_migrations()` applies pending SQL statements from an in-file list; tracked via `migrations` table. It runs on every request.
- Helpers
  - Output escaping `e()`, input sanitization, CSRF helpers, redirects.
  - Auth utilities: `is_logged_in()`, `get_user()`, `refresh_user_data()`, `is_paid_user()`.
  - Password helpers: `hash_password()`, `verify_password()`.
  - Business helpers: CRUD, current-business selection, safe ownership checks, and transactional updates.
- POST request handling
  - All POSTs validate CSRF, route on `action`, validate inputs, perform DB ops, populate `$errors`/`$messages`, then redirect to avoid resubmission.
- Routing
  - `$route_categories` groups routes: `public`, `dashboard`, `other`.
  - Matching sets `$current_page`, page title, and category.
  - Guards:
    - Dashboard pages require login (redirect to `/`).
    - `paid_only` routes require `is_paid_user()`; otherwise redirect to `/dashboard` with a message.
- Views and styling
  - A single HTML document renders different pages via `switch` on `$current_page`.
  - Inline `<style>` blocks define and use shared CSS variables declared in `:root` (brand colors, spacing, surfaces, semantic colors).
  - jQuery is used for light client-side interactions; no bundling/build step.

## Repository rules and conventions

- Single-file constraint: do not add new files; all code (PHP, HTML, CSS, JS) goes in `public/index.php`.
- Procedural PHP only; no classes/OOP or frameworks.
- Keep CSS/JS close to the view section that uses it; rely on `:root` CSS variables.
- Use existing helpers from the `<helpers>` section; don’t duplicate utilities.
- Maintain security: escape output with `e()`, validate CSRF on POST, use prepared statements, and prefer session regeneration on login/register.
- Commenting convention uses paired section markers like:
  - `// <feature-name>` … `// </feature-name>` to delineate logical blocks.

## Important paths

- Main app: `public/index.php`
- Environment: `.env` (copy from `.env.example`)
- Database file: `database/monophp.sqlite`
- Error logs: `logs/app.log`
- Static assets (if any): `public/assets/`
