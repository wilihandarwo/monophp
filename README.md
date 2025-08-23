================================================================================
| PROJECT OVERVIEW :: MonoPHP - Single Index.PHP Boilerplate
================================================================================

This is a minimal, vanilla PHP web application - no frameworks, just pure PHP.

ARCHITECTURE:
- Single-file application (index.php) handling all routes and logic
- Procedural programming using functions and variables only
- No OOP, no frameworks, no external dependencies (except jQuery)
- SQLite for database
- Google Authentication for login

TECH STACK:
- Backend: Vanilla PHP 8+ (procedural style)
- Frontend: Vanilla CSS + jQuery
- Database: SQLite (file-based)
- Server: Nginx with PHP-FPM 8.4
- Security: Built-in CSRF protection, password hashing, session management

FILE STRUCTURE:
- /public/index.php          - Main application file (this file)
- /public/style.css          - Vanilla CSS styling
- /public/script.js          - jQuery-based JavaScript
- /public/assets/            - Static assets (images, fonts, etc.)
- /database/database.sqlite  - SQLite database file
- /logs/app-error.log        - Error logs
- /.env                      - Environment configuration

FEATURES:
- User registration and login system
- Session management with security headers
- Environment variable loading from .env
- Error handling (development vs production modes)
- Database migrations system
- CSRF protection on all forms
- Responsive design with vanilla CSS

DEVELOPMENT PHILOSOPHY:
- Keep it simple and minimal
- No over-engineering or unnecessary abstractions
- Direct, readable code that's easy to understand
- Fast development and deployment