================================================================================
| PROJECT OVERVIEW :: MonoPHP - Single Index.PHP Boilerplate
================================================================================

This is a minimal, vanilla PHP web application - no frameworks, just pure PHP.

ARCHITECTURE:
- Single-file application (index.php) handling all routes and logic
- Procedural programming using functions and variables only
- No OOP, no frameworks, no external dependencies (except jQuery)
- SQLite for database
- Authentication: Email/Password or Google OAuth (choose during setup)

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

INSTALLATION (CLI Generator):
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
- Prompt you to choose authentication method (Email/Password or Google OAuth)
- Set SITE_DOMAIN to <project-name>.test
- Rename the database file to <project-name>.sqlite
- Initialize a fresh git repository
