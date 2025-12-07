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

INSTALLATION (CLI Generator):
MonoPHP includes a CLI tool to scaffold new projects, similar to `laravel new`.

1. Install globally (choose one):

   # Option A: Symlink to /usr/local/bin (requires sudo)
   sudo ln -sf /path/to/monophp/bin/monophp /usr/local/bin/monophp

   # Option B: Add to PATH in ~/.zshrc or ~/.bashrc
   echo 'export PATH="/path/to/monophp/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc

2. Create a new project:
   monophp new myproject

3. Start developing:
   cd myproject
   php -S localhost:8000 -t public

The generator will:
- Copy the MonoPHP template structure
- Set SITE_DOMAIN to <project-name>.test
- Rename the database file to <project-name>.sqlite
- Initialize a git repository
