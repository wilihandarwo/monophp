# AI-Optimized Single-File Codebase Strategy

This document outlines the organizational strategy for making a large single-file PHP codebase (30K+ LOC) efficient for AI agents to navigate and modify with minimal token usage.

## Goals

1. **Token Efficiency**: Minimize tokens needed for AI to understand context
2. **Navigation Speed**: Help AI find specific sections/functions quickly
3. **Predictable Structure**: Enable AI to know where things are without reading everything
4. **Self-Documenting**: The file describes its own structure

---

## Strategy 1: File Header Block

Add a structured header at the very top of `index.php` (before any PHP code):

```php
<?php
/**
 * ============================================================================
 * MONOPHP - Single File Application
 * ============================================================================
 * Version: 1.0.0
 * Total Lines: ~3300 (update periodically)
 * Last Structure Update: 2025-01-15
 *
 * HOW TO USE THIS FILE (FOR AI AGENTS):
 * -------------------------------------
 * 1. Read the TABLE OF CONTENTS below to find sections
 * 2. Search for section markers: ===[SECTION:name]===
 * 3. Search for function markers: @FUNC function_name
 * 4. Search for view markers: ===[VIEW:page-name]===
 * 5. Search for POST handler markers: ===[POST:action-name]===
 *
 * TABLE OF CONTENTS
 * -----------------
 * @TOC-START
 * SECTION:init        Lines 50-80      Initial settings, strict types
 * SECTION:env         Lines 80-140     Environment file loading
 * SECTION:config      Lines 140-180    Site configuration constants
 * SECTION:session     Lines 180-260    Session management
 * SECTION:security    Lines 260-320    CSRF tokens, CSP headers
 * SECTION:error       Lines 320-500    Error/exception handlers
 * SECTION:database    Lines 500-700    DB connection, migrations
 * SECTION:helpers     Lines 700-1200   Utility functions
 * SECTION:post        Lines 1200-1800  POST request handlers
 * SECTION:routes      Lines 1800-1900  Route definitions
 * SECTION:html-head   Lines 1900-2200  DOCTYPE, CSS, navigation
 * VIEW:home           Lines 2200-2600  Homepage
 * VIEW:dashboard      Lines 2600-3000  Dashboard
 * VIEW:settings       Lines 3000-3200  Settings page
 * @TOC-END
 *
 * FUNCTION INDEX
 * --------------
 * @FUNC-INDEX-START
 * @FUNC e()                    line:720   HTML escape output
 * @FUNC sanitize_input()       line:730   Sanitize array input
 * @FUNC csrf_token()           line:750   Get CSRF token
 * @FUNC csrf_field()           line:760   Generate CSRF hidden field
 * @FUNC redirect()             line:780   Redirect and exit
 * @FUNC is_logged_in()         line:800   Check if user authenticated
 * @FUNC get_user()             line:820   Get current user from session
 * @FUNC refresh_user_data()    line:850   Sync session with database
 * @FUNC is_paid_user()         line:900   Check paid status
 * @FUNC hash_password()        line:920   Hash password with bcrypt
 * @FUNC verify_password()      line:930   Verify password hash
 * @FUNC register_user()        line:950   Create new user account
 * @FUNC login_user()           line:1000  Authenticate user
 * @FUNC create_business()      line:1050  Create business record
 * @FUNC get_user_businesses()  line:1100  Get user's businesses
 * @FUNC get_business_by_id()   line:1130  Get specific business
 * @FUNC update_business()      line:1160  Update business record
 * @FUNC delete_business()      line:1190  Soft delete business
 * @FUNC-INDEX-END
 *
 * POST ACTIONS INDEX
 * ------------------
 * @POST-INDEX-START
 * @POST login                  line:1250  User login
 * @POST register               line:1300  User registration
 * @POST logout                 line:1350  User logout
 * @POST create_business        line:1400  Create new business
 * @POST update_business        line:1450  Update existing business
 * @POST delete_business        line:1500  Delete business
 * @POST update_profile         line:1550  Update user profile
 * @POST-INDEX-END
 *
 * ============================================================================
 */
```

---

## Strategy 2: Section Markers

Use consistent, grep-friendly section markers throughout the file:

### Opening Marker Format
```php
// ===[SECTION:section-name]=== @line:XXX
// PURPOSE: Brief description of what this section does
// DEPENDENCIES: List of sections this depends on
// EXPORTS: List of functions/variables this section provides
```

### Closing Marker Format
```php
// ===[/SECTION:section-name]=== @line:XXX
```

### Example
```php
// ===[SECTION:helpers]=== @line:700
// PURPOSE: Utility functions for HTML output, security, and authentication
// DEPENDENCIES: session, database
// EXPORTS: e(), sanitize_input(), csrf_token(), csrf_field(), redirect(),
//          is_logged_in(), get_user(), refresh_user_data(), is_paid_user()

    function e(?string $string): string {
        return htmlspecialchars((string) $string, ENT_QUOTES, "UTF-8");
    }

    // ... more functions ...

// ===[/SECTION:helpers]=== @line:1200
```

---

## Strategy 3: Function Documentation

Each function should have a minimal but informative docblock:

```php
/**
 * @FUNC create_business
 * @brief Create a new business for the current user
 * @param array $data {name, description, address, phone, email, website, logo_url}
 * @return int|false Business ID on success, false on failure
 * @uses SECTION:database
 * @called-by POST:create_business
 */
function create_business(array $data): int|false {
    // implementation
}
```

### Key Annotations
- `@FUNC name` - Searchable function marker
- `@brief` - One-line description
- `@uses SECTION:name` - Dependencies
- `@called-by` - What invokes this function

---

## Strategy 4: POST Handler Markers

Mark each POST action handler clearly:

```php
// ===[POST:create_business]=== @line:1400
// CSRF: Required
// AUTH: Required (is_logged_in)
// PAID: No
// REDIRECT: /dashboard/business
case 'create_business':
    if (!is_logged_in()) {
        $errors[] = 'You must be logged in.';
        break;
    }
    // ... handler code ...
    break;
// ===[/POST:create_business]===
```

---

## Strategy 5: View Markers

Mark each view/page section:

```php
// ===[VIEW:dashboard]=== @line:2600
// ROUTE: /dashboard
// AUTH: Required
// PAID: No
// STYLES: Lines 2600-2700
// HTML: Lines 2700-2950
// SCRIPTS: Lines 2950-3000
<?php case 'dashboard': ?>

    <!-- Styles for this view -->
    <style>
    .dashboard-container { /* ... */ }
    </style>

    <!-- HTML content -->
    <section class="dashboard-container">
        <!-- ... -->
    </section>

    <!-- Scripts for this view -->
    <script>
    $(function() { /* ... */ });
    </script>

<?php break; ?>
// ===[/VIEW:dashboard]=== @line:3000
```

---

## Strategy 6: Route Definition Markers

Make routes easily discoverable:

```php
// ===[SECTION:routes]=== @line:1800
// FORMAT: 'url-path' => ['page' => 'switch-case-name', 'title' => 'Page Title', 'paid_only' => bool]
//
// ROUTE INDEX:
// @ROUTE /              => VIEW:home        (public)
// @ROUTE /about         => VIEW:about       (public)
// @ROUTE /login         => VIEW:login       (public)
// @ROUTE /signup        => VIEW:signup      (public)
// @ROUTE /dashboard     => VIEW:dashboard   (auth required)
// @ROUTE /settings      => VIEW:settings    (auth required)
// @ROUTE /business      => VIEW:business    (auth + paid)

$route_categories = [
    'public' => [
        ''        => ['page' => 'home',   'title' => 'MonoPHP', 'paid_only' => false],
        'about'   => ['page' => 'about',  'title' => 'About',   'paid_only' => false],
        // ...
    ],
    // ...
];
// ===[/SECTION:routes]=== @line:1900
```

---

## Strategy 7: Cross-Reference System

When code in one section references another, add explicit cross-references:

```php
// In SECTION:post
case 'login':
    // @xref FUNC:login_user - handles authentication
    // @xref FUNC:refresh_user_data - loads user into session
    $user = login_user($email, $password);
    if ($user) {
        refresh_user_data($user['id']);
        redirect('/dashboard');
    }
    break;
```

```php
// In a function
function login_user(string $email, string $password): array|false {
    // @xref SECTION:database - uses get_db_connection()
    // @xref POST:login - called from POST handler
    $pdo = get_db_connection();
    // ...
}
```

---

## Strategy 8: CSS Organization

Group styles with clear markers:

```php
// ===[STYLES:global]=== @line:1900
// PURPOSE: Base styles, CSS variables, reset
// APPLIES-TO: All pages
<style>
:root {
    /* Color System */
    --primary: #B88400;
    // ...
}
</style>
// ===[/STYLES:global]=== @line:2000

// ===[STYLES:components]=== @line:2000
// PURPOSE: Reusable component styles (buttons, cards, forms)
// APPLIES-TO: All pages
<style>
.btn { /* ... */ }
.card { /* ... */ }
</style>
// ===[/STYLES:components]=== @line:2100

// ===[STYLES:layout]=== @line:2100
// PURPOSE: Layout structures (navbar, footer, containers)
// APPLIES-TO: All pages
<style>
.navbar { /* ... */ }
.container { /* ... */ }
</style>
// ===[/STYLES:layout]=== @line:2200
```

---

## Strategy 9: Naming Conventions

### Function Prefixes
| Prefix | Purpose | Example |
|--------|---------|---------|
| `db_` | Database operations | `db_query()`, `db_insert()` |
| `user_` | User-related functions | `user_create()`, `user_get()` |
| `biz_` | Business-related functions | `biz_create()`, `biz_list()` |
| `auth_` | Authentication functions | `auth_check()`, `auth_login()` |
| `view_` | View helper functions | `view_render()`, `view_partial()` |
| `util_` | General utilities | `util_slug()`, `util_format_date()` |

### CSS Class Prefixes
| Prefix | Purpose | Example |
|--------|---------|---------|
| `.c-` | Components | `.c-btn`, `.c-card` |
| `.l-` | Layout | `.l-container`, `.l-grid` |
| `.u-` | Utilities | `.u-hidden`, `.u-text-center` |
| `.p-` | Page-specific | `.p-dashboard`, `.p-home` |
| `.is-` | State | `.is-active`, `.is-loading` |

---

## Strategy 10: Quick-Find Patterns

Design markers that are easy to grep/search:

| To Find | Search Pattern |
|---------|---------------|
| Section start | `===[SECTION:name]===` |
| Section end | `===[/SECTION:name]===` |
| View start | `===[VIEW:name]===` |
| POST handler | `===[POST:action]===` |
| Function definition | `@FUNC function_name` |
| Route definition | `@ROUTE /path` |
| Cross-reference | `@xref` |
| TOC entry | `@TOC-` |
| Line marker | `@line:` |

---

## Implementation Checklist

When implementing this strategy:

- [ ] Add file header block with TOC and indexes
- [ ] Convert all `// <section>` markers to `===[SECTION:name]===` format
- [ ] Add PURPOSE/DEPENDENCIES/EXPORTS to each section
- [ ] Add `@FUNC` markers to all function docblocks
- [ ] Add `===[POST:action]===` markers to all POST handlers
- [ ] Add `===[VIEW:name]===` markers to all views
- [ ] Add `@xref` cross-references where applicable
- [ ] Group CSS with `===[STYLES:name]===` markers
- [ ] Update function names to use consistent prefixes
- [ ] Periodically update line numbers in TOC (can be automated)

---

## Maintenance

### Updating Line Numbers
Create a simple script to regenerate the TOC line numbers:

```bash
# Find all section markers and their line numbers
grep -n "===[SECTION:" public/index.php
grep -n "===[VIEW:" public/index.php
grep -n "@FUNC " public/index.php
```

### Validation
Periodically verify structure integrity:
- All `===[SECTION:` have matching `===[/SECTION:`
- All functions in index are in the FUNCTION INDEX
- All routes have corresponding VIEW markers

---

## AI Agent Instructions

Include this in CLAUDE.md or as a comment in the file:

```
FOR AI AGENTS:
1. FIRST read the TABLE OF CONTENTS at the top (lines 1-100)
2. To find a section: search for ===[SECTION:name]===
3. To find a function: search for @FUNC function_name
4. To find a view: search for ===[VIEW:name]===
5. To find a POST handler: search for ===[POST:action]===
6. Always check @xref comments for dependencies
7. Update TOC line numbers after major changes
```

---

## Benefits Summary

| Benefit | How Achieved |
|---------|-------------|
| **Reduced token usage** | AI reads TOC first, then only relevant sections |
| **Faster navigation** | Consistent markers enable precise grep searches |
| **Self-documenting** | PURPOSE/DEPENDENCIES/EXPORTS explain each section |
| **Predictable structure** | Same patterns throughout the entire file |
| **Easy maintenance** | Clear boundaries make updates safer |
| **Cross-referencing** | @xref helps AI understand relationships |
