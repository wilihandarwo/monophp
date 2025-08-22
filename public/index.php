<?php
session_start();

// Google OAuth Configuration
$google_client_id = getenv('GOOGLE_CLIENT_ID');
$google_client_secret = getenv('GOOGLE_CLIENT_SECRET');
$redirect_uri = getenv('GOOGLE_REDIRECT_URI');

// Database Configuration
$db_path = '/Users/wilihandarwo/dev/php/monophp/database/database.sqlite';

// Initialize SQLite Database
function initDatabase($db_path) {
    try {
        $pdo = new PDO('sqlite:' . $db_path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create users table if it doesn't exist
        $sql = "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                google_id VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                picture TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ";
        $pdo->exec($sql);

        return $pdo;
    } catch (PDOException $e) {
        die('Database connection failed: ' . $e->getMessage());
    }
}

// Get or create user in database
function getOrCreateUser($pdo, $user_data) {
    try {
        // Check if user exists
        $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
        $stmt->execute([$user_data['id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Update existing user
            $stmt = $pdo->prepare('
                UPDATE users
                SET name = ?, email = ?, picture = ?, updated_at = CURRENT_TIMESTAMP
                WHERE google_id = ?
            ');
            $stmt->execute([
                $user_data['name'],
                $user_data['email'],
                $user_data['picture'],
                $user_data['id']
            ]);

            // Get updated user data
            $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
            $stmt->execute([$user_data['id']]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } else {
            // Create new user
            $stmt = $pdo->prepare('
                INSERT INTO users (google_id, name, email, picture)
                VALUES (?, ?, ?, ?)
            ');
            $stmt->execute([
                $user_data['id'],
                $user_data['name'],
                $user_data['email'],
                $user_data['picture']
            ]);

            // Get newly created user
            $stmt = $pdo->prepare('SELECT * FROM users WHERE google_id = ?');
            $stmt->execute([$user_data['id']]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }
    } catch (PDOException $e) {
        die('Database error: ' . $e->getMessage());
    }
}

// Initialize database
$pdo = initDatabase($db_path);

// Handle Google OAuth callback
if (isset($_GET['code'])) {
    $code = $_GET['code'];

    // Exchange code for access token
    $token_url = 'https://oauth2.googleapis.com/token';
    $token_data = [
        'client_id' => $google_client_id,
        'client_secret' => $google_client_secret,
        'redirect_uri' => $redirect_uri,
        'grant_type' => 'authorization_code',
        'code' => $code
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $token_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $token_response = curl_exec($ch);
    curl_close($ch);

    $token_info = json_decode($token_response, true);

    if (isset($token_info['access_token'])) {
        // Get user info from Google
        $user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo?access_token=' . $token_info['access_token'];
        $user_response = file_get_contents($user_info_url);
        $user_data = json_decode($user_response, true);

        // Save user to database and store in session
        $db_user = getOrCreateUser($pdo, $user_data);
        $_SESSION['user'] = [
            'id' => $db_user['id'],
            'google_id' => $db_user['google_id'],
            'name' => $db_user['name'],
            'email' => $db_user['email'],
            'picture' => $db_user['picture'],
            'created_at' => $db_user['created_at'],
            'updated_at' => $db_user['updated_at']
        ];

        // Redirect to dashboard
        header('Location: /dashboard');
        exit;
    }
}

// Handle logout (keep backward compatibility)
if (isset($_GET['logout']) || $path === 'logout') {
    session_destroy();
    header('Location: /');
    exit;
}

// Simple router - parse the URL path
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$path = trim($path, '/');

// Handle OAuth callback route
if ($path === 'auth/google/callback') {
    // OAuth callback is handled above, just set current page
    $current_page = 'oauth_callback';
} elseif ($path === 'logout') {
    // Logout is handled above, this won't be reached but kept for clarity
    $current_page = 'logout';
} elseif ($path === '' || $path === 'index.php') {
    $current_page = 'home';
} elseif ($path === 'dashboard') {
    $current_page = 'dashboard';
} else {
    $current_page = 'home'; // Default fallback
}

// Check if user is logged in
$is_logged_in = isset($_SESSION['user']);

// Protect dashboard page
if ($current_page === 'dashboard' && !$is_logged_in) {
    header('Location: /');
    exit;
}

// Google OAuth URL
$google_auth_url = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
    'client_id' => $google_client_id,
    'redirect_uri' => $redirect_uri,
    'scope' => 'openid profile email',
    'response_type' => 'code',
    'access_type' => 'online'
]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $current_page === 'dashboard' ? 'Dashboard' : 'MonoPHP'; ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            text-align: center;
            max-width: 400px;
            width: 90%;
        }

        .logo {
            font-size: 2.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 10px;
        }

        .subtitle {
            color: #666;
            margin-bottom: 40px;
            font-size: 1.1rem;
        }

        .google-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #4285f4;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 50px;
            text-decoration: none;
            font-size: 1rem;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(66, 133, 244, 0.3);
        }

        .google-btn:hover {
            background: #3367d6;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(66, 133, 244, 0.4);
        }

        .google-icon {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            background: white;
            border-radius: 3px;
            padding: 2px;
        }

        .user-profile {
            text-align: center;
        }

        .user-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 20px;
            border: 4px solid #f0f0f0;
        }

        .user-name {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }

        .user-email {
            color: #666;
            margin-bottom: 30px;
        }

        .logout-btn {
            background: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 25px;
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .logout-btn:hover {
            background: #c82333;
            transform: translateY(-1px);
        }

        .dashboard-title {
            font-size: 2rem;
            color: #333;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($current_page === 'dashboard' && $is_logged_in): ?>
            <!-- Dashboard Page -->
            <h1 class="dashboard-title">Dashboard</h1>
            <div class="user-profile">
                <img src="<?php echo htmlspecialchars($_SESSION['user']['picture']); ?>" alt="Profile Picture" class="user-avatar">
                <div class="user-name"><?php echo htmlspecialchars($_SESSION['user']['name']); ?></div>
                <div class="user-email"><?php echo htmlspecialchars($_SESSION['user']['email']); ?></div>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        <?php else: ?>
            <!-- Home Page -->
            <div class="logo">MonoPHP</div>
            <div class="subtitle">Simple & Minimalist PHP Framework</div>

            <?php if (!$is_logged_in): ?>
                <a href="<?php echo htmlspecialchars($google_auth_url); ?>" class="google-btn">
                    <svg class="google-icon" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Continue with Google
                </a>
            <?php else: ?>
                <p style="margin-bottom: 20px;">Welcome back, <?php echo htmlspecialchars($_SESSION['user']['name']); ?>!</p>
                <a href="/dashboard" style="background: #28a745; color: white; padding: 10px 20px; border-radius: 25px; text-decoration: none; margin-right: 10px;">Go to Dashboard</a>
                <a href="/logout" class="logout-btn">Logout</a>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
