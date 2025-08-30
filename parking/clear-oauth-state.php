        <?php if (!empty($errors)): ?>
            <div class="error">
                <?php foreach ($errors as $error): ?>
                    <p><?php echo e($error); ?></p>
                <?php endforeach; ?>
                <div style="margin-top: 10px; font-size: 0.9rem;">
                    <a href="?clear_oauth=1" style="color: #721c24; text-decoration: underline;">Clear OAuth state and try again</a>
                </div>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['debug']) && $_GET['debug'] === '1'): ?>
            <div style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 1rem; border-radius: 5px; margin-bottom: 2rem; font-family: monospace; font-size: 0.875rem;">
                <strong>Debug Information:</strong><br>
                Session ID: <?= session_id() ?><br>
                OAuth State: <?= isset($_SESSION['oauth_state']) ? 'Set (' . substr($_SESSION['oauth_state'], 0, 8) . '...)' : 'Not set' ?><br>
                OAuth Timestamp: <?= isset($_SESSION['oauth_timestamp']) ? date('Y-m-d H:i:s', $_SESSION['oauth_timestamp']) : 'Not set' ?><br>
                User Session: <?= isset($_SESSION['user']) ? 'Logged in as ' . $_SESSION['user']['email'] : 'Not logged in' ?><br>
                Current URL: <?= $_SERVER['REQUEST_URI'] ?? 'Unknown' ?><br>
                Server Name: <?= $_SERVER['SERVER_NAME'] ?? 'Unknown' ?><br>
            </div>
        <?php endif; ?>
