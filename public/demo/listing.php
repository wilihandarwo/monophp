<?php
/**
 * MonoPHP Demo Gallery
 * Lists all available variants with live demo links
 */
$manifest = json_decode(file_get_contents(__DIR__ . '/../../variants/manifest.json'), true);
$variants = $manifest['variants'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Demos - MonoPHP</title>
    <style>
        :root {
            --primary: #4f46e5;
            --primary-dark: #4338ca;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
            --white: #ffffff;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--gray-50);
            color: var(--gray-800);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        header {
            text-align: center;
            margin-bottom: 3rem;
        }

        header h1 {
            font-size: 2.5rem;
            color: var(--gray-900);
            margin-bottom: 0.5rem;
        }

        header p {
            color: var(--gray-600);
            font-size: 1.1rem;
        }

        .back-link {
            display: inline-block;
            margin-bottom: 2rem;
            color: var(--primary);
            text-decoration: none;
        }

        .back-link:hover {
            text-decoration: underline;
        }

        .variant-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }

        .variant-card {
            background: var(--white);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: box-shadow 0.2s, transform 0.2s;
        }

        .variant-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transform: translateY(-2px);
        }

        .variant-card.experimental {
            border: 2px dashed var(--gray-200);
        }

        .variant-card h3 {
            font-size: 1.25rem;
            color: var(--gray-900);
            margin-bottom: 0.5rem;
        }

        .variant-card p {
            color: var(--gray-600);
            font-size: 0.95rem;
            margin-bottom: 1rem;
        }

        .variant-meta {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }

        .auth-type {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: var(--gray-100);
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--gray-700);
            text-transform: capitalize;
        }

        .variant-features {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .feature-tag {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            background: var(--primary);
            color: var(--white);
            border-radius: 4px;
            font-size: 0.75rem;
        }

        .btn-demo {
            display: inline-block;
            width: 100%;
            padding: 0.75rem 1.5rem;
            background: var(--primary);
            color: var(--white);
            text-decoration: none;
            border-radius: 8px;
            text-align: center;
            font-weight: 500;
            transition: background 0.2s;
        }

        .btn-demo:hover {
            background: var(--primary-dark);
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            background: #fbbf24;
            color: var(--gray-900);
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-top: 0.75rem;
        }

        .credentials {
            background: var(--white);
            border-radius: 12px;
            padding: 1.5rem;
            margin-top: 2rem;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .credentials h2 {
            font-size: 1.25rem;
            color: var(--gray-900);
            margin-bottom: 0.5rem;
        }

        .credentials code {
            display: inline-block;
            padding: 0.5rem 1rem;
            background: var(--gray-100);
            border-radius: 6px;
            font-family: monospace;
            margin-top: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">&larr; Back to MonoPHP</a>

        <header>
            <h1>Try MonoPHP Variants</h1>
            <p>Explore different authentication and layout options. Each demo runs in an isolated environment.</p>
        </header>

        <div class="variant-grid">
            <?php foreach ($variants as $variant): ?>
            <div class="variant-card <?= !empty($variant['experimental']) ? 'experimental' : '' ?>">
                <h3><?= htmlspecialchars($variant['name']) ?></h3>
                <p><?= htmlspecialchars($variant['description']) ?></p>

                <div class="variant-meta">
                    <span class="auth-type"><?= htmlspecialchars(str_replace('_', ' ', $variant['auth_type'])) ?></span>
                    <?php if (isset($variant['layout'])): ?>
                    <span class="auth-type"><?= htmlspecialchars($variant['layout']) ?> layout</span>
                    <?php endif; ?>
                </div>

                <?php if (!empty($variant['features'])): ?>
                <div class="variant-features">
                    <?php foreach ($variant['features'] as $feature): ?>
                    <span class="feature-tag"><?= htmlspecialchars($feature) ?></span>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>

                <a href="<?= htmlspecialchars($variant['demo_url']) ?>/" class="btn-demo">
                    Try Live Demo
                </a>

                <?php if (!empty($variant['experimental'])): ?>
                <span class="badge">Experimental</span>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="credentials">
            <h2>Demo Login Credentials</h2>
            <p>Use these credentials to test authenticated features:</p>
            <code>Email: demo@example.com | Password: demo1234</code>
        </div>
    </div>
</body>
</html>
