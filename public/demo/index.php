<?php
/**
 * MonoPHP Live Demo Router
 * Routes /demo/{variant}/* to the appropriate variant with isolated context
 */
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$parts = explode('/', trim($path, '/'));
array_shift($parts); // Remove "demo"

$variant_id = $parts[0] ?? null;
$variant_path = implode('/', array_slice($parts, 1));

// Load manifest from /variants/ (at repo root)
$manifest_file = __DIR__ . '/../../variants/manifest.json';
if (!file_exists($manifest_file)) {
    http_response_code(500);
    echo "Variants manifest not found";
    exit;
}

$manifest = json_decode(file_get_contents($manifest_file), true);
$valid_variants = array_column($manifest['variants'], 'id');

// If no variant specified or invalid, show demo listing
if (!$variant_id || !in_array($variant_id, $valid_variants)) {
    include __DIR__ . '/listing.php';
    exit;
}

// Set up isolated demo environment
define('DEMO_MODE', true);
define('DEMO_VARIANT', $variant_id);
define('DEMO_BASE_PATH', '/demo/' . $variant_id);

// Override environment for isolation
$_ENV['DEMO_DB_FILE'] = __DIR__ . '/../../demo-data/' . $variant_id . '.sqlite';
$_ENV['DEMO_CACHE_DIR'] = __DIR__ . '/../../cache/demo/' . $variant_id . '/';
$_ENV['DEMO_LOG_FILE'] = __DIR__ . '/../../logs/demo-' . $variant_id . '.log';

// Ensure demo cache directory exists
if (!is_dir($_ENV['DEMO_CACHE_DIR'])) {
    @mkdir($_ENV['DEMO_CACHE_DIR'], 0755, true);
}

// Rewrite REQUEST_URI for the variant (remove /demo/{variant} prefix)
$_SERVER['REQUEST_URI'] = '/' . $variant_path . (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] ? '?' . $_SERVER['QUERY_STRING'] : '');
$_SERVER['SCRIPT_NAME'] = '/index.php';

// Include variant from /variants/
$variant_file = __DIR__ . '/../../variants/' . $variant_id . '/index.php';
if (file_exists($variant_file)) {
    include $variant_file;
} else {
    http_response_code(404);
    echo "Variant not found: " . htmlspecialchars($variant_id);
}
