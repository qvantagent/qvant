<?php

define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_USER', getenv('DB_USER') ?: 'devhacks');
define('DB_PASS', getenv('DB_PASS') ?: 'password');
define('DB_NAME', getenv('DB_NAME') ?: 'devhacks');

define('N8N_WEBHOOK_URL', 'https://qvant.pachook.online:443/webhook/1f78371e-e5b8-4162-9409-fef73134d735');

define('GOOGLE_CLIENT_ID', getenv('GOOGLE_CLIENT_ID') ?: '497275514042-k9sp4snomdkb4pqn80nq6pflf7qbpphp.apps.googleusercontent.com');
define('ENCRYPTION_KEY', getenv('ENCRYPTION_KEY') ?: 'YOUR_VERY_STRONG_ENCRYPTION_KEY_32_CHARS_LONG!');
define('ENCRYPTION_CIPHER', 'aes-256-cbc');
define('ENCRYPTION_IV_LENGTH', openssl_cipher_iv_length(ENCRYPTION_CIPHER));

function log_error($message) {
    $log_dir = __DIR__ . '/logs';
    if (!is_dir($log_dir)) {
        if (!mkdir($log_dir, 0777, true)) {
            error_log("Could not create log directory: " . $log_dir);
            return;
        }
    }
    $log_file = $log_dir . '/error.log';
    if (file_exists($log_file) && !is_writable($log_file)) {
        error_log("Log file is not writable: " . $log_file);
        return;
    }
    file_put_contents($log_file, date('[Y-m-d H:i:s]') . ' ' . $message . PHP_EOL, FILE_APPEND);
}

?>
