<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

function register_user($email, $password = null, $googleId = null) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to register user.");
        return false;
    }

    $hashed_password = '';
    if ($password) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        if ($hashed_password === false) {
            log_error("Password hashing error for email: " . $email);
            $conn->close();
            return false;
        }
    } else {
        log_error("No password provided for user registration " . $email . ". An empty string is used for the hashed password.");
        $hashed_password = '';
    }

    $stmt = $conn->prepare("INSERT INTO users (email, password, google_id, created_at) VALUES (?, ?, ?, NOW())");
    if ($stmt === false) {
        log_error("Error preparing register_user query: " . $conn->error . ". Email: " . $email);
        $conn->close();
        return false;
    }

    $stmt->bind_param("sss", $email, $hashed_password, $googleId);
    $result = $stmt->execute();

    if ($result === false) {
        log_error("Error executing register_user query: " . $stmt->error . ". Email: " . $email . ". Google ID: " . $googleId);
        if ($conn->errno == 1062) {
            log_error("User with email '" . $email . "' or Google ID '" . $googleId . "' already exists.");
        }
        $conn->close();
        return false;
    }

    $new_user_id = $conn->insert_id;
    $stmt->close();
    $conn->close();
    return $new_user_id;
}

function login_user($email, $password) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection for user login.");
        return false;
    }

    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
    if ($stmt === false) {
        log_error("Error preparing login_user query: " . $conn->error . ". Email: " . $email);
        $conn->close();
        return false;
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        log_error("Error getting result for login_user query: " . $stmt->error . ". Email: " . $email);
        $stmt->close();
        $conn->close();
        return false;
    }

    $user = $result->fetch_assoc();

    if ($user && password_verify($password, $user['password'])) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $_SESSION['user_id'] = $user['id'];
        log_error("User successfully logged in: " . $email);
        $stmt->close();
        $conn->close();
        return $user['id'];
    } else {
        log_error("Failed login attempt for email: " . $email . ". Invalid email or password.");
        $stmt->close();
        $conn->close();
        return false;
    }
}

function google_login_or_register($idToken) {
    log_error("Starting Google authentication. Token: " . substr($idToken, 0, 50) . "...");

    $ch = curl_init("https://oauth2.googleapis.com/tokeninfo?id_token=" . $idToken);
    if ($ch === false) {
        $msg = "cURL init error during Google ID Token verification.";
        log_error($msg);
        return ['error' => $msg];
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        $msg = "cURL error during Google ID Token verification: " . $curlError;
        log_error($msg);
        return ['error' => $msg];
    }

    if ($httpCode !== 200) {
        $msg = "Google API returned an error during token verification: HTTP " . $httpCode;
        log_error($msg . ". Response: " . $response);
        return ['error' => $msg];
    }

    $tokenInfo = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        $msg = "Error decoding JSON response from Google API: " . json_last_error_msg();
        log_error($msg . ". Response: " . $response);
        return ['error' => $msg];
    }

    log_error("Google Token Info: " . print_r($tokenInfo, true));

    if (!isset($tokenInfo['aud']) || $tokenInfo['aud'] !== GOOGLE_CLIENT_ID) {
        $msg = "Invalid GOOGLE_CLIENT_ID in token";
        log_error($msg . ": " . ($tokenInfo['aud'] ?? 'N/A') . ". Expected: " . GOOGLE_CLIENT_ID);
        return ['error' => $msg];
    }
    if (!isset($tokenInfo['iss']) || !in_array($tokenInfo['iss'], ['accounts.google.com', 'https://accounts.google.com'])) {
        $msg = "Invalid token issuer";
        log_error($msg . ": " . ($tokenInfo['iss'] ?? 'N/A'));
        return ['error' => $msg];
    }
    if (!isset($tokenInfo['sub']) || !isset($tokenInfo['email'])) {
        $msg = "Missing required fields (sub, email) in Google token.";
        log_error($msg);
        return ['error' => $msg];
    }

    $googleId = $tokenInfo['sub'];
    $email = $tokenInfo['email'];
    $name = $tokenInfo['name'] ?? '';

    $conn = get_db_connection();
    if (!$conn) {
        $msg = "Failed to get DB connection for Google authentication";
        log_error($msg . " (after token verification).");
        return ['error' => $msg];
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE google_id = ? OR email = ?");
    if ($stmt === false) {
        $msg = "Error preparing query to check Google ID/email: " . $conn->error;
        log_error($msg);
        $conn->close();
        return ['error' => $msg];
    }
    $stmt->bind_param("ss", $googleId, $email);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result === false) {
        $msg = "Error getting result for Google ID/email check query: " . $stmt->error;
        log_error($msg);
        $stmt->close();
        $conn->close();
        return ['error' => $msg];
    }
    $user = $result->fetch_assoc();
    $stmt->close();

    $userId = false;
    if ($user) {
        $userId = $user['id'];
        $update_stmt = $conn->prepare("UPDATE users SET google_id = ? WHERE id = ? AND google_id IS NULL");
        if ($update_stmt) {
            $update_stmt->bind_param("si", $googleId, $userId);
            if (!$update_stmt->execute()) {
                log_error("Error updating google_id for user " . $userId . ": " . $update_stmt->error);
            }
            $update_stmt->close();
        }
        log_error("User logged in via Google (existing): " . $email . " (ID: " . $userId . ")");
    } else {
        log_error("User not found, attempting to register new via Google: " . $email);
        $userId = register_user($email, null, $googleId);
        if ($userId === false) {
            $msg = "Failed to register new user via Google.";
            log_error($msg . " Email: " . $email);
            $conn->close();
            return ['error' => $msg];
        }
        log_error("New user registered via Google: " . $email . " (ID: " . $userId . ")");
    }

    if ($userId) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $_SESSION['user_id'] = $userId;
        $_SESSION['user_email'] = $email;
        $_SESSION['user_name'] = $name;
        $conn->close();
        log_error("Google authentication successfully completed for user ID: " . $userId);
        return [
            'user_id' => $userId,
            'user_email' => $email,
            'user_name' => $name
        ];
    } else {
        $msg = "Google authentication failed: unable to get user ID.";
        log_error($msg);
        $conn->close();
        return ['error' => $msg];
    }
}

function is_user_logged_in() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    return $_SESSION['user_id'] ?? false;
}

function logout_user() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    session_unset();
    session_destroy();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    log_error("User logged out.");
}

function get_user_settings($userId) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to retrieve user settings " . $userId);
        return false;
    }

    $stmt = $conn->prepare("SELECT settings_json FROM users WHERE id = ?");
    if ($stmt === false) {
        log_error("Error preparing get_user_settings query: " . $conn->error . ". User ID: " . $userId);
        $conn->close();
        return false;
    }

    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        log_error("Error getting result for get_user_settings query: " . $stmt->error . ". User ID: " . $userId);
        $stmt->close();
        $conn->close();
        return false;
    }

    $user = $result->fetch_assoc();
    $stmt->close();
    $conn->close();

    if ($user && isset($user['settings_json'])) {
        $settings = json_decode($user['settings_json'], true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            log_error("Error decoding JSON settings for user " . $userId . ": " . json_last_error_msg() . ". JSON: " . $user['settings_json']);
            return [];
        }
        return $settings;
    }

    log_error("Settings not found for user " . $userId);
    return [];
}

function save_user_settings($userId, $settings) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to save user settings " . $userId);
        return false;
    }

    $settings_json = json_encode($settings);
    if ($settings_json === false) {
        log_error("Error encoding JSON settings for user " . $userId . ": " . json_last_error_msg() . ". Settings: " . print_r($settings, true));
        $conn->close();
        return false;
    }

    $stmt = $conn->prepare("UPDATE users SET settings_json = ? WHERE id = ?");
    if ($stmt === false) {
        log_error("Error preparing save_user_settings query: " . $conn->error . ". User ID: " . $userId);
        $conn->close();
        return false;
    }

    $stmt->bind_param("si", $settings_json, $userId);
    $result = $stmt->execute();

    if ($result === false) {
        log_error("Error executing save_user_settings query: " . $stmt->error . ". User ID: " . $userId . ". Settings JSON: " . $settings_json);
    }

    $stmt->close();
    $conn->close();
    return $result;
}
