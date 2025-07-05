<?php

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_error.log');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

$currentUserId = is_user_logged_in();

try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
        header('Content-Type: application/json');
        $currentUserId = is_user_logged_in();

        if (!$currentUserId) {
            http_response_code(401);
            echo json_encode(['error' => 'User is not authenticated.']);
            log_error('Attempt to access chat data without authorization.');
            exit();
        }

        switch ($_GET['action']) {
            case 'get_chat_history':
                if (!isset($_GET['chat_id'])) {
                    http_response_code(400);
                    echo json_encode(['error' => 'chat_id is required to get chat history.']);
                    log_error('Missing chat_id in get_chat_history request.');
                    exit();
                }
                $chatId = $_GET['chat_id'];
                $history = get_chat_history($chatId, $currentUserId);
                echo json_encode(['history' => $history]);
                exit();

            case 'get_user_chats':
                $chats = get_user_chats($currentUserId);
                echo json_encode(['chats' => $chats]);
                exit();

            case 'get_user_status':
                $userEmail = $_SESSION['user_email'] ?? null;
                $userName = $_SESSION['user_name'] ?? null;

                echo json_encode([
                    'logged_in' => (bool)$currentUserId,
                    'user_id' => $currentUserId,
                    'user_email' => $userEmail,
                    'user_name' => $userName
                ]);
                exit();

            default:
                http_response_code(400);
                echo json_encode(['error' => 'Unknown action.']);
                log_error('Unknown GET action: ' . $_GET['action']);
                exit();
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json');

        $action = $_POST['action'] ?? null;

        log_error('Received POST request. Action: ' . ($action ?? 'N/A') . '. POST data: ' . print_r($_POST, true));

        switch ($action) {
            case 'google_auth':
                if (!isset($_POST['id_token'])) {
                    http_response_code(400);
                    echo json_encode(['error' => 'ID Token not provided.']);
                    log_error('ID Token not provided for Google authentication.');
                    exit();
                }
                $idToken = $_POST['id_token'];
                $authResult = google_login_or_register($idToken);

                if (isset($authResult['user_id'])) {
                    echo json_encode([
                        'success' => true,
                        'user_id' => $authResult['user_id'],
                        'user_email' => $authResult['user_email'],
                        'user_name' => $authResult['user_name'],
                        'message' => 'Successful login via Google.'
                    ]);
                } else {
                    http_response_code(401);
                    echo json_encode(['success' => false, 'error' => $authResult['error'] ?? 'Google authentication error.']);
                }
                exit();

            case 'logout':
                logout_user();
                echo json_encode(['success' => true, 'message' => 'You have successfully logged out.']);
                exit();

            default:
                $input = file_get_contents('php://input');
                if ($input === false) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Failed to read incoming data.']);
                    log_error('Failed to read incoming data from php://input.');
                    exit();
                }

                $data = json_decode($input, true);

                log_error('Received POST request (JSON body). Data: ' . print_r($data, true));

                if (json_last_error() !== JSON_ERROR_NONE) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid JSON data format: ' . json_last_error_msg()]);
                    log_error('JSON decoding error: ' . json_last_error_msg() . ' Incoming data: ' . $input);
                    exit();
                }

                if (!isset($data['chat_id']) || !isset($data['user_id']) || (!isset($data['input_text']) && !isset($data['audio_data_base64']))) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid request data. chat_id, user_id, and (input_text or audio_data_base64) are required.']);
                    log_error('Invalid request data. Missing chat_id, user_id, or both input_text/audio_data_base64. Received: ' . print_r($data, true));
                    exit();
                }

                $chatId = $data['chat_id'];
                $userId = $data['user_id'];
                $inputText = $data['input_text'] ?? '';
                $audioDataBase64 = $data['audio_data_base64'] ?? null;

                $currentUserId = is_user_logged_in();
                if (!$currentUserId) {
                    http_response_code(401);
                    echo json_encode(['error' => 'User is not authenticated.']);
                    log_error('Attempt to send message without authorization.');
                    exit();
                }
                if ($currentUserId != $userId) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Session and request user_id mismatch.']);
                    log_error('User_id mismatch in POST request. Request: ' . $userId . ', session: ' . $currentUserId);
                    exit();
                }

                $n8nPayload = [
                    'user_id' => $userId,
                    'chat_id' => $chatId,
                    'input_text' => $inputText
                ];

                if ($audioDataBase64) {
                    $n8nPayload['user_audio_base64'] = $audioDataBase64;
                    log_error('Received voice message for chat_id: ' . $chatId . ', user_id: ' . $userId . '. Base64 length: ' . strlen($audioDataBase64));
                }

                $jsonPayload = json_encode($n8nPayload);
                if ($jsonPayload === false) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Error encoding JSON for n8n.']);
                    log_error('Error encoding JSON for n8n: ' . json_last_error_msg() . ' Payload: ' . print_r($n8nPayload, true));
                    exit();
                }

                $ch = curl_init(N8N_WEBHOOK_URL);
                if ($ch === false) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Failed to initialize cURL.']);
                    log_error('Failed to initialize cURL for ' . N8N_WEBHOOK_URL);
                    exit();
                }

                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonPayload);
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Content-Type: application/json',
                    'Content-Length: ' . strlen($jsonPayload)
                ]);

                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                $curlErrno = curl_errno($ch);
                curl_close($ch);

                if ($curlError) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Error sending request to n8n: ' . $curlError . ' (Code: ' . $curlErrno . ')']);
                    log_error('cURL error sending to n8n: ' . $curlError . ' (Code: ' . $curlErrno . '). URL: ' . N8N_WEBHOOK_URL . '. Payload: ' . substr($jsonPayload, 0, 500) . '...');
                    exit();
                }

                if ($httpCode !== 200) {
                    http_response_code(500);
                    echo json_encode(['error' => 'n8n returned an error: HTTP ' . $httpCode . '. Response: ' . (is_string($response) ? substr($response, 0, 200) : 'Unknown response')]);
                    log_error('n8n returned HTTP error ' . $httpCode . '. Response: ' . (is_string($response) ? $response : 'Unknown response') . '. Request: ' . substr($jsonPayload, 0, 500) . '...');
                    exit();
                }

                $n8nResponse = json_decode($response, true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Invalid JSON format from n8n response: ' . json_last_error_msg()]);
                    log_error('JSON decoding error from n8n response: ' . json_last_error_msg() . '. Full response: ' . (is_string($response) ? $response : 'Unknown response type'));
                    exit();
                }

                if (!isset($n8nResponse['text_response'])) {
                    if (isset($n8nResponse['output'])) {
                        $n8nResponse['text_response'] = $n8nResponse['output'];
                    } else {
                        http_response_code(500);
                        echo json_encode(['error' => 'Invalid response format from n8n.']);
                        log_error('Invalid response format from n8n. Received: ' . print_r($n8nResponse, true));
                        exit();
                    }
                }
                if (!isset($n8nResponse['audio_url'])) {
                    $n8nResponse['audio_url'] = '';
                }

                $currentUserId = is_user_logged_in();
                if ($currentUserId) {
                    if (!save_interaction($chatId, $currentUserId, $inputText, $n8nResponse['text_response'], $n8nResponse['audio_url'])) {
                        log_error('Failed to save interaction to DB for chat_id: ' . $chatId . ', user_id: ' . $currentUserId . '. Input: ' . $inputText);
                    }
                } else {
                    log_error('Attempt to save interaction to DB without authenticated user. Chat ID: ' . $chatId . '. Input: ' . $inputText);
                }

                echo json_encode([
                    'text_response' => $n8nResponse['text_response'],
                    'audio_url' => $n8nResponse['audio_url']
                ]);
                exit();
        }
    }
} catch (Throwable $e) {
    header('Content-Type: application/json');
    http_response_code(500);
    log_error("Uncaught error in index.php: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine() . "\n" . $e->getTraceAsString());
    echo json_encode(['error' => 'An unexpected server error occurred. Please try again later.']);
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Voice Assistant</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #1a1a1a;
            color: #e0e0e0;
            transition: background-color 0.3s ease, color 0.3s ease;
            overflow: hidden;
        }

        body.light {
            background-color: #f0f2f5;
            color: #1a1a1a;
        }

        .app-container {
            display: flex;
            width: 100%;
            height: 100vh;
            max-height: 100vh;
            background-color: #1a1a1a;
            border-radius: 1.5rem;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            transition: background-color 0.3s ease, box-shadow 0.3s ease;
        }
        body.light .app-container {
            background-color: #ffffff;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }

        .sidebar {
            width: 280px;
            flex-shrink: 0;
            background-color: #2c2c2c;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            border-right: 1px solid #3a3a3a;
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }
        body.light .sidebar {
            background-color: #f8f9fa;
            border-right-color: #e2e8f0;
        }

        .sidebar-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 2rem;
            color: #e0e0e0;
        }
        body.light .sidebar-header {
            color: #1a1a1a;
        }

        .sidebar-logo {
            font-weight: bold;
            font-size: 1.5rem;
        }

        .sidebar-search {
            background-color: #3a3a3a;
            border: 1px solid #4a4a4a;
            padding: 0.75rem 1rem;
            border-radius: 0.75rem;
            color: #e0e0e0;
            outline: none;
            width: 100%;
            margin-bottom: 1.5rem;
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }
        body.light .sidebar-search {
            background-color: #ffffff;
            border-color: #cbd5e0;
            color: #2d3748;
        }
        .sidebar-search::placeholder {
            color: #a0a0a0;
        }
        body.light .sidebar-search::placeholder {
            color: #666;
        }

        .sidebar-button {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            border-radius: 0.75rem;
            background-color: #3b82f6;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s ease;
            margin-bottom: 1rem;
        }
        .sidebar-button:hover {
            background-color: #2563eb;
        }
        .sidebar-button.secondary {
            background-color: #4a4a4a;
            color: #e0e0e0;
        }
        .sidebar-button.secondary:hover {
            background-color: #5a5a5a;
        }
        body.light .sidebar-button.secondary {
            background-color: #e2e8f0;
            color: #2d3748;
        }
        body.light .sidebar-button.secondary:hover {
            background-color: #cbd5e0;
        }

        .sidebar-chats-list {
            flex-grow: 1;
            overflow-y: auto;
            margin-top: 1rem;
            padding-right: 0.5rem;
        }
        .sidebar-chat-item {
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            margin-bottom: 0.5rem;
            background-color: transparent;
            transition: background-color 0.2s ease;
            color: #e0e0e0;
            font-size: 0.9rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .sidebar-chat-item:hover {
            background-color: #3a3a3a;
        }
        .sidebar-chat-item.active {
            background-color: #3b82f6;
            color: white;
        }
        body.light .sidebar-chat-item {
            color: #2d3748;
        }
        body.light .sidebar-chat-item:hover {
            background-color: #f0f0f0;
        }
        body.light .sidebar-chat-item.active {
            background-color: #3b82f6;
            color: white;
        }
        .sidebar-chat-item-date {
            font-size: 0.75rem;
            color: #a0a0a0;
        }
        body.light .sidebar-chat-item-date {
            color: #666;
        }
        .sidebar-chat-item.active .sidebar-chat-item-date {
            color: rgba(255, 255, 255, 0.7);
        }

        .main-content {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: space-between;
            padding: 2rem;
            position: relative;
        }

        .main-header {
            width: 100%;
            display: flex;
            justify-content: flex-end;
            padding-bottom: 1rem;
            position: absolute;
            top: 2rem;
            right: 2rem;
            left: 2rem;
            z-index: 10;
        }

        .user-profile-dropdown {
            position: relative;
            cursor: pointer;
        }
        .user-profile-avatar {
            width: 40px;
            height: 40px;
            border-radius: 9999px;
            background-color: #3b82f6;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: white;
            font-size: 1.1rem;
        }
        .user-profile-menu {
            position: absolute;
            top: 100%;
            right: 0;
            background-color: #2c2c2c;
            border-radius: 0.75rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            padding: 0.5rem;
            min-width: 200px;
            z-index: 20;
            display: none;
            flex-direction: column;
            gap: 0.25rem;
            border: 1px solid #4a4a4a;
        }
        body.light .user-profile-menu {
            background-color: #ffffff;
            border-color: #e2e8f0;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        .user-profile-menu.show {
            display: flex;
        }
        .user-profile-info {
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
            color: #e0e0e0;
            border-bottom: 1px solid #4a4a4a;
            margin-bottom: 0.5rem;
        }
        body.light .user-profile-info {
            color: #2d3748;
            border-bottom-color: #e2e8f0;
        }
        .user-profile-info span {
            display: block;
            font-weight: 600;
        }
        .user-profile-menu-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            color: #e0e0e0;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        .user-profile-menu-item:hover {
            background-color: #3a3a3a;
        }
        body.light .user-profile-menu-item {
            color: #2d3748;
        }
        body.light .user-profile-menu-item:hover {
            background-color: #f0f0f0;
        }

        .central-content {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding-bottom: 2rem;
        }

        .main-title {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            color: #e0e0e0;
        }
        .main-title .highlight {
            color: #3b82f6;
        }
        body.light .main-title {
            color: #1a1a1a;
        }

        .sub-title {
            font-size: 1.25rem;
            color: #a0a0a0;
            margin-bottom: 2rem;
        }
        body.light .sub-title {
            color: #666;
        }

        .main-input-area {
            width: 80%;
            max-width: 600px;
            background-color: #2c2c2c;
            border: 1px solid #4a4a4a;
            border-radius: 1.5rem;
            padding: 0.75rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 2rem;
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }
        body.light .main-input-area {
            background-color: #ffffff;
            border-color: #cbd5e0;
        }
        .main-input {
            flex-grow: 1;
            background: none;
            border: none;
            outline: none;
            color: #e0e0e0;
            font-size: 1rem;
        }
        body.light .main-input {
            color: #2d3748;
        }
        .main-input::placeholder {
            color: #a0a0a0;
        }
        body.light .main-input::placeholder {
            color: #666;
        }
        .input-action-link {
            color: #3b82f6;
            font-size: 0.9rem;
            cursor: pointer;
            white-space: nowrap;
        }
        .input-action-link:hover {
            text-decoration: underline;
        }
        .main-input-microphone {
            color: #a0a0a0;
            font-size: 1.25rem;
            cursor: pointer;
        }
        .main-input-microphone:hover {
            color: #e0e0e0;
        }
        body.light .main-input-microphone {
            color: #666;
        }
        body.light .main-input-microphone:hover {
            color: #2d3748;
        }

        .feature-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            width: 80%;
            max-width: 900px;
        }
        .feature-card {
            background-color: #2c2c2c;
            border: 1px solid #4a4a4a;
            border-radius: 1rem;
            padding: 1.5rem;
            text-align: left;
            transition: background-color 0.2s ease, border-color 0.2s ease;
            cursor: pointer;
        }
        .feature-card:hover {
            background-color: #3a3a3a;
            border-color: #5a5a5a;
        }
        body.light .feature-card {
            background-color: #ffffff;
            border-color: #e2e8f0;
        }
        body.light .feature-card:hover {
            background-color: #f0f0f0;
            border-color: #cbd5e0;
        }
        .feature-card-icon {
            font-size: 1.5rem;
            color: #3b82f6;
            margin-bottom: 0.75rem;
        }
        .feature-card-title {
            font-weight: 600;
            color: #e0e0e0;
            margin-bottom: 0.25rem;
        }
        body.light .feature-card-title {
            color: #1a1a1a;
        }
        .feature-card-description {
            font-size: 0.9rem;
            color: #a0a0a0;
        }
        body.light .feature-card-description {
            color: #666;
        }

        .chat-messages {
            flex-grow: 1;
            overflow-y: auto;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background-color: #1a1a1a;
            color: #e0e0e0;
        }
        body.light .chat-messages {
            background-color: #ffffff;
            color: #1a1a1a;
        }
        .message {
            max-width: 80%;
            padding: 0.75rem 1.25rem;
            border-radius: 1.25rem;
            word-wrap: break-word;
            line-height: 1.5;
        }
        .message.user {
            background-color: #3b82f6;
            align-self: flex-end;
            color: white;
            border-bottom-right-radius: 0.5rem;
        }
        .message.assistant {
            background-color: #2c2c2c;
            align-self: flex-start;
            color: #e0e0e0;
            border-bottom-left-radius: 0.5rem;
        }
        body.light .message.assistant {
            background-color: #f0f4f8;
            color: #2d3748;
        }

        .loading-indicator {
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 0.5rem;
            padding: 0.75rem 1.25rem;
            border-radius: 1.25rem;
            background-color: #2c2c2c;
            color: #e0e0e0;
            align-self: flex-start;
            max-width: 80%;
        }
        body.light .loading-indicator {
            background-color: #f0f4f8;
            color: #2d3748;
        }
        .loading-indicator span {
            animation: blink 1s infinite;
        }
        .loading-indicator span:nth-child(2) { animation-delay: 0.2s; }
        .loading-indicator span:nth-child(3) { animation-delay: 0.4s; }
        @keyframes blink {
            0%, 100% { opacity: 0.2; }
            50% { opacity: 1; }
        }

        .chat-input-area {
            display: flex;
            padding: 1.5rem;
            background-color: #1a1a1a;
            border-top: 1px solid #3a3a3a;
            gap: 0.75rem;
        }
        body.light .chat-input-area {
            background-color: #ffffff;
            border-top-color: #e2e8f0;
        }
        .chat-input {
            flex-grow: 1;
            padding: 0.75rem 1rem;
            border: 1px solid #4a4a4a;
            border-radius: 1.5rem;
            outline: none;
            font-size: 1rem;
            background-color: #2c2c2c;
            color: #e0e0e0;
            transition: border-color 0.2s ease, background-color 0.2s ease;
        }
        body.light .chat-input {
            background-color: #ffffff;
            border-color: #cbd5e0;
            color: #2d3748;
        }
        .chat-input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
        }
        .send-button {
            background-color: #3b82f6;
            color: white;
            padding: 0.75rem 1.25rem;
            border-radius: 1.5rem;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            transition: background-color 0.2s ease, transform 0.1s ease;
        }
        .send-button:hover { background-color: #2563eb; transform: translateY(-1px); }
        .send-button:active { background-color: #1d4ed8; transform: translateY(0); }
        .play-audio-button {
            background: none; border: none; color: #3b82f6; cursor: pointer; font-size: 1.1rem; margin-left: 0.75rem; transition: color 0.2s ease;
        }
        .play-audio-button:hover { color: #2563eb; }

        .record-button {
            background-color: #2c2c2c;
            border: 1px solid #4a4a4a;
            border-radius: 9999px;
            padding: 0.75rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            transition: background-color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
            color: #e0e0e0;
        }
        body.light .record-button {
            background-color: #ffffff;
            border-color: #cbd5e0;
            color: #2d3748;
        }
        .record-button.recording {
            background-color: #ef4444;
            color: white;
            animation: pulse 1s infinite;
        }
        .record-button.recording i {
            color: white;
        }

        .modal {
            position: fixed;
            z-index: 100;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.6);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        body.light .modal {
            background-color: rgba(0,0,0,0.4);
        }

        .modal-content {
            background-color: #2c2c2c;
            margin: auto;
            padding: 20px;
            border-radius: 1rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.5);
            width: 90%;
            max-width: 500px;
            position: relative;
            display: flex;
            flex-direction: column;
            max-height: 80vh;
            overflow-y: auto;
            color: #e0e0e0;
        }
        body.light .modal-content {
            background-color: #fefefe;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            color: #1a1a1a;
        }

        .close-button {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            position: absolute;
            top: 10px;
            right: 20px;
            cursor: pointer;
        }
        .close-button:hover, .close-button:focus { color: #fff; }
        body.light .close-button:hover, body.light .close-button:focus { color: #000; }

        .auth-modal-content { text-align: center; }
        .auth-modal-content .message-box {
            margin-top: 1rem; padding: 0.75rem; border-radius: 0.5rem; background-color: #4a4a4a; color: #e0e0e0; font-size: 0.9rem;
        }
        body.light .auth-modal-content .message-box {
            background-color: #e0f2fe; color: #1a202c;
        }
        .auth-modal-content hr { margin: 1.5rem 0; border-color: #4a4a4a; }
        body.light .auth-modal-content hr { border-color: #e2e8f0; }

        @media (max-width: 768px) {
            .app-container {
                flex-direction: column;
                border-radius: 0;
                height: 100vh;
                max-height: 100vh;
            }
            .sidebar {
                width: 100%;
                height: auto;
                border-right: none;
                border-bottom: 1px solid #3a3a3a;
                padding-bottom: 1rem;
            }
            body.light .sidebar {
                border-bottom-color: #e2e8f0;
            }
            .sidebar-chats-list {
                display: none;
            }
            .main-content {
                padding: 1rem;
            }
            .main-header {
                position: static;
                justify-content: center;
                padding-bottom: 0;
                margin-bottom: 1rem;
            }
            .main-title {
                font-size: 2rem;
            }
            .sub-title {
                font-size: 1rem;
            }
            .main-input-area {
                width: 95%;
                padding: 0.5rem 1rem;
            }
            .feature-cards {
                grid-template-columns: 1fr;
                width: 95%;
            }
            .chat-input-area {
                flex-direction: column;
                gap: 0.5rem;
                padding: 1rem;
            }
            .send-button {
                width: 100%;
            }
            .top-right-buttons {
                position: static;
                flex-direction: row;
                width: 100%;
                justify-content: flex-end;
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body class="dark">
    <div class="app-container">
        <div class="sidebar">
            <div class="sidebar-header">
                <i class="fas fa-robot text-2xl"></i>
                <span class="sidebar-logo">Dash</span>
            </div>

            <input type="text" class="sidebar-search" placeholder="Search threads...">

            <button id="new-chat-button" class="sidebar-button">
                <i class="fas fa-plus"></i> New Chat
            </button>

            <button id="workflows-button" class="sidebar-button secondary">
                <i class="fas fa-cogs"></i> Workflows
            </button>

            <div class="text-xs text-gray-500 uppercase mb-2 mt-4">Previous 7 Days</div>
            <div id="sidebar-chats-list" class="sidebar-chats-list">
                <p class="text-gray-600 dark:text-gray-400 text-center text-sm" id="sidebar-no-chats-message">Loading chats...</p>
            </div>
        </div>

        <div class="main-content">
            <div class="main-header">
                <div id="user-profile-dropdown" class="user-profile-dropdown">
                    <div id="user-profile-avatar" class="user-profile-avatar">V</div>
                    <div id="user-profile-menu" class="user-profile-menu">
                        <div class="user-profile-info">
                            <span id="profile-user-name">Guest</span>
                            <span id="profile-user-email">Not authenticated</span>
                        </div>
                        <div id="login-menu-item" class="user-profile-menu-item">
                            <i class="fas fa-sign-in-alt"></i> Sign in
                        </div>
                        <div id="settings-menu-item" class="user-profile-menu-item">
                            <i class="fas fa-cog"></i> Settings
                        </div>
                        <div id="sign-out-menu-item" class="user-profile-menu-item">
                            <i class="fas fa-sign-out-alt"></i> Sign out
                        </div>
                    </div>
                </div>
                <button id="theme-toggle" class="theme-toggle-button ml-2" title="Toggle theme">
                    <i class="fas fa-sun"></i>
                </button>
            </div>

            <div id="central-content" class="central-content">
                <h2 class="main-title">Words to actions <span class="highlight">in seconds</span></h2>
                <p class="sub-title">Dash is your AI agent for Gmail, Calendar, Notion, and more</p>

                <div class="main-input-area">
                    <input type="text" id="message-input" class="main-input" placeholder="Ask anything...">
                    <a href="#" class="input-action-link">Add integration</a>
                    <button id="record-button" class="main-input-microphone" title="Record voice message">
                        <i class="fas fa-microphone"></i>
                    </button>
                </div>

                <div class="feature-cards">
                    <div class="feature-card">
                        <i class="fas fa-chart-line feature-card-icon"></i>
                        <div class="feature-card-title">Sprint Planning</div>
                        <div class="feature-card-description">Look at Linear and create a sprint plan for the next 2 weeks</div>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-calendar-alt feature-card-icon"></i>
                        <div class="feature-card-title">Summarize Meetings</div>
                        <div class="feature-card-description">Summarize my key meetings this week from Google Calendar.</div>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-envelope-open-text feature-card-icon"></i>
                        <div class="feature-card-title">Scan Emails</div>
                        <div class="feature-card-description">Check my emails and send out meetings to anyone needed</div>
                    </div>
                </div>
            </div>

            <div id="chat-messages" class="chat-messages" style="display: none;">
            </div>

            <div id="chat-input-area" class="chat-input-area" style="display: none;">
                <input type="text" id="chat-message-input" class="chat-input" placeholder="Enter your message...">
                <button id="chat-send-button" class="send-button">
                    <i class="fas fa-paper-plane"></i> Send
                </button>
            </div>
        </div>
    </div>

    <div id="auth-modal" class="modal" style="display: none;">
        <div class="modal-content auth-modal-content">
            <span class="close-button" id="auth-modal-close-button">&times;</span>
            <h2 class="text-xl font-bold mb-4 text-gray-800 dark:text-gray-100" id="auth-modal-title">Login / Register</h2>

            <div id="auth-content">
                <div id="g_id_onload"
                     data-client_id="<?php echo GOOGLE_CLIENT_ID; ?>"
                     data-callback="handleGoogleAuth"
                     data-auto_prompt="false">
                </div>
                <div class="g_id_signin"
                     data-type="standard"
                     data-size="large"
                     data-theme="outline"
                     data-text="sign_in_with"
                     data-shape="rectangular"
                     data-logo_alignment="left">
                </div>

                <div class="mt-4 text-gray-600 dark:text-gray-400 message-box" id="auth-status-message" style="display: none;"></div>

                <hr class="my-6 border-gray-300 dark:border-gray-600">

                <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    Authenticate to use all chat features and save history.
                </p>
            </div>

            <div id="logout-content" style="display: none;">
                <p class="text-lg text-gray-800 dark:text-gray-100 mb-4">You are logged in as User ID: <span id="logged-in-user-id"></span></p>
                <button id="logout-button" class="send-button bg-red-500 hover:bg-red-600">Logout</button>
            </div>
        </div>
    </div>

    <script>
        const appContainer = document.querySelector('.app-container');
        const sidebar = document.querySelector('.sidebar');
        const sidebarSearch = document.querySelector('.sidebar-search');
        const newChatButton = document.getElementById('new-chat-button');
        const workflowsButton = document.getElementById('workflows-button');
        const sidebarChatsList = document.getElementById('sidebar-chats-list');
        const sidebarNoChatsMessage = document.getElementById('sidebar-no-chats-message');

        const mainContent = document.querySelector('.main-content');
        const centralContent = document.getElementById('central-content');
        const mainInputArea = document.querySelector('.main-input-area');
        const mainInput = document.getElementById('message-input');
        const mainInputMicrophone = document.getElementById('record-button');

        const chatMessages = document.getElementById('chat-messages');
        const chatInputArea = document.getElementById('chat-input-area');
        const chatMessageInput = document.getElementById('chat-message-input');
        const chatSendButton = document.getElementById('chat-send-button');

        const userProfileDropdown = document.getElementById('user-profile-dropdown');
        const userProfileAvatar = document.getElementById('user-profile-avatar');
        const userProfileMenu = document.getElementById('user-profile-menu');
        const profileUserName = document.getElementById('profile-user-name');
        const profileUserEmail = document.getElementById('profile-user-email');
        const loginMenuItem = document.getElementById('login-menu-item');
        const settingsMenuItem = document.getElementById('settings-menu-item');
        const signOutMenuItem = document.getElementById('sign-out-menu-item');
        const themeToggleButton = document.getElementById('theme-toggle');

        const authModal = document.getElementById('auth-modal');
        const authModalCloseButton = document.getElementById('auth-modal-close-button');
        const authModalTitle = document.getElementById('auth-modal-title');
        const authContent = document.getElementById('auth-content');
        const logoutContent = document.getElementById('logout-content');
        const loggedInUserIdSpan = document.getElementById('logged-in-user-id');
        const logoutButton = document.getElementById('logout-button');
        const authStatusMessage = document.getElementById('auth-status-message');

        const body = document.body;

        let CURRENT_USER_ID = null;
        let CURRENT_USER_EMAIL = null;
        let CURRENT_USER_NAME = null;

        let currentChatId = localStorage.getItem('currentChatId') || null;
        let loadingIndicator = null;
        let mediaRecorder;
        let audioChunks = [];
        let isRecording = false;
        let isChatActive = false;

        async function updateAuthUI() {
            const response = await fetch('index.php?action=get_user_status');
            const data = await response.json();

            if (data.logged_in) {
                CURRENT_USER_ID = data.user_id;
                CURRENT_USER_EMAIL = data.user_email;
                CURRENT_USER_NAME = data.user_name;

                profileUserName.textContent = CURRENT_USER_NAME || `User ID: ${CURRENT_USER_ID}`;
                profileUserEmail.textContent = CURRENT_USER_EMAIL || 'Authenticated';
                userProfileAvatar.textContent = (CURRENT_USER_NAME || CURRENT_USER_EMAIL || 'U').charAt(0).toUpperCase();
                userProfileAvatar.title = CURRENT_USER_NAME || CURRENT_USER_EMAIL || 'Authenticated';

                loadUserChats();
                mainInput.disabled = false;
                mainInputMicrophone.disabled = false;
                newChatButton.disabled = false;
                workflowsButton.disabled = false;
                loginMenuItem.style.display = 'none';
                settingsMenuItem.style.display = 'block';
                signOutMenuItem.style.display = 'block';

            } else {
                CURRENT_USER_ID = null;
                CURRENT_USER_EMAIL = null;
                CURRENT_USER_NAME = null;
                profileUserName.textContent = 'Guest';
                profileUserEmail.textContent = 'Not authenticated';
                userProfileAvatar.textContent = 'G';
                userProfileAvatar.title = 'Not authenticated';

                mainInput.disabled = true;
                mainInputMicrophone.disabled = true;
                newChatButton.disabled = true;
                workflowsButton.disabled = true;
                sidebarChatsList.innerHTML = `<p class="text-gray-600 dark:text-gray-400 text-center text-sm" id="sidebar-no-chats-message">Authenticate to see your chats.</p>`;
                loginMenuItem.style.display = 'block';
                settingsMenuItem.style.display = 'none';
                signOutMenuItem.style.display = 'none';
            }
        }

        function toggleChatView(showChat) {
            if (showChat) {
                centralContent.style.display = 'none';
                chatMessages.style.display = 'flex';
                chatInputArea.style.display = 'flex';
                isChatActive = true;
                chatMessageInput.focus();
            } else {
                centralContent.style.display = 'flex';
                chatMessages.style.display = 'none';
                chatInputArea.style.display = 'none';
                isChatActive = false;
                mainInput.focus();
            }
        }

        function addMessage(text, sender, audioUrl = null, isVoiceMessage = false) {
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', sender, 'message-animation');

            if (isVoiceMessage && sender === 'user') {
                messageDiv.innerHTML = `<i class="fas fa-microphone mr-2"></i>Voice message`;
            } else {
                messageDiv.textContent = text;
            }

            if (sender === 'assistant' && audioUrl) {
                const playButton = document.createElement('button');
                playButton.classList.add('play-audio-button');
                playButton.innerHTML = '<i class="fas fa-volume-up"></i>';
                playButton.title = 'Play audio';
                playButton.onclick = () => playAudio(url);
                messageDiv.appendChild(playButton);
            }

            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function showLoadingIndicator() {
            if (loadingIndicator) return;

            loadingIndicator = document.createElement('div');
            loadingIndicator.classList.add('loading-indicator', 'message-animation');
            loadingIndicator.innerHTML = `<span>.</span><span>.</span><span>.</span>`;
            chatMessages.appendChild(loadingIndicator);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function hideLoadingIndicator() {
            if (loadingIndicator) {
                loadingIndicator.remove();
                loadingIndicator = null;
            }
        }

        function playAudio(url) {
            const audio = new Audio(url);
            audio.play().catch(e => {
                console.error("Audio playback error:", e);
            });
        }

        async function sendMessageToServer(inputText, audioDataBase64 = null) {
            if (!CURRENT_USER_ID) {
                addMessage('Please authenticate to send messages.', 'assistant');
                return;
            }

            chatSendButton.disabled = true;
            chatMessageInput.disabled = true;
            mainInputMicrophone.disabled = true;
            if (isChatActive) {
                mainInputMicrophone.disabled = true;
            }


            showLoadingIndicator();

            try {
                const payload = {
                    user_id: CURRENT_USER_ID,
                    chat_id: currentChatId,
                };

                if (inputText) {
                    payload.input_text = inputText;
                }
                if (audioDataBase64) {
                    payload.audio_data_base64 = audioDataBase64;
                }

                const response = await fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                console.log('Raw response from PHP (n8n response):', response);

                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('Raw error response text from PHP:', errorText);
                    try {
                        const errorData = JSON.parse(errorText);
                        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                    } catch (e) {
                        throw new Error(`HTTP error! status: ${response.status}. Response: ${errorText.substring(0, 200)}...`);
                    }
                }

                const data = await response.json();
                console.log('Parsed data from PHP (n8n response):', data);

                hideLoadingIndicator();

                addMessage(data.text_response, 'assistant', data.audio_url);

            } catch (error) {
                console.error("Error sending message:", error);
                hideLoadingIndicator();
                addMessage(`An error occurred: ${error.message}. Please try again.`, 'assistant');
            } finally {
                chatSendButton.disabled = false;
                chatMessageInput.disabled = false;
                mainInputMicrophone.disabled = false;
                chatMessageInput.focus();
            }
        }

        async function sendMainScreenTextMessage() {
            const inputText = mainInput.value.trim();
            if (inputText === '') return;

            if (!isChatActive) {
                toggleChatView(true);
                chatMessages.innerHTML = '';
            }
            addMessage(inputText, 'user');
            mainInput.value = '';
            chatMessageInput.value = inputText;
            await sendMessageToServer(inputText);
        }

        async function sendChatMessage() {
            const inputText = chatMessageInput.value.trim();
            if (inputText === '') return;

            addMessage(inputText, 'user');
            chatMessageInput.value = '';
            await sendMessageToServer(inputText);
        }

        mainInputMicrophone.addEventListener('click', async () => {
            if (!CURRENT_USER_ID) {
                addMessage('Please authenticate for voice messages.', 'assistant');
                return;
            }

            if (!isRecording) {
                try {
                    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                    mediaRecorder = new MediaRecorder(stream);
                    audioChunks = [];

                    mediaRecorder.ondataavailable = event => {
                        audioChunks.push(event.data);
                    };

                    mediaRecorder.onstop = async () => {
                        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                        const reader = new FileReader();
                        reader.readAsDataURL(audioBlob);
                        reader.onloadend = async () => {
                            const base64data = reader.result.split(',')[1];
                            console.log('Sending voice message (Base64 length):', base64data.length);

                            if (!isChatActive) {
                                toggleChatView(true);
                                chatMessages.innerHTML = '';
                            }
                            addMessage('Voice message', 'user', null, true);
                            await sendMessageToServer('', base64data);
                        };
                    };

                    mediaRecorder.start();
                    isRecording = true;
                    mainInputMicrophone.classList.add('recording');
                    mainInputMicrophone.innerHTML = '<i class="fas fa-stop"></i>';
                    mainInput.disabled = true;
                    chatMessageInput.disabled = true;
                    chatSendButton.disabled = true;
                    console.log('Recording started...');
                } catch (err) {
                    console.error('Microphone access error:', err);
                    alert('Could not access microphone. Please allow access.');
                }
            } else {
                mediaRecorder.stop();
                isRecording = false;
                mainInputMicrophone.classList.remove('recording');
                mainInputMicrophone.innerHTML = '<i class="fas fa-microphone"></i>';
                mainInput.disabled = false;
                chatMessageInput.disabled = false;
                chatSendButton.disabled = false;
                console.log('Recording stopped.');
            }
        });


        mainInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !mainInput.disabled) {
                sendMainScreenTextMessage();
            }
        });

        chatSendButton.addEventListener('click', sendChatMessage);
        chatMessageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !chatMessageInput.disabled) {
                sendChatMessage();
            }
        });

        themeToggleButton.addEventListener('click', () => {
            if (body.classList.contains('dark')) {
                body.classList.remove('dark');
                body.classList.add('light');
                themeToggleButton.innerHTML = '<i class="fas fa-moon"></i>';
            } else {
                body.classList.remove('light');
                body.classList.add('dark');
                themeToggleButton.innerHTML = '<i class="fas fa-sun"></i>';
            }
            localStorage.setItem('theme', body.classList.contains('dark') ? 'dark' : 'light');
        });

        newChatButton.addEventListener('click', () => {
            currentChatId = crypto.randomUUID();
            localStorage.setItem('currentChatId', currentChatId);
            toggleChatView(true);
            chatMessages.innerHTML = `
                <div class="message assistant message-animation">
                    Hello! I am your AI assistant. How can I help you?
                </div>
            `;
            chatMessageInput.value = '';
            mainInput.value = '';
            console.log('New chat created with ID:', currentChatId);
            chatMessageInput.focus();
            loadUserChats();
        });

        async function loadChatHistory(chatId) {
            toggleChatView(true);
            chatMessages.innerHTML = '';
            showLoadingIndicator();

            try {
                const response = await fetch(`index.php?action=get_chat_history&chat_id=${chatId}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('Raw error response text from PHP (get_chat_history):', errorText);
                    try {
                        const errorData = JSON.parse(errorText);
                        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                    } catch (e) {
                        throw new Error(`HTTP error! status: ${response.status}. Response: ${errorText.substring(0, 200)}...`);
                    }
                }

                const data = await response.json();
                hideLoadingIndicator();

                if (data.history && data.history.length > 0) {
                    data.history.forEach(msg => {
                        if (msg.input_text) {
                            addMessage(msg.input_text, 'user');
                        }
                        if (msg.output_text) {
                            addMessage(msg.output_text, 'assistant', msg.audio_url);
                        }
                        if (msg.is_voice_message && !msg.input_text) {
                            addMessage('Voice message', 'user', null, true);
                        }
                    });
                } else {
                    addMessage('Hello! I am your AI assistant. How can I help you?', 'assistant');
                }
            } catch (error) {
                console.error("Error loading chat history:", error);
                hideLoadingIndicator();
                addMessage(`An error occurred while loading chat: ${error.message}.`, 'assistant');
            }
        }

        async function loadUserChats() {
            if (!CURRENT_USER_ID) {
                sidebarNoChatsMessage.textContent = 'Authenticate to see your chats.';
                return;
            }
            sidebarChatsList.innerHTML = '';
            sidebarNoChatsMessage.style.display = 'block';

            try {
                const response = await fetch(`index.php?action=get_user_chats`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('Raw error response text from PHP (get_user_chats):', errorText);
                    try {
                        const errorData = JSON.parse(errorText);
                        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                    } catch (e) {
                        throw new Error(`HTTP error! status: ${response.status}. Response: ${errorText.substring(0, 200)}...`);
                    }
                }

                const data = await response.json();

                if (data.chats && data.chats.length > 0) {
                    sidebarNoChatsMessage.style.display = 'none';
                    data.chats.forEach(chat => {
                        const chatItem = document.createElement('div');
                        chatItem.classList.add('sidebar-chat-item');
                        if (chat.chat_id === currentChatId) {
                            chatItem.classList.add('active');
                        }
                        chatItem.dataset.chatId = chat.chat_id;
                        chatItem.innerHTML = `
                            <span class="chat-list-item-title">${chat.title}</span>
                            <span class="chat-list-item-date">${new Date(chat.created_at).toLocaleDateString()}</span>
                        `;
                        chatItem.addEventListener('click', () => {
                            if (currentChatId !== chat.chat_id) {
                                const activeChat = document.querySelector('.sidebar-chat-item.active');
                                if (activeChat) activeChat.classList.remove('active');
                                chatItem.classList.add('active');
                                currentChatId = chat.chat_id;
                                localStorage.setItem('currentChatId', currentChatId);
                                loadChatHistory(currentChatId);
                            }
                        });
                        sidebarChatsList.appendChild(chatItem);
                    });
                } else {
                    sidebarNoChatsMessage.textContent = 'You don\'t have any chats yet. Start a new one!';
                }

            } catch (error) {
                console.error("Error loading chat list:", error);
                sidebarNoChatsMessage.textContent = `Error loading chats: ${error.message}`;
            }
        }


        userProfileDropdown.addEventListener('click', (event) => {
            event.stopPropagation();
            userProfileMenu.classList.toggle('show');
        });

        window.addEventListener('click', (event) => {
            if (!userProfileDropdown.contains(event.target) && userProfileMenu.classList.contains('show')) {
                userProfileMenu.classList.remove('show');
            }
        });

        settingsMenuItem.addEventListener('click', () => {
            userProfileMenu.classList.remove('show');
            authModal.style.display = 'flex';
            authModalTitle.textContent = 'Profile Settings';
            authContent.style.display = 'none';
            logoutContent.style.display = 'block';
            loggedInUserIdSpan.textContent = CURRENT_USER_ID;
        });

        signOutMenuItem.addEventListener('click', async () => {
            userProfileMenu.classList.remove('show');
            await handleLogout();
        });

        loginMenuItem.addEventListener('click', () => {
            userProfileMenu.classList.remove('show');
            authModal.style.display = 'flex';
            authModalTitle.textContent = 'Login / Register';
            authContent.style.display = 'block';
            logoutContent.style.display = 'none';
        });

        authModalCloseButton.addEventListener('click', () => {
            authModal.style.display = 'none';
        });

        window.handleGoogleAuth = async (response) => {
            console.log('Google ID Token:', response.credential);
            authStatusMessage.textContent = 'Authenticating with Google...';
            authStatusMessage.style.display = 'block';
            authStatusMessage.classList.remove('bg-red-200', 'text-red-800', 'bg-blue-200', 'text-blue-800');
            authStatusMessage.classList.add('bg-gray-200', 'text-gray-800');


            try {
                const res = await fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=google_auth&id_token=${response.credential}`
                });

                if (!res.ok) {
                    const errorText = await res.text();
                    console.error('Raw error response text from PHP (Google Auth):', errorText);
                    try {
                        const errorData = JSON.parse(errorText);
                        throw new Error(errorData.error || `HTTP error! status: ${res.status}`);
                    } catch (e) {
                        throw new Error(`HTTP error! status: ${res.status}. Response: ${errorText.substring(0, 200)}...`);
                    }
                }

                const data = await res.json();
                if (data.success) {
                    console.log('Google Auth Success:', data);
                    authStatusMessage.textContent = 'Successful login!';
                    authStatusMessage.classList.remove('bg-gray-200', 'text-gray-800');
                    authStatusMessage.classList.add('bg-blue-200', 'text-blue-800');
                    CURRENT_USER_ID = data.user_id;
                    const decodedToken = JSON.parse(atob(response.credential.split('.')[1]));
                    CURRENT_USER_NAME = decodedToken.name || decodedToken.email;
                    CURRENT_USER_EMAIL = decodedToken.email;
                    await updateAuthUI();
                    setTimeout(() => authModal.style.display = 'none', 1500);
                } else {
                    console.error('Google Auth Error:', data.error);
                    authStatusMessage.textContent = `Error: ${data.error}`;
                    authStatusMessage.classList.remove('bg-gray-200', 'text-gray-800');
                    authStatusMessage.classList.add('bg-red-200', 'text-red-800');
                    await updateAuthUI();
                }
            } catch (error) {
                console.error('Fetch error during Google Auth:', error);
                authStatusMessage.textContent = `Network error: ${error.message}`;
                authStatusMessage.classList.remove('bg-gray-200', 'text-gray-800');
                authStatusMessage.classList.add('bg-red-200', 'text-red-800');
                await updateAuthUI();
            }
        };

        async function handleLogout() {
            try {
                const res = await fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=logout`
                });
                const data = await res.json();
                if (data.success) {
                    console.log('Logout Success:', data);
                    CURRENT_USER_ID = null;
                    CURRENT_USER_EMAIL = null;
                    CURRENT_USER_NAME = null;
                    localStorage.removeItem('currentChatId');
                    currentChatId = null;
                    await updateAuthUI();
                    toggleChatView(false);
                    mainInput.value = '';
                    chatMessages.innerHTML = `
                        <div class="message assistant message-animation">
                            Hello! I am your AI assistant. How can I help you?
                        </div>
                    `;
                    authModal.style.display = 'none';
                } else {
                    console.error('Logout Error:', data.error);
                    alert(`Logout error: ${data.error}`);
                }
            } catch (error) {
                console.error('Fetch error during logout:', error);
                alert(`Network error during logout: ${error.message}`);
            }
        }
        logoutButton.addEventListener('click', handleLogout);


        window.onload = async () => {
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme) {
                body.classList.remove('light', 'dark');
                body.classList.add(savedTheme);
                themeToggleButton.innerHTML = savedTheme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
            } else {
                if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    body.classList.add('dark');
                    themeToggleButton.innerHTML = '<i class="fas fa-sun"></i>';
                } else {
                    body.classList.add('light');
                    themeToggleButton.innerHTML = '<i class="fas fa-moon"></i>';
                }
            }

            google.accounts.id.initialize({
                client_id: "<?php echo GOOGLE_CLIENT_ID; ?>",
                callback: handleGoogleAuth,
                auto_select: false,
                scope: 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/gmail.readonly'
            });
            google.accounts.id.renderButton(
                document.querySelector(".g_id_signin"),
                { theme: "outline", size: "large", text: "sign_in_with", shape: "rectangular", logo_alignment: "left" }
            );

            await updateAuthUI();

            toggleChatView(false);
            mainInput.focus();

            if (CURRENT_USER_ID) {
                loadUserChats();
            } else {
                chatMessages.innerHTML = `
                    <div class="message assistant message-animation">
                        Please authenticate to start a chat.
                    </div>
                `;
            }
        };
    </script>
</body>
</html>
