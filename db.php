<?php

require_once __DIR__ . '/config.php';

function get_db_connection() {
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

        if ($conn->connect_error) {
            log_error("Database connection error: " . $conn->connect_error);
            return false;
        }
        if (!$conn->set_charset("utf8mb4")) {
            log_error("Error setting UTF-8 charset for DB: " . $conn->error);
            $conn->close();
            return false;
        }
        return $conn;
    } catch (Exception $e) {
        log_error("Exception during DB connection attempt: " . $e->getMessage());
        return false;
    }
}

function save_interaction($chatId, $userId, $inputText, $outputText, $audioUrl) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to save interaction.");
        return false;
    }

    $stmt = $conn->prepare("INSERT INTO interactions (chat_id, user_id, input_text, output_text, audio_url, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
    if ($stmt === false) {
        log_error("Error preparing save_interaction query: " . $conn->error . ". SQL: INSERT INTO interactions (chat_id, user_id, input_text, output_text, audio_url, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
        $conn->close();
        return false;
    }

    $stmt->bind_param("sisss", $chatId, $userId, $inputText, $outputText, $audioUrl);

    $result = $stmt->execute();

    if ($result === false) {
        log_error("Error executing save_interaction query: " . $stmt->error . ". Chat ID: " . $chatId . ". User ID: " . $userId . ". Input Text: " . substr($inputText, 0, 100));
    }

    $stmt->close();
    $conn->close();
    return $result;
}

function get_chat_history($chatId, $userId) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to retrieve chat history.");
        return [];
    }

    $stmt = $conn->prepare("SELECT input_text, output_text, audio_url, created_at FROM interactions WHERE chat_id = ? AND user_id = ? ORDER BY created_at ASC");
    if ($stmt === false) {
        log_error("Error preparing get_chat_history query: " . $conn->error . ". Chat ID: " . $chatId . ", User ID: " . $userId);
        $conn->close();
        return [];
    }

    $stmt->bind_param("si", $chatId, $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        log_error("Error getting result for get_chat_history query: " . $stmt->error . ". Chat ID: " . $chatId . ", User ID: " . $userId);
        $stmt->close();
        $conn->close();
        return [];
    }

    $history = [];
    while ($row = $result->fetch_assoc()) {
        $is_voice_message = empty($row['input_text']) && !empty($row['audio_url']);
        $history[] = [
            'input_text' => $row['input_text'],
            'output_text' => $row['output_text'],
            'audio_url' => $row['audio_url'],
            'created_at' => $row['created_at'],
            'is_voice_message' => $is_voice_message
        ];
    }

    $stmt->close();
    $conn->close();
    return $history;
}

function get_user_chats($userId) {
    $conn = get_db_connection();
    if (!$conn) {
        log_error("Failed to get DB connection to retrieve user chat list.");
        return [];
    }

    $stmt = $conn->prepare("
        SELECT
            t1.chat_id,
            t1.input_text,
            t1.created_at
        FROM
            interactions t1
        WHERE
            t1.user_id = ?
            AND t1.created_at = (
                SELECT MIN(t2.created_at)
                FROM interactions t2
                WHERE t2.chat_id = t1.chat_id AND t2.user_id = ?
            )
        ORDER BY t1.created_at DESC
    ");

    if ($stmt === false) {
        log_error("Error preparing get_user_chats query: " . $conn->error . ". User ID: " . $userId);
        $conn->close();
        return [];
    }

    $stmt->bind_param("ii", $userId, $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        log_error("Error getting result for get_user_chats query: " . $stmt->error . ". User ID: " . $userId);
        $stmt->close();
        $conn->close();
        return [];
    }

    $chats = [];
    while ($row = $result->fetch_assoc()) {
        $chats[] = [
            'chat_id' => $row['chat_id'],
            'title' => !empty($row['input_text']) ? substr($row['input_text'], 0, 50) . (strlen($row['input_text']) > 50 ? '...' : '') : 'New Chat',
            'created_at' => $row['created_at']
        ];
    }

    $stmt->close();
    $conn->close();
    return $chats;
}
?>
