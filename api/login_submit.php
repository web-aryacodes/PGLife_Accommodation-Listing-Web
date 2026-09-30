<?php
session_start();
require("../includes/database_connect.php");

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = array("success" => false, "message" => "Invalid request.");
    echo json_encode($response);
    return;
}

$email = strtolower(trim($_POST['email'] ?? ''));
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    $response = array("success" => false, "message" => "Email and password are required.");
    echo json_encode($response);
    return;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
    $response = array("success" => false, "message" => "Please enter a valid email address.");
    echo json_encode($response);
    return;
}

if (strlen($password) > 255) {
    $response = array("success" => false, "message" => "Invalid email or password.");
    echo json_encode($response);
    return;
}

$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE email = ?");
mysqli_stmt_bind_param($stmt, "s", $email);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (!$result) {
    $response = array("success" => false, "message" => "Something went wrong!");
    echo json_encode($response);
    return;
}

$row = mysqli_fetch_assoc($result);

if (!$row) {
    $response = array("success" => false, "message" => "Login failed! Invalid email or password.");
    echo json_encode($response);
    return;
}

$password_valid = false;
$password_needs_migration = false;

if (password_verify($password, $row['password'])) {
    $password_valid = true;

    if (password_needs_rehash($row['password'], PASSWORD_DEFAULT)) {
        $password_needs_migration = true;
    }
} elseif (hash_equals($row['password'], sha1($password))) {
    $password_valid = true;
    $password_needs_migration = true;
}

if (!$password_valid) {
    $response = array("success" => false, "message" => "Login failed! Invalid email or password.");
    echo json_encode($response);
    return;
}

if ($password_needs_migration) {
    $new_password_hash = password_hash($password, PASSWORD_DEFAULT);

    $update_stmt = mysqli_prepare($conn, "UPDATE users SET password = ? WHERE id = ?");
    mysqli_stmt_bind_param($update_stmt, "si", $new_password_hash, $row['id']);
    mysqli_stmt_execute($update_stmt);
    mysqli_stmt_close($update_stmt);
}

session_regenerate_id(true);

$_SESSION['user_id'] = $row['id'];
$_SESSION['full_name'] = $row['full_name'];
$_SESSION['email'] = $row['email'];

$response = array("success" => true, "message" => "Login successful!");
echo json_encode($response);

mysqli_stmt_close($stmt);
mysqli_close($conn);