<?php
session_start();
require("../includes/database_connect.php");

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = array("success" => false, "message" => "Invalid request.");
    echo json_encode($response);
    return;
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    $response = array("success" => false, "message" => "Email and password are required.");
    echo json_encode($response);
    return;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $response = array("success" => false, "message" => "Please enter a valid email address.");
    echo json_encode($response);
    return;
}

$password = sha1($password);

$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE email = ? AND password = ?");
mysqli_stmt_bind_param($stmt, "ss", $email, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (!$result) {
    $response = array("success" => false, "message" => "Something went wrong!");
    echo json_encode($response);
    return;
}

$row_count = mysqli_num_rows($result);

if ($row_count == 0) {
    $response = array("success" => false, "message" => "Login failed! Invalid email or password.");
    echo json_encode($response);
    return;
}

$row = mysqli_fetch_assoc($result);

session_regenerate_id(true);

$_SESSION['user_id'] = $row['id'];
$_SESSION['full_name'] = $row['full_name'];
$_SESSION['email'] = $row['email'];

$response = array("success" => true, "message" => "Login successful!");
echo json_encode($response);

mysqli_stmt_close($stmt);
mysqli_close($conn);