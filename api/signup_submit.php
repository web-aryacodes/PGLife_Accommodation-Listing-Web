<?php
require("../includes/database_connect.php");

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = array("success" => false, "message" => "Invalid request.");
    echo json_encode($response);
    return;
}

$full_name = trim($_POST['full_name'] ?? '');
$phone = trim($_POST['phone'] ?? '');
$email = strtolower(trim($_POST['email'] ?? ''));
$password = $_POST['password'] ?? '';
$college_name = trim($_POST['college_name'] ?? '');
$gender = $_POST['gender'] ?? '';

if (
    $full_name === '' ||
    $phone === '' ||
    $email === '' ||
    $password === '' ||
    $college_name === '' ||
    $gender === ''
) {
    $response = array("success" => false, "message" => "All fields are required.");
    echo json_encode($response);
    return;
}

if (strlen($full_name) > 100 || strlen($college_name) > 100) {
    $response = array("success" => false, "message" => "Name or college name is too long.");
    echo json_encode($response);
    return;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
    $response = array("success" => false, "message" => "Please enter a valid email address.");
    echo json_encode($response);
    return;
}

if (!preg_match('/^[0-9]{10}$/', $phone)) {
    $response = array("success" => false, "message" => "Please enter a valid 10-digit phone number.");
    echo json_encode($response);
    return;
}

if (strlen($password) < 8 || strlen($password) > 255) {
    $response = array("success" => false, "message" => "Password must be between 8 and 255 characters.");
    echo json_encode($response);
    return;
}

if ($gender !== 'male' && $gender !== 'female') {
    $response = array("success" => false, "message" => "Invalid gender selected.");
    echo json_encode($response);
    return;
}

$stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ?");
mysqli_stmt_bind_param($stmt, "s", $email);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (!$result) {
    $response = array("success" => false, "message" => "Something went wrong!");
    echo json_encode($response);
    return;
}

if (mysqli_num_rows($result) != 0) {
    $response = array("success" => false, "message" => "This email id is already registered with us!");
    echo json_encode($response);
    return;
}

$password_hash = password_hash($password, PASSWORD_DEFAULT);

$insert_stmt = mysqli_prepare(
    $conn,
    "INSERT INTO users (email, password, full_name, phone, gender, college_name) VALUES (?, ?, ?, ?, ?, ?)"
);

mysqli_stmt_bind_param(
    $insert_stmt,
    "ssssss",
    $email,
    $password_hash,
    $full_name,
    $phone,
    $gender,
    $college_name
);

if (!mysqli_stmt_execute($insert_stmt)) {
    $response = array("success" => false, "message" => "Something went wrong!");
    echo json_encode($response);
    return;
}

$response = array("success" => true, "message" => "Your account has been created successfully!");
echo json_encode($response);

mysqli_stmt_close($insert_stmt);
mysqli_stmt_close($stmt);
mysqli_close($conn);