<?php
error_reporting(E_ALL);
ini_set('display_errors', 0); // Don't display errors, it breaks JSON
ini_set('log_errors', 1);

session_start();
require_once 'db_connect.php';

header('Content-Type: application/json');
$response = ['success' => false, 'message' => 'An unknown error occurred.'];

// MODIFIED: More robust authorization check
$is_authorized = false;
if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true) {
        $is_authorized = true;
    } elseif (isset($_SESSION['role']) && $_SESSION['role'] === 'manager') {
        $manager_permissions = $_SESSION['permissions'] ?? [];
        if (is_array($manager_permissions) && in_array('manage_reservations', $manager_permissions)) {
            $is_authorized = true;
        }
    }
}

if (!$is_authorized) {
    $response['message'] = 'Unauthorized access. You do not have permission to perform this action.';
    echo json_encode($response);
    exit;
}


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'] ?? null;
    
    if ($action === 'create') {
        $res_name = htmlspecialchars(trim($_POST['res_name'] ?? ''));
        $res_email = filter_var(trim($_POST['res_email'] ?? ''), FILTER_SANITIZE_EMAIL);
        $res_phone = htmlspecialchars(trim($_POST['res_phone'] ?? ''));
        $res_date = htmlspecialchars(trim($_POST['res_date'] ?? ''));
        $res_time = htmlspecialchars(trim($_POST['res_time'] ?? ''));
        $num_guests = filter_var(trim($_POST['num_guests'] ?? ''), FILTER_SANITIZE_NUMBER_INT);
        $status = "Confirmed";
        $source = "Walk-in";

        if (empty($res_name) || empty($res_email) || empty($res_phone) || empty($res_date) || empty($res_time) || empty($num_guests)) {
            $response['message'] = 'Please fill in all required fields for the new reservation.';
            echo json_encode($response);
            exit;
        }

        $sql = "INSERT INTO reservations (res_name, res_email, res_phone, res_date, res_time, num_guests, status, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        if ($stmt = mysqli_prepare($link, $sql)) {
            mysqli_stmt_bind_param($stmt, "sssssiss", $res_name, $res_email, $res_phone, $res_date, $res_time, $num_guests, $status, $source);
            if (mysqli_stmt_execute($stmt)) {
                $response['success'] = true;
                $response['message'] = 'Walk-in reservation added successfully.';
            } else {
                $response['message'] = 'Database error: Could not add reservation.';
                error_log("Create reservation error: " . mysqli_stmt_error($stmt));
            }
            mysqli_stmt_close($stmt);
        } else {
            $response['message'] = 'Database error: Could not prepare statement for creation.';
            error_log("Prepare create statement error: " . mysqli_error($link));
        }
    }
    elseif ($action === 'update') {
        $reservation_id = filter_input(INPUT_POST, 'reservation_id', FILTER_SANITIZE_NUMBER_INT);
        if(empty($reservation_id)) {
             $response['message'] = 'Missing reservation ID for update.';
             echo json_encode($response);
             exit;
        }

        $res_name = htmlspecialchars(trim($_POST['res_name'] ?? ''));
        $res_email = filter_var(trim($_POST['res_email'] ?? ''), FILTER_SANITIZE_EMAIL);
        $res_phone = htmlspecialchars(trim($_POST['res_phone'] ?? ''));
        $res_date = htmlspecialchars(trim($_POST['res_date'] ?? ''));
        $res_time = htmlspecialchars(trim($_POST['res_time'] ?? ''));
        $num_guests = filter_var(trim($_POST['num_guests'] ?? ''), FILTER_SANITIZE_NUMBER_INT);
        $status = htmlspecialchars(trim($_POST['status'] ?? ''));

        if (empty($res_name) || empty($res_email) || empty($res_date) || empty($res_time) || empty($num_guests) || empty($status)) {
            $response['message'] = 'Missing required fields for update.';
            echo json_encode($response);
            exit;
        }

        $sql = "UPDATE reservations SET res_name = ?, res_email = ?, res_phone = ?, res_date = ?, res_time = ?, num_guests = ?, status = ? WHERE reservation_id = ?";
        if ($stmt = mysqli_prepare($link, $sql)) {
            mysqli_stmt_bind_param($stmt, "sssssisi", $res_name, $res_email, $res_phone, $res_date, $res_time, $num_guests, $status, $reservation_id);
            if (mysqli_stmt_execute($stmt)) {
                $response['success'] = true;
                $response['message'] = 'Reservation updated successfully.';
            } else {
                $response['message'] = 'Database error: Could not update reservation.';
                error_log("Update reservation error: " . mysqli_stmt_error($stmt));
            }
            mysqli_stmt_close($stmt);
        } else {
            $response['message'] = 'Database error: Could not prepare statement for update.';
            error_log("Prepare update statement error: " . mysqli_error($link));
        }

    } elseif ($action === 'delete') {
        $reservation_id = filter_input(INPUT_POST, 'reservation_id', FILTER_SANITIZE_NUMBER_INT);
         if(empty($reservation_id)) {
             $response['message'] = 'Missing reservation ID for deletion.';
             echo json_encode($response);
             exit;
        }

        $sql_select = "SELECT * FROM reservations WHERE reservation_id = ?";
        $stmt_select = mysqli_prepare($link, $sql_select);
        mysqli_stmt_bind_param($stmt_select, "i", $reservation_id);
        mysqli_stmt_execute($stmt_select);
        $result = mysqli_stmt_get_result($stmt_select);
        $reservation_data = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt_select);

        if ($reservation_data) {
            $item_data_json = json_encode($reservation_data);

            mysqli_begin_transaction($link);

            try {
                $sql_soft_delete = "UPDATE reservations SET deleted_at = NOW() WHERE reservation_id = ?";
                $stmt_soft_delete = mysqli_prepare($link, $sql_soft_delete);
                mysqli_stmt_bind_param($stmt_soft_delete, "i", $reservation_id);
                mysqli_stmt_execute($stmt_soft_delete);
                mysqli_stmt_close($stmt_soft_delete);

                $sql_log = "INSERT INTO deletion_history (item_type, item_id, item_data, purge_date) VALUES ('reservation', ?, ?, DATE_ADD(CURDATE(), INTERVAL 30 DAY))";
                $stmt_log = mysqli_prepare($link, $sql_log);
                mysqli_stmt_bind_param($stmt_log, "is", $reservation_id, $item_data_json);
                mysqli_stmt_execute($stmt_log);
                mysqli_stmt_close($stmt_log);

                mysqli_commit($link);
                $response['success'] = true;
                $response['message'] = 'Reservation moved to deletion history successfully.';

            } catch (mysqli_sql_exception $exception) {
                mysqli_rollback($link);
                $response['message'] = 'Database error during deletion process.';
                error_log("Reservation deletion transaction failed: " . $exception->getMessage());
            }
        } else {
            $response['message'] = 'No reservation found with the given ID to delete.';
        }
    } else {
        $response['message'] = 'Invalid action specified.';
    }

    mysqli_close($link);
} else {
    $response['message'] = 'Invalid request method.';
}

echo json_encode($response);
?>