<?php
session_start();
require_once 'db_connect.php';

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true || !$_SESSION['is_admin']) {
    header('Location: login.php');
    exit;
}

$return_to_page = 'admin.php';
$return_title = 'Back to Dashboard';
if (isset($_GET['return_to'])) {
    if ($_GET['return_to'] === 'reservation') {
        $return_to_page = 'reservation.php';
        $return_title = 'Back to Reservations';
    }
}

$customer_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

if ($customer_id <= 0) {
    $_SESSION['error_message'] = "Invalid Customer ID specified.";
    header('Location: customer_database.php');
    exit;
}

$customer = null;
$sql_user = "SELECT username, email, created_at, avatar, mobile, birthday FROM users WHERE user_id = ? AND deleted_at IS NULL";
if ($stmt_user = mysqli_prepare($link, $sql_user)) {
    mysqli_stmt_bind_param($stmt_user, "i", $customer_id);
    if (mysqli_stmt_execute($stmt_user)) {
        $result_user = mysqli_stmt_get_result($stmt_user);
        $customer = mysqli_fetch_assoc($result_user);
    } else {
        error_log("Error executing user query: " . mysqli_stmt_error($stmt_user));
    }
    mysqli_stmt_close($stmt_user);
} else {
     error_log("Error preparing user query: " . mysqli_error($link));
}

if (!$customer) {
    $_SESSION['error_message'] = "Customer not found.";
    header('Location: customer_database.php');
    exit;
}

$reservations = [];
$sql_reservations = "SELECT reservation_id, res_date, res_time, num_guests, status, created_at FROM reservations WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC";
if ($stmt_reservations = mysqli_prepare($link, $sql_reservations)) {
    mysqli_stmt_bind_param($stmt_reservations, "i", $customer_id);
    if (mysqli_stmt_execute($stmt_reservations)) {
        $result_reservations = mysqli_stmt_get_result($stmt_reservations);
        while ($row = mysqli_fetch_assoc($result_reservations)) {
            $reservations[] = $row;
        }
    } else {
        error_log("Error executing reservations query: " . mysqli_stmt_error($stmt_reservations));
    }
    mysqli_stmt_close($stmt_reservations);
} else {
    error_log("Error preparing reservations query: " . mysqli_error($link));
}

mysqli_close($link);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Profile - <?= htmlspecialchars($customer['username']); ?></title>
    <link rel="stylesheet" href="CSS/admin.css">
    <link rel="stylesheet" href="CSS/profile.css">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        .profile-header-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #eee;
        }
        .close-profile-btn {
            font-size: 24px;
            font-weight: bold;
            text-decoration: none;
            color: #888;
            transition: color 0.2s;
            line-height: 1;
        }
        .close-profile-btn:hover {
            color: #333;
        }
        .toggle-history-btn {
            display: block;
            margin: 15px auto 0;
            background: #f0f0f0;
            border: 1px solid #ddd;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
        }
        .admin-content-area .main-header {
            position: fixed;
            top: 0;
            right: 0;
            width: calc(100% - 250px);
            z-index: 950;
        }
        .dashboard-main-content {
            padding-top: 70px;
        }
    </style>
</head>
<body>

    <div class="page-wrapper">
        <aside class="admin-sidebar">
            <div class="sidebar-header">
                <img src="Tavern.png" alt="Home Icon" class="home-icon">
            </div>
            <nav>
                <ul class="sidebar-menu">
                    <li class="menu-item"><a href="admin.php"><i class="material-icons">dashboard</i> Dashboard</a></li>
                    <li class="menu-item"><a href="update.php"><i class="material-icons">file_upload</i> Upload Management</a></li>
                    <li class="menu-item"><a href="reservation.php"><i class="material-icons">event_note</i> Reservation</a></li>
                </ul>
                <div class="user-management-title">User Management</div>
                <ul class="sidebar-menu user-management-menu">
                    <li class="menu-item"><a href="notification_control.php"><i class="material-icons">notifications</i> Notification Control</a></li>
                    <li class="menu-item"><a href="table_management.php"><i class="material-icons">table_chart</i> Calendar Management</a></li>
                    <li class="menu-item active"><a href="customer_database.php"><i class="material-icons">people</i> Customer Database</a></li>
                    <li class="menu-item"><a href="reports.php"><i class="material-icons">analytics</i>Reservation Reports</a></li>
                    <li class="menu-item"><a href="deletion_history.php"><i class="material-icons">history</i> Archive</a></li>
                    <li class="menu-item"><a href="logout.php"><i class="material-icons">logout</i> Log out</a></li>
                </ul>
            </nav>
        </aside>

        <div class="admin-content-area">
            <header class="main-header">
                <div class="header-content">
                    <h1 class="header-page-title">Customer Profile View</h1>
                     <div class="admin-header-right">
    
    <div class="admin-notification-area">
        <div class="admin-notification-item">
            <button class="admin-notification-button" id="adminMessageBtn" title="Messages">
                <i class="material-icons">email</i>
                <span class="admin-notification-badge" id="adminMessageCount" style="display: none;">0</span>
            </button>
            <div class="admin-notification-dropdown" id="adminMessageDropdown"></div>
        </div>
        <div class="admin-notification-item">
            <button class="admin-notification-button" id="adminReservationBtn" title="Reservations">
                <i class="material-icons">notifications</i> <span class="admin-notification-badge" id="adminReservationCount" style="display: none;">0</span>
            </button>
            <div class="admin-notification-dropdown" id="adminReservationDropdown"></div>
        </div>
    </div>

    <div class="header-separator"></div>

    <div class="admin-profile-area">
        <?php $admin_avatar_path = isset($_SESSION['avatar']) && file_exists($_SESSION['avatar']) ? htmlspecialchars($_SESSION['avatar']) : 'images/default_avatar.png'; ?>
        <img src="<?php echo $admin_avatar_path; ?>" alt="Admin Avatar" class="admin-avatar">
        <div class="admin-user-info">
            <span class="admin-username"><?php echo htmlspecialchars($_SESSION['username']); ?></span>
            <span class="admin-role"><?php echo ucfirst(htmlspecialchars($_SESSION['role'])); ?></span>
        </div>
    </div>

</div>
                </div>
            </header>

            <main class="dashboard-main-content">
                <div class="profile-header-container">
                    <h1 class="dashboard-heading" style="margin: 0; font-size: 24px; color: #333;">Profile: <?= htmlspecialchars($customer['username']); ?></h1>
                    <a href="<?php echo htmlspecialchars($return_to_page); ?>" class="close-profile-btn" title="<?php echo htmlspecialchars($return_title); ?>">&times; Back</a>
                </div>

                <div class="profile-content-grid">
                    <div class="profile-details-card">
                        <div class="card-header" style="display: flex; align-items: center; gap: 15px;">
                            <?php $avatar_path = !empty($customer['avatar']) && file_exists($customer['avatar']) ? $customer['avatar'] : 'images/default_avatar.png'; ?>
                            <img src="<?= htmlspecialchars($avatar_path) ?>" alt="Avatar" style="width: 60px; height: 60px; border-radius: 50%;">
                            <h3><?= htmlspecialchars($customer['username']); ?></h3>
                        </div>
                        <div class="card-body">
                            <div class="info-row">
                                <span class="info-label">Email</span>
                                <span class="info-value"><?= htmlspecialchars($customer['email']); ?></span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Mobile</span>
                                <span class="info-value"><?= htmlspecialchars($customer['mobile'] ?? 'Not Provided'); ?></span>
                            </div>
                             <div class="info-row">
                                <span class="info-label">Birthday</span>
                                <span class="info-value"><?= !empty($customer['birthday']) ? date('F j, Y', strtotime($customer['birthday'])) : 'Not Provided'; ?></span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Member Since</span>
                                <span class="info-value"><?= date('F j, Y', strtotime($customer['created_at'])); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="reservation-history-card">
                        <div class="card-header">
                            <h3><i class="material-icons">calendar_today</i> Reservation History</h3>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Time</th>
                                            <th>Guests</th>
                                            <th>Status</th>
                                            <th>Booked On</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (!empty($reservations)): ?>
                                            <?php foreach ($reservations as $index => $res): ?>
                                                <tr class="reservation-row" style="<?= $index >= 3 ? 'display: none;' : '' ?>">
                                                    <td><?= htmlspecialchars($res['res_date']); ?></td>
                                                    <td><?= htmlspecialchars(date('g:i A', strtotime($res['res_time']))); ?></td>
                                                    <td><?= htmlspecialchars($res['num_guests']); ?></td>
                                                    <td>
                                                        <span class="status-badge status-<?= strtolower(htmlspecialchars($res['status'])); ?>">
                                                            <?= htmlspecialchars($res['status']); ?>
                                                        </span>
                                                    </td>
                                                    <td><?= htmlspecialchars(date('Y-m-d', strtotime($res['created_at']))); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <tr>
                                                <td colspan="5" class="no-reservations">This customer has no reservation history.</td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                                <?php if (count($reservations) > 3): ?>
                                    <button id="toggleHistoryBtn" class="toggle-history-btn">Show More</button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <div id="notificationModal" class="modal">
        <div class="modal-content" style="max-width: 450px; text-align: center;">
            <span class="close-button">&times;</span>
            <div id="modalHeaderIcon" class="modal-header-icon"></div>
            <h2 id="modalTitle"></h2>
            <p id="modalMessage"></p>
            <div class="modal-actions" style="justify-content: center;">
                <button class="btn modal-close-btn" style="background-color: #007bff; color: white;">OK</button>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const toggleBtn = document.getElementById('toggleHistoryBtn');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', function() {
                    const rows = document.querySelectorAll('.reservation-row');
                    const isShowingAll = this.textContent === 'Show Less';

                    rows.forEach((row, index) => {
                        if (index >= 3) {
                            row.style.display = isShowingAll ? 'none' : 'table-row';
                        }
                    });

                    this.textContent = isShowingAll ? 'Show More' : 'Show Less';
                });
            }
        });
    </script>

    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const messageBtn = document.getElementById('adminMessageBtn');
        const reservationBtn = document.getElementById('adminReservationBtn');
        const messageDropdown = document.getElementById('adminMessageDropdown');
        const reservationDropdown = document.getElementById('adminReservationDropdown');

        const messageCountBadge = document.getElementById('adminMessageCount');
        const reservationCountBadge = document.getElementById('adminReservationCount');

        function showAdminNotificationModal(type, title, message) {
            const modal = document.getElementById('notificationModal');
            const iconEl = document.getElementById('modalHeaderIcon');
            const titleEl = document.getElementById('modalTitle');
            const messageEl = document.getElementById('modalMessage');
            const closeBtn = modal.querySelector('.close-button');
            const okBtn = modal.querySelector('.modal-close-btn');

            if (!modal || !iconEl || !titleEl || !messageEl || !closeBtn || !okBtn) {
                console.error("Notification modal elements not found!");
                alert(message);
                return;
            }

            iconEl.innerHTML = type === 'success' ? '<i class="material-icons" style="color: #28a745; font-size: 3em;">check_circle</i>' : '<i class="material-icons" style="color: #dc3545; font-size: 3em;">error</i>';
            iconEl.className = 'modal-header-icon ' + type;

            titleEl.textContent = title;
            messageEl.textContent = message;

            const closeModalHandler = () => modal.style.display = 'none';
            closeBtn.onclick = closeModalHandler;
            okBtn.onclick = closeModalHandler;

            modal.style.display = 'flex';
        }


        async function fetchAdminNotifications() {
            try {
                const response = await fetch('get_admin_notifications.php');
                const data = await response.json();

                if (data.success) {
                    if (data.new_messages > 0) {
                        messageCountBadge.textContent = data.new_messages;
                        messageCountBadge.style.display = 'block';
                    } else {
                        messageCountBadge.style.display = 'none';
                    }
                    messageDropdown.innerHTML = data.messages_html;

                    if (data.pending_reservations > 0) {
                        reservationCountBadge.textContent = data.pending_reservations;
                        reservationCountBadge.style.display = 'block';
                    } else {
                        reservationCountBadge.style.display = 'none';
                    }
                    reservationDropdown.innerHTML = data.reservations_html;
                }
            } catch (error) {
                console.error('Error fetching admin notifications:', error);
            }
        }

        if(messageBtn) {
             messageBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if(reservationDropdown) reservationDropdown.classList.remove('show');
                if(messageDropdown) messageDropdown.classList.toggle('show');
            });
        }

       if(reservationBtn) {
            reservationBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if(messageDropdown) messageDropdown.classList.remove('show');
                if(reservationDropdown) reservationDropdown.classList.toggle('show');
            });
       }

        window.addEventListener('click', () => {
            if(messageDropdown) messageDropdown.classList.remove('show');
            if(reservationDropdown) reservationDropdown.classList.remove('show');
        });

        [messageDropdown, reservationDropdown].forEach(dropdown => {
           if(dropdown) {
                dropdown.addEventListener('click', (e) => {
                    if (!e.target.classList.contains('admin-notification-dismiss')) {
                        e.stopPropagation();
                    }
                });
           }
        });

        async function handleDismiss(e) {
            if (!e.target.classList.contains('admin-notification-dismiss')) return;

            e.preventDefault();
            e.stopPropagation();

            const button = e.target;
            const id = button.dataset.id;
            const type = button.dataset.type;
            const itemWrapper = button.parentElement;

            const formData = new FormData();
            formData.append('id', id);
            formData.append('type', type);

            try {
                const response = await fetch('clear_admin_notification.php', { method: 'POST', body: formData });
                const result = await response.json();

                if (result.success) {
                    itemWrapper.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                    itemWrapper.style.opacity = '0';
                    itemWrapper.style.transform = 'translateX(-20px)';
                    setTimeout(() => {
                        itemWrapper.remove();
                        fetchAdminNotifications();
                    }, 300);
                } else {
                    showAdminNotificationModal('error', 'Action Failed', result.message);
                }
            } catch (error) {
                console.error('Error dismissing notification:', error);
                showAdminNotificationModal('error', 'Error', 'An error occurred. Please try again.');
            }
        }

       if(messageDropdown) messageDropdown.addEventListener('click', handleDismiss);
       if(reservationDropdown) reservationDropdown.addEventListener('click', handleDismiss);

        fetchAdminNotifications();
        setInterval(fetchAdminNotifications, 30000);
    });
    </script>

</body>
</html>