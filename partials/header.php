<style>
    /* --- INLINED HEADER STYLES --- */
    .header-avatar {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        object-fit: cover;
        border: 2px solid #ddd;
    }
    .user-profile-menu {
        display: flex;
        align-items: center;
        gap: 15px;
    }
    #profileBtn {
        background-color: #fff;
        color: #333;
        font-size: 1em;
        border: 1px solid #ddd;
        cursor: pointer;
        border-radius: 50px;
        font-family: 'Mada', sans-serif;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: all 0.3s ease;
        height: 42px;
        padding: 0 15px 0 5px;
    }
    .notification-button {
        background-color: transparent;
        border: 1px solid #ddd;
        color: #333;
        width: 42px;
        height: 42px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        cursor: pointer;
        transition: background-color 0.3s ease, border-color 0.3s ease;
    }
    .notification-button .fa-bell { font-size: 1.1em; }
    .notification-badge { position: absolute; top: 0px; right: 0px; background-color: #e74c3c; color: white; font-size: 0.7rem; border-radius: 50%; padding: 3px 6px; display: flex; justify-content: center; align-items: center; min-width: 18px; height: 18px; font-weight: bold; }
    #profileBtn:hover { background-color: #f5f5f5; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .profile-dropdown { position: relative; display: inline-block; }

    /* Dropdown Animation */
    #profileDropdownContent, .notification-dropdown-content { 
        display: block; position: absolute; background-color: #ffffff; min-width: 180px; 
        box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.15); z-index: 2000; right: 0; 
        border: 1px solid #eee; border-radius: 8px; margin-top: 8px; overflow: hidden;
        opacity: 0; visibility: hidden; transform: translateY(10px);
        transition: opacity 0.3s ease, transform 0.3s ease, visibility 0.3s;
    }
    #profileDropdownContent.show-dropdown, .notification-dropdown-content.show {
        opacity: 1; visibility: visible; transform: translateY(0);
    }
    .notification-dropdown-content { min-width: 320px; max-width: 350px; padding: 0; }
    #profileDropdownContent a { color: black; padding: 12px 16px; text-decoration: none; display: block; font-size: 1em; }
    #profileDropdownContent a:hover { background-color: #f1f1f1; }
    .notification-header { padding: 12px 16px; font-weight: bold; font-size: 1.1em; color: #333; border-bottom: 1px solid #eee; }
    .notification-body { max-height: 300px; overflow-y: auto; }
    .notification-item { display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid #f0f0f0; transition: background-color 0.2s ease; text-decoration: none; color: inherit; font-size: 0.9em; }
    .no-notifications { text-align: center; color: #777; padding: 20px; font-size: 0.9em; }
    .notification-item:hover { background-color: #f8f9fa; }
    .notification-item i { margin-right: 10px; color: #555; width: 20px; text-align: center; }
    .notification-item .fa-check-circle { color: #28a745; }
    .notification-item .fa-times-circle, .notification-item .fa-ban { color: #dc3545; }
    .notification-item .fa-reply { color: #007bff; }

    /* === NEW/MODIFIED STYLES FOR DISMISS BUTTON === */
    .notification-item {
        justify-content: space-between; /* Push button to the end */
    }
    .notification-item .notification-message-text {
        flex-grow: 1; /* Allow text to take available space */
        margin-right: 10px; /* Space before the button */
    }
    .notification-dismiss-btn {
        background: transparent;
        border: none;
        color: #aaa;
        font-size: 20px;
        font-weight: bold;
        line-height: 1;
        padding: 5px;
        margin-left: 5px;
        cursor: pointer;
        border-radius: 50%;
        width: 25px;
        height: 25px;
        flex-shrink: 0;
        transition: background-color 0.2s ease, color 0.2s ease;
    }
    .notification-dismiss-btn:hover {
        background-color: #f0f0f0;
        color: #333;
    }
    body.dark-theme .notification-dismiss-btn {
        color: #888;
    }
    body.dark-theme .notification-dismiss-btn:hover {
        background-color: #555;
        color: #fff;
    }
    /* === END NEW/MODIFIED STYLES === */

    /* Mobile Header Controls */
    .mobile-header-controls { display: flex; align-items: center; gap: 10px; }
    .no-scroll { overflow: hidden; }
    .mobile-nav-toggle { display: none; background: none; border: none; cursor: pointer; z-index: 2001; padding: 10px; }
    .mobile-nav-toggle span { display: block; width: 25px; height: 3px; background-color: #333; margin: 5px 0; transition: transform 0.3s ease, opacity 0.3s ease; }
    .mobile-nav-toggle.active span:nth-child(1) { transform: translateY(8px) rotate(45deg); }
    .mobile-nav-toggle.active span:nth-child(2) { opacity: 0; }
    .mobile-nav-toggle.active span:nth-child(3) { transform: translateY(-8px) rotate(-45deg); }
    
    @media (max-width: 992px) {
        .header-content { padding: 0 15px; }
        .logo { margin-right: auto; }
        
        /* Slide-in Menu from Right */
        .main-nav { 
            position: fixed; top: 0; right: 0; transform: translateX(100%);
            width: 75%; max-width: 320px; height: 100vh; 
            background-color: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            z-index: 2000; padding-top: 100px; display: flex; 
            flex-direction: column; justify-content: flex-start; 
            transition: transform 0.5s cubic-bezier(0.23, 1, 0.32, 1);
        }
        .main-nav.nav-open { transform: translateX(0); box-shadow: -5px 0 15px rgba(0,0,0,0.1); }
        .main-nav ul { flex-direction: column; align-items: center; gap: 10px; width: 100%; padding: 15px 0; }
        .main-nav ul li { width: 100%; text-align: center; opacity: 0; transform: translateX(20px); animation: fadeInRight 0.5s ease forwards; }
        .main-nav.nav-open ul li:nth-child(1) { animation-delay: 0.2s; }
        .main-nav.nav-open ul li:nth-child(2) { animation-delay: 0.3s; }
        .main-nav.nav-open ul li:nth-child(3) { animation-delay: 0.4s; }
        .main-nav.nav-open ul li:nth-child(4) { animation-delay: 0.5s; }
        .main-nav.nav-open ul li:nth-child(5) { animation-delay: 0.6s; }
        .main-nav.nav-open ul li:nth-child(6) { animation-delay: 0.7s; }
        @keyframes fadeInRight { to { opacity: 1; transform: translateX(0); } }
        .main-nav ul li a { padding: 15px 0; width: 100%; display: block; font-size: 1.5em; font-weight: 600; }
        .mobile-nav-toggle { display: block; }
        
        .signin-button .desktop-text { display: none; }
        .signin-button { width: 45px; height: 45px; padding: 0; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
        .signin-button .mobile-icon { display: block !important; font-size: 1.5em; }
        
        #profileBtn .username-text, #profileBtn .fa-caret-down { display: none; }
        #profileBtn { padding: 0; width: 42px; justify-content: center; }
    }
</style>

<header class="main-header">
    <div class="header-content">
        <div class="logo">
            <div class="logo-main-line">
                <span>TAVERN PUBLICO</span>
            </div>
            <span class="est-year">EST ★ 2024</span>
        </div>

        <nav class="main-nav">
            <ul>
                <li><a href="index.php">Home</a></li>
                <li><a href="menu.php">Menu</a></li>
                <li><a href="gallery.php">Gallery</a></li>
                <li><a href="events.php">Events</a></li>
                <li><a href="contact.php">Contact</a></li>
                <li><a href="about.php">About</a></li>
            </ul>
        </nav>

        <div class="header-right">
            <?php
            if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
                $avatar_path = isset($_SESSION['avatar']) && file_exists($_SESSION['avatar']) ? $_SESSION['avatar'] : 'images/default_avatar.png';

                echo '<div class="user-profile-menu">';
                echo '  <div class="profile-dropdown">';
                echo '    <button id="profileBtn" class="profile-button">';
                echo '      <img src="' . htmlspecialchars($avatar_path) . '" alt="My Avatar" class="header-avatar">';
                echo '      <span class="username-text">' . htmlspecialchars($_SESSION['username']) . '</span>';
                echo '      <i class="fas fa-caret-down" style="font-size: 0.8em; margin-left: 5px;"></i>';
                echo '    </button>';
                echo '    <div id="profileDropdownContent">';
                echo '      <a href="profile.php">My Profile</a>';
                echo '      <a href="logout.php">Logout</a>';
                echo '    </div>';
                echo '  </div>';
                echo '  <div class="notification-dropdown">';
                echo '      <button class="notification-button" id="notificationBtn">';
                echo '          <i class="fas fa-bell"></i>';
                echo '          <span class="notification-badge" id="notificationCount" style="display: none;">0</span>';
                echo '      </button>';
                echo '      <div class="notification-dropdown-content" id="notificationDropdownContent"></div>';
                echo '  </div>';
                echo '</div>';
            } else {
                echo '<a href="#" class="btn header-button signin-button" id="openModalBtn"><span 
                class="desktop-text">Sign In/Sign Up</span><i class="fas fa-user-circle mobile-icon" style="display: none;"></i></a>';
            }
            ?>
        </div>
        
        <button class="mobile-nav-toggle" aria-label="Open navigation menu">
            <span></span>
            <span></span>
            <span></span>
        </button>
    </div>
</header>
<button id="theme-switcher"><i class="fas fa-moon"></i></button>

<script>
document.addEventListener('DOMContentLoaded', () => {
    // --- Elements ---
    const profileButton = document.getElementById('profileBtn');
    const profileDropdown = document.getElementById('profileDropdownContent');
    const notificationButton = document.getElementById('notificationBtn');
    const notificationDropdown = document.getElementById('notificationDropdownContent');
    const mobileNavToggle = document.querySelector('.mobile-nav-toggle');
    const mainNav = document.querySelector('.main-nav');

    // --- Active Nav Link Logic ---
    const navLinks = document.querySelectorAll('.main-nav a');
    const currentPageFile = window.location.pathname.split('/').pop();
    navLinks.forEach(link => {
        const linkFile = link.getAttribute('href').split('/').pop();
        if (linkFile === currentPageFile || (currentPageFile === '' && linkFile === 'index.php')) {
            link.classList.add('active-nav-link');
        }
    });

    // --- Mobile Nav Logic ---
    if (mobileNavToggle) {
        mobileNavToggle.addEventListener('click', function() {
            mainNav.classList.toggle('nav-open');
            this.classList.toggle('active');
            document.body.classList.toggle('no-scroll');
        });
    }

    // --- Dropdown Logic ---
    if (profileButton) {
        profileButton.addEventListener('click', function(event) {
            event.stopPropagation();
            if(notificationDropdown) notificationDropdown.classList.remove('show');
            profileDropdown.classList.toggle('show-dropdown');
        });
    }

    if (notificationButton) {
        notificationButton.addEventListener('click', function(event) {
            event.stopPropagation();
            if(profileDropdown) profileDropdown.classList.remove('show-dropdown');
            notificationDropdown.classList.toggle('show');
            fetchNotifications(); // Fetch fresh notifications when opening
        });
    }

    window.addEventListener('click', function() {
        if (profileDropdown && profileDropdown.classList.contains('show-dropdown')) {
            profileDropdown.classList.remove('show-dropdown');
        }
        if (notificationDropdown && notificationDropdown.classList.contains('show')) {
            notificationDropdown.classList.remove('show');
        }
    });

    if(profileDropdown) profileDropdown.addEventListener('click', e => e.stopPropagation());
    if(notificationDropdown) notificationDropdown.addEventListener('click', e => e.stopPropagation());
    
    // --- Notification Fetching and Display Logic ---
    async function fetchNotifications() {
        if (!notificationButton) return;
        try {
            const response = await fetch('get_notifications.php');
            const data = await response.json();
            const notificationCountBadge = document.getElementById('notificationCount');
            
            notificationDropdown.innerHTML = '<div class="notification-header">Notifications</div><div class="notification-body"></div>';
            const notificationBody = notificationDropdown.querySelector('.notification-body');

            if (data.success && data.notifications.length > 0) {
                notificationCountBadge.textContent = data.notifications.length;
                notificationCountBadge.style.display = 'flex';
                
                data.notifications.forEach(notif => {
                    const notifLink = document.createElement('a');
                    notifLink.href = notif.link;
                    notifLink.className = 'notification-item';
                    notifLink.dataset.id = notif.id;
                    notifLink.dataset.type = notif.type;
                    
                    let iconClass = 'fa-info-circle';
                    if (notif.type === 'reservation') {
                        if (notif.message.toLowerCase().includes('confirmed')) {
                            iconClass = 'fa-check-circle';
                        } else if (notif.message.toLowerCase().includes('declined')) {
                            iconClass = 'fa-ban';
                        }
                    } else if (notif.type === 'custom') {
                        iconClass = 'fa-reply';
                    }
                    
                    // === MODIFIED LINE: Added span for text and dismiss button ===
                    notifLink.innerHTML = `<i class="fas ${iconClass}"></i><span class="notification-message-text">${notif.message}</span><button class="notification-dismiss-btn" title="Dismiss">&times;</button>`;
                    notificationBody.appendChild(notifLink);
                });
            } else {
                notificationCountBadge.style.display = 'none';
                notificationBody.innerHTML = '<div class="no-notifications">You have no new notifications.</div>';
            }
        } catch (error) { 
            console.error('Error fetching notifications:', error); 
            const notificationBody = notificationDropdown.querySelector('.notification-body');
            if(notificationBody) notificationBody.innerHTML = '<div class="no-notifications">Could not load notifications.</div>';
        }
    }
    
    // === NEW FUNCTION: To handle clearing notifications ===
    async function clearNotification(id, type, element, redirectLink = null) {
        const formData = new FormData();
        formData.append('id', id);
        formData.append('type', type);

        try {
            const response = await fetch('clear_notifications.php', { method: 'POST', body: formData });
            const result = await response.json();

            if (result.success) {
                // Animate removal
                element.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                element.style.opacity = '0';
                element.style.transform = 'translateX(20px)';
                
                // After animation, either remove or redirect
                setTimeout(() => {
                    if (redirectLink && !redirectLink.endsWith('#')) {
                        window.location.href = redirectLink;
                    } else {
                        element.remove(); // Remove from DOM
                        // Refetch to update count and check if empty
                        fetchNotifications(); 
                    }
                }, 300);
            } else {
                // Failed to clear, but still navigate if a link was clicked
                if (redirectLink && !redirectLink.endsWith('#')) {
                    window.location.href = redirectLink;
                }
            }
        } catch (error) {
            console.error('Error clearing notification:', error);
            // Still navigate if a link was clicked
            if (redirectLink && !redirectLink.endsWith('#')) {
                window.location.href = redirectLink;
            }
        }
    }
    
    // === MODIFIED CLICK HANDLER: Differentiates between 'x' click and item click ===
    if (notificationDropdown) {
        notificationDropdown.addEventListener('click', async (e) => {
            const dismissBtn = e.target.closest('.notification-dismiss-btn');
            const notificationItem = e.target.closest('.notification-item');

            if (!notificationItem) return; // Click was outside any item

            e.preventDefault(); // Always prevent default <a> click first

            const id = notificationItem.dataset.id;
            const type = notificationItem.dataset.type;
            const link = notificationItem.href;

            if (dismissBtn) {
                // Click was on the 'x' button
                // Just dismiss, don't navigate
                await clearNotification(id, type, notificationItem, null); // Pass null for redirectLink
            } else {
                // Click was on the notification item itself
                // Dismiss AND navigate
                await clearNotification(id, type, notificationItem, link);
            }
        });
    }

    if (notificationButton) {
        fetchNotifications(); // Initial fetch
        setInterval(fetchNotifications, 60000); // Poll for new notifications every 60 seconds
    }
});
</script>