<!-- <navigation>  -->
    <!--// PHP IF Start-->
        <?php if ($is_public_page) { ?>
    <!--// Navbar -->
        <!--// Style-->
            <style>
            #navbar {
                position: fixed;
                top: var(--space-lg);
                left: 50%;
                transform: translateX(-50%);
                z-index: var(--z-navbar);
                width: calc(100% - 40px);
                max-width: var(--container-xl);
                background-color: var(--bg-card);
                padding: var(--space-xs) var(--space-xs);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                box-shadow: var(--shadow-sm);
                border-radius: var(--radius-lg);
                border: 1px solid var(--border-light);
                align-items: center;
                display: flex;
                justify-content: space-between;
            }

            #navbar .navbar-left {
                display: flex;
                align-items: center;
            }
            #navbar .navbar-left img {
                height: 32px;
                width: auto;
            }

            #navbar .navbar-center {
                display: flex; align-items: center; gap: var(--space-xs);
            }

            #navbar .menu-item {
                position: relative; display: flex; align-items: center;
            }
            #navbar a {
                color: var(--text-primary);
                text-decoration: none;
                padding: var(--space-sm) var(--space-md);
                font-weight: var(--font-medium);
                font-size: var(--text-sm);
                display: flex;
                align-items: center;
                gap: var(--space-xs);
            }
            #navbar a:hover {
                color: var(--text-link-hover);
            }
            #navbar a.active {
                color: var(--text-link-active);
            }
            #navbar a.dropdown::after {
                content: "▼";
                font-size: var(--text-xs);
                color: var(--text-primary);
            }
            #navbar a.dropdown:hover::after {
                color: var(--text-link-hover);
            }
            #navbar .dropdown-menu {
                position: absolute;
                top: 100%;
                left: 0;
                min-width: 220px;
                background: var(--bg-card);
                border-radius: var(--radius-md);
                padding: var(--space-sm) 0;
                box-shadow: var(--shadow-sm);
                border: 1px solid var(--border-light);
                opacity: 0;
                visibility: hidden;
                transform: translateY(-10px);
                transition: all var(--transition-base);
                z-index: var(--z-dropdown);
            }
            #navbar .menu-item:hover .dropdown-menu {
                opacity: 1;
                visibility: visible;
                transform: translateY(0);
            }
            #navbar .dropdown-menu a {
                padding: 12px 20px;
                font-size: var(--text-sm);
                color: var(--text-secondary);
                display: flex;
                align-items: center;
                gap: var(--space-sm);
                border-radius: 0;
            }
            #navbar .dropdown-menu a:hover {
                background-color: var(--bg-hover); color: var(--text-link-hover);
            }
            #navbar .dropdown-menu a .icon {
                width: 32px; height: 32px; border-radius: 8px;
                display: flex; align-items: center; justify-content: center;
                font-size: 16px; flex-shrink: 0;
                background-color: var(--primary-transparent);
            }
            #navbar .dropdown-item-title {
                font-weight: var(--font-semibold);
            }
            #navbar .dropdown-item-description {
                font-size: var(--text-sm);
                color: var(--text-muted);
            }

            #navbar .navbar-right {
                display: flex; align-items: center; gap: var(--space-xs);
            }
            #navbar a.button {
                background: var(--primary);
                color: var(--white) !important;
                text-align: center;
                padding: 12px 24px; border-radius: var(--radius-md);
                font-weight: var(--font-bold); font-size: 14px;
                line-height: var(--leading-relaxed);
                padding: var(--space-xs) var(--space-md);
                /* box-shadow: 0 4px 14px 0 rgba(79, 124, 255, 0.3); */
                box-shadow: var(--button-shadow);
                transition: var(--transition-base);
                border: none;
            }
            #navbar a.button:hover {
                background: var(--primary-dark);
                color: var(--white) !important;
                transform: translateY(-2px);
                box-shadow: var(--button-shadow);
            }

            @media (max-width: 768px) {
                #navbar {
                flex-wrap: wrap;
                align-items: center;
                gap: var(--space-xs);
                /* Ensure horizontal margins on mobile */
                left: 0;
                right: 0;
                transform: none;
                width: auto;
                margin: 0 20px; /* keeps the floating look on mobile */
                }
                #navbar .navbar-left {
                order: 1;
                }
                #navbar .navbar-right {
                order: 2;
                margin-left: auto;
                }
                #navbar .navbar-center {
                order: 3;
                width: 100%;
                display: flex;
                justify-content: center;
                gap: var(--space-xs);
                margin-top: var(--space-xs);
                }
            }

            @media (max-width: 1024px) {
                #navbar {
                left: 0;
                right: 0;
                transform: none;
                width: auto;
                margin: 0 20px; /* horizontal margins on tablet */
                }
            }

            @media (max-width: 1280px) {
                #navbar {
                left: 0;
                right: 0;
                transform: none;
                width: auto;
                margin: 0 20px; /* horizontal margins on tablet */
                }
            }

            @media (max-width: 1536px) {
                #navbar {
                left: 0;
                right: 0;
                transform: none;
                width: auto;
                margin: 0 20px; /* horizontal margins on tablet */
                }
            }
            </style>
        <!--// HTML-->
            <nav id="navbar">
                <div class="navbar-left">
                    <a href="/">
                        <img src="/assets/images/logo.png" alt="Aplikasi Emas Pintar">
                    </a>
                </div>

                <div class="navbar-center">
                    <div class="menu-item">
                        <a href="/home" class="<?= $current_page === 'home' ? 'active' : ''; ?>">Home</a>
                    </div>
                    <div class="menu-item">
                        <a href="#" class="dropdown">Fitur</a>
                        <div class="dropdown-menu">
                            <a href="/home">
                                <div class="icon">🔍</div>
                                <div>
                                    <div class="dropdown-item-title">All Features</div>
                                    <div class="dropdown-item-description">Complete overview</div>
                                </div>
                            </a>
                            <a href="/about">
                                <div class="icon">🧩</div>
                                <div>
                                    <div class="dropdown-item-title">Components</div>
                                    <div class="dropdown-item-description">Reusable building blocks</div>
                                </div>
                            </a>
                            <a href="#">
                                <div class="icon">📋</div>
                                <div>
                                    <div class="dropdown-item-title">Templates</div>
                                    <div class="dropdown-item-description">Ready-made designs</div>
                                </div>
                            </a>
                            <a href="#">
                                <div class="icon">🔗</div>
                                <div>
                                    <div class="dropdown-item-title">Integrations</div>
                                    <div class="dropdown-item-description">Connect your tools</div>
                                </div>
                            </a>
                        </div>
                    </div>
                    <div class="menu-item">
                        <a href="/">Artikel</a>
                    </div>
                    <div class="menu-item">
                        <a href="/">Kontak</a>
                    </div>
                </div>

                <div class="navbar-right">
                    <?php if ($is_logged_in): ?>
                        <a href="/dashboard" class="button">Dashboard</a>
                    <?php else: ?>
                        <?php
                            // Generate OAuth URL only if not already set in session
                            if (!isset($_SESSION['google_auth_url']) || !isset($_SESSION['oauth_state'])) {
                                $_SESSION['google_auth_url'] = get_google_auth_url();
                            }
                        ?>
                        <a href="<?= e($_SESSION['google_auth_url']); ?>">
                            <img src="/assets/images/google_login.svg" alt="Google Logo" width="auto" height="46">
                        </a>
                    <?php endif; ?>
                </div>
            </nav>
    <!--// PHP IF Else-->
        <?php } else { ?>
    <!--// Sidebar-->
        <!--// Style-->
            <style>
            .sidebar {
                width: 250px;
                background: #f8f9fa;
                color: #333;
                display: flex;
                flex-direction: column;
                position: fixed;
                height: 100vh;
                left: 0;
                top: 0;
                z-index: 1000;
            }

            .sidebar-header {
                padding: 2rem 1.5rem 1rem 1.5rem;
                border-bottom: none;
            }

            .sidebar-header h3 {
                margin: 0;
                color: #333;
                font-weight: 600;
                font-size: 1.25rem;
            }

            .sidebar-nav {
                flex: 1;
                padding: 1rem 0;
            }

            .sidebar-nav ul {
                list-style: none;
                margin: 0;
                padding: 0;
            }

            .sidebar-nav li {
                margin: 0.25rem 0;
            }

            .nav-link {
                display: flex;
                align-items: center;
                padding: 0.75rem 1.5rem;
                color: #6c757d;
                text-decoration: none;
                transition: all 0.2s ease;
                border-radius: 0 25px 25px 0;
                margin-right: 1rem;
                font-weight: 500;
            }

            .nav-link:hover {
                background: #e9ecef;
                color: #495057;
            }

            .nav-link.active {
                background: #007bff;
                color: white;
            }

            .nav-link .nav-icon {
                margin-right: 0.75rem;
                font-size: 1.1rem;
            }

            .sidebar-footer {
                padding: 1.5rem;
                border-top: 1px solid #e9ecef;
            }

            .sidebar-footer .btn {
                width: 100%;
                padding: 0.75rem;
                background: #dc3545;
                color: white;
                border: none;
                border-radius: 8px;
                text-decoration: none;
                display: inline-block;
                text-align: center;
                font-weight: 500;
                transition: background 0.2s ease;
            }

            .sidebar-footer .btn:hover {
                background: #c82333;
            }
            </style>
        <!--// HTML-->
            <div class="sidebar">
                <div class="sidebar-header">
                    <h3>Dashboard</h3>
                </div>
                <nav class="sidebar-nav">
                    <ul>
                        <li><a href="#" class="nav-link active"><span class="nav-icon">📊</span>Dashboard</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">👥</span>Members</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">📋</span>Plans</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">📄</span>Gated Content</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">🔧</span>Components</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">👥</span>Community</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">📊</span>Event Log</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">🛠️</span>Dev Tools</a></li>
                        <li><a href="#" class="nav-link"><span class="nav-icon">⚙️</span>Settings</a></li>
                    </ul>
                </nav>
                <div class="sidebar-footer">
                    <a href="/logout" class="btn btn-danger">Logout</a>
                </div>
            </div>
    <!--PHP IF End-->
        <?php } ?>
<!-- </navigation>  -->
