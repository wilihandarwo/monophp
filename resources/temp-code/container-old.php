<div class="container">


    <?php
    // Page content based on current page
    switch ($current_page) {
        case 'home':
            ?>
            <!-- <hero section -->
            <style>
                #hero-section {
                    padding: var(--space-xl) 0 var(--space-xl);
                    background: linear-gradient(135deg, var(--white) 0%, var(--gray-50) 100%);
                    background-image: radial-gradient(circle, var(--bg-body-transparent), var(--bg-body)), url('/assets/images/background-square.svg');
                    background-repeat: repeat;
                    background-size: auto, 20px 20px;
                    background-position: center, 0 0;
                    margin-bottom: var(--space-4xl);
                    width: 100vw;
                    margin-left: calc(-50vw + 50%);
                    position: relative;
                    margin-top: var(--space-sm);
                }
                .hero-container {
                    max-width: var(--container-2xl);
                    margin: 0 auto;
                    padding: 0 var(--space-xl);
                    display: flex;
                    align-items: center;
                    gap: var(--space-lg);
                }
                .hero-content {
                    flex: 1;
                    text-align: left;
                }
                .hero-image {
                    flex: 1;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .hero-image img {
                    max-width: 100%;
                    height: auto;
                    border-radius: 12px;
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                }
                .hero-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: var(--space-xs);
                    font-size: var(--text-sm);
                    color: var(--text-secondary);
                    font-weight: var(--font-medium);
                    margin-bottom: var(--space-md);
                }
                .hero-title {
                    font-family: var(--font-serif);
                    font-size: var(--text-6xl);
                    font-weight: var(--font-bold);
                    line-height: var(--leading-tight);
                    margin: 0 0 var(--space-lg) 0;
                    color: var(--text-primary);
                    border: none;
                    padding: 0;
                }
                .hero-title-highlight {
                    color: var(--primary);
                }
                .hero-subtitle {
                    font-size: var(--text-xl);
                    line-height: var(--leading-relaxed);
                    color: var(--text-secondary);
                    margin: 0 0 var(--space-2xl) 0;
                    max-width: var(--container-sm);
                }
                .hero-cta-buttons {
                    display: flex;
                    gap: var(--space-lg);
                    justify-content: flex-start;
                    margin-bottom: var(--space-2xl);
                }
                .hero-cta-primary {
                    background: var(--primary);
                    color: var(--white) !important;
                    text-align: center; align-items: center;
                    padding: 16px 32px; border-radius: var(--radius-md);
                    font-weight: var(--font-bold); font-size: var(--text-base);
                    box-shadow: var(--button-shadow);
                    transition: var(--transition-base);
                    border: none;
                    display: inline-flex;
                    cursor: pointer;
                    text-decoration: none;
                }
                .hero-cta-secondary {
                    background: var(--white);
                    color: var(--text-secondary) !important;
                    padding: 16px 32px; border-radius: var(--radius-md);
                    font-weight: var(--font-semibold); font-size: var(--text-base);
                    text-decoration: none;
                    border: 2px solid var(--border-light);
                    transition: var(--transition-base);
                    display: inline-flex;
                    align-items: center;
                    box-shadow: var(--button-secondary-shadow);
                }
                .trusted-by-section {
                    text-align: left;
                }
                .trusted-by-title {
                    font-size: var(--text-sm);
                    color: var(--text-muted);
                    font-weight: var(--font-medium);
                    letter-spacing: 0.05em;
                    margin-bottom: var(--space-xl);
                    text-transform: uppercase;
                }
                .trusted-by-logos {
                    display: flex;
                    align-items: center;
                    justify-content: flex-start;
                    gap: var(--space-2xl);
                    flex-wrap: wrap;
                }
                .trusted-by-logo {
                    height: 0.9rem;
                    max-width: 100px;
                    filter: grayscale(1) opacity(0.5);
                    transition: filter 0.2s ease;
                }
                .trusted-by-logo:hover {
                    filter: grayscale(0) opacity(1);
                }

                @media (max-width: 768px) {
                  .hero-title {
                    font-size: clamp(2rem, 8vw, var(--text-4xl));
                    line-height: var(--leading-tight);
                  }
                  .hero-subtitle {
                    font-size: var(--text-lg);
                    max-width: 100%;
                  }
                  .hero-cta-buttons {
                    flex-direction: column;
                    align-items: stretch;
                  }
                  .hero-cta-primary, .hero-cta-secondary {
                    width: 80%;
                    justify-content: center;
                  }
                }

                @media (max-width: 1024px) {
                  #hero-section {
                    padding: var(--space-xl) 0 var(--space-2xl);
                    margin-top: var(--space-3xl);
                  }
                  .hero-container {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: var(--space-xl);
                  }
                  .hero-content {
                    order: 1;
                    text-align: left;
                  }
                  .hero-image {
                    order: 2;
                    width: 100%;
                    margin-top: var(--space-lg);
                    justify-content: flex-start;
                  }
                  .hero-image img {
                    max-width: 90%;
                    height: auto;
                  }
                  .hero-cta-buttons {
                    justify-content: flex-start;
                    gap: var(--space-md);
                  }
                  .trusted-by-logos {
                    justify-content: flex-start;
                    gap: var(--space-lg);
                  }
                }
            </style>
            <section id="hero-section">
                <div class="hero-container">
                    <!-- Left Column: Content -->
                    <div class="hero-content">
                        <!-- Badge -->
                        <div class="hero-badge">
                            Your SaaS for Everyone
                        </div>

                        <!-- Main Heading -->
                        <h1 class="hero-title">
                            Tinggalkan <span class="hero-title-highlight">cara manual,</span><br>
                            majukan usaha emas Anda.
                        </h1>

                        <!-- Subtitle -->
                        <p class="hero-subtitle">
                            Dari manajemen pelanggan, stock, harga, hingga pembukuan, <br>semua rapi di satu aplikasi.
                        </p>

                        <!-- CTA Buttons -->
                        <div class="hero-cta-buttons">
                            <a href="/register" class="hero-cta-primary">
                                Daftar Sekarang
                            </a>
                            <a href="/about" class="hero-cta-secondary">
                                Lihat Demo
                            </a>
                        </div>

                        <!-- Trusted By Section -->
                        <div class="trusted-by-section">
                            <p class="trusted-by-title">
                                Trusted by
                            </p>
                            <div class="trusted-by-logos">
                                <img src="/assets/images/client-logo.svg" alt="Webflow" class="trusted-by-logo">
                                <img src="/assets/images/client-logo.svg" alt="Slack" class="trusted-by-logo">
                                <img src="/assets/images/client-logo.svg" alt="Finsweet" class="trusted-by-logo">
                                <img src="/assets/images/client-logo.svg" alt="Reddit" class="trusted-by-logo">
                                <img src="/assets/images/client-logo.svg" alt="Amazon" class="trusted-by-logo">
                                <img src="/assets/images/client-logo.svg" alt="Salesforce" class="trusted-by-logo">
                            </div>
                        </div>
                    </div>

                    <!-- Right Column: Hero Image -->
                    <div class="hero-image">
                        <img src="/assets/images/hero-image.webp" alt="Hero Image">
                    </div>
                </div>
            </section>
            <!-- </hero section -->

            <?php break;
        case 'about': ?>
            <div class="content">
                <h2>About MonoPHP</h2>
                <p>MonoPHP is a minimalist PHP framework inspired by the philosophy of keeping things simple and effective. Built with modern web development practices in mind, it provides just enough structure to build robust applications without the bloat.</p>
            </div>
            <?php
            break;

        case 'contact':
            ?>
            <div class="content">
                <h2>Contact Us</h2>
                <p>Have questions about MonoPHP? We'd love to hear from you. Send us a message and we'll get back to you as soon as possible.</p>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem;">
                    <div>
                        <form method="POST" action="/contact" style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <?php echo csrf_field(); ?>

                            <div style="margin-bottom: 1rem;">
                                <label for="name" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Name</label>
                                <input type="text" id="name" name="name" required
                                       style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                            </div>

                            <div style="margin-bottom: 1rem;">
                                <label for="email" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Email</label>
                                <input type="email" id="email" name="email" required
                                       style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                            </div>

                            <div style="margin-bottom: 1rem;">
                                <label for="subject" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Subject</label>
                                <input type="text" id="subject" name="subject" required
                                       style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem;">
                            </div>

                            <div style="margin-bottom: 1.5rem;">
                                <label for="message" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">Message</label>
                                <textarea id="message" name="message" rows="5" required
                                          style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem; resize: vertical;"></textarea>
                            </div>

                            <button type="submit" class="btn" style="width: 100%;">Send Message</button>
                        </form>
                    </div>

                    <div>
                        <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); height: fit-content;">
                            <h3 style="margin-bottom: 1rem; color: #333;">Get in Touch</h3>

                            <div style="margin-bottom: 1.5rem;">
                                <h4 style="margin-bottom: 0.5rem; color: #333;">📧 Email</h4>
                                <p style="margin: 0; color: #666;">hello@monophp.dev</p>
                            </div>

                            <div style="margin-bottom: 1.5rem;">
                                <h4 style="margin-bottom: 0.5rem; color: #333;">💬 Community</h4>
                                <p style="margin: 0; color: #666;">Join our community discussions on GitHub</p>
                            </div>

                            <div style="margin-bottom: 1.5rem;">
                                <h4 style="margin-bottom: 0.5rem; color: #333;">📚 Documentation</h4>
                                <p style="margin: 0; color: #666;">Check out our comprehensive documentation and examples</p>
                            </div>

                            <div>
                                <h4 style="margin-bottom: 0.5rem; color: #333;">🐛 Bug Reports</h4>
                                <p style="margin: 0; color: #666;">Found a bug? Please report it on our GitHub issues page</p>
                            </div>
                        </div>
                    </div>
                </div>
                </div>
            </div>

            <style>
            @media (max-width: 768px) {
                .content > div {
                    grid-template-columns: 1fr !important;
                }
            }
            </style>
            <?php
            break;

        case 'dashboard':
            // Ensure user is logged in (this check is also done in routing)
            if (!$is_logged_in) {
                redirect('/');
            }

            $user = $_SESSION['user'];
            ?>

            <style>
                .dashboard-content {
                    flex: 1;
                    margin-left: 250px;
                    padding: 1rem 0rem 1rem 1rem;
                    position: relative;
                    top: 0;
                    height: 100vh;
                    background: #f8f9fa;
                    overflow: hidden;
                }

                .dashboard-content-wrapper {
                    background: white;
                    border-radius: 16px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.12);
                    border: 1px solid #e9ecef;
                    padding: 2rem;
                    height: calc(100vh - 6rem);
                    overflow-y: auto;
                }

                /* Override container margin for dashboard layout */
                .container {
                    margin: 0 auto !important;
                    padding: 0 !important;
                    max-width: none !important;
                }

                .dashboard-header {
                    margin-bottom: 2rem;
                    padding-bottom: 1rem;
                    border-bottom: 1px solid #e9ecef;
                }

                .dashboard-header h2 {
                    margin: 0 0 0.5rem 0;
                    color: #333;
                    font-weight: 600;
                    font-size: 1.75rem;
                }

                .dashboard-header p {
                    margin: 0;
                    color: #6c757d;
                    font-size: 1rem;
                }

                .dashboard-cards {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }

                .dashboard-card {
                    background: #f8f9fa;
                    padding: 2rem;
                    border-radius: 12px;
                    border: 1px solid #e9ecef;
                    transition: transform 0.2s ease, background-color 0.2s ease;
                }

                .dashboard-card:hover {
                    transform: translateY(-2px);
                    background: white;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                }

                .card-header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 1rem;
                }

                .card-icon {
                    width: 40px;
                    height: 40px;
                    background: #007bff;
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-right: 1rem;
                    font-size: 1.2rem;
                }

                .card-title {
                    margin: 0;
                    color: #333;
                    font-weight: 600;
                    font-size: 1.1rem;
                }

                .card-content {
                    color: #6c757d;
                    line-height: 1.6;
                }

                .content-body {
                    background: white;
                    padding: 2rem;
                    border-radius: 12px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                    border: 1px solid #e9ecef;
                }

                .placeholder-content {
                    text-align: center;
                    padding: 3rem;
                    color: #6c757d;
                }

                @media (max-width: 768px) {
                    .sidebar {
                        width: 100%;
                        height: auto;
                        position: relative;
                    }

                    .dashboard-content {
                        margin-left: 0;
                        padding: 1rem;
                    }

                    .dashboard-layout {
                        flex-direction: column;
                    }
                }
            </style>
            <!-- Main Content -->
            <div class="dashboard-content">
                <div class="dashboard-content-wrapper">
                    <div class="dashboard-header">
                        <h2>Create a Test Member</h2>
                        <p>Create your first member to change their plans, edit custom fields, login as that person, etc.</p>
                    </div>

                    <div class="dashboard-cards">
                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">👥</div>
                            <h3 class="card-title">Members</h3>
                        </div>
                        <div class="card-content">
                            <p>Manage your community members, their profiles, and access levels.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📋</div>
                            <h3 class="card-title">Plans</h3>
                        </div>
                        <div class="card-content">
                            <p>Create and manage subscription plans for your members.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📄</div>
                            <h3 class="card-title">Gated Content</h3>
                        </div>
                        <div class="card-content">
                            <p>Control access to premium content based on membership levels.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">🔧</div>
                            <h3 class="card-title">Components</h3>
                        </div>
                        <div class="card-content">
                            <p>Customize and configure various components of your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">👥</div>
                            <h3 class="card-title">Community</h3>
                        </div>
                        <div class="card-content">
                            <p>Foster engagement and build connections within your community.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>


                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>


                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>

                    <div class="dashboard-card">
                        <div class="card-header">
                            <div class="card-icon">📊</div>
                            <h3 class="card-title">Analytics</h3>
                        </div>
                        <div class="card-content">
                            <p>Track performance metrics and gain insights into your platform.</p>
                        </div>
                    </div>
                </div>
            </div>

            <?php
            break;
        // <settings>
        case 'settings':
            // Ensure user is logged in (this check is also done in routing)
            if (!$is_logged_in) {
                redirect('/');
            }

            $user = $_SESSION['user'];
            ?>

            <!-- Main Content -->
            <div class="dashboard-content">
                <div class="dashboard-header">
                    <h2>Settings, <?= e($user['name']); ?>!</h2>
                    <p>Here's what's happening with your account today.</p>
                </div>
                <div class="content-body">
                    <!-- Content will go here -->
                    <div class="placeholder-content">
                        <p>Main content area - ready for your content!</p>
                    </div>
                </div>
            </div>

            <?php
            break;
            // </settings>

        default:
            // Default to home page
            ?>
            <div class="hero">
                <h1>MonoPHP</h1>
                <p>Simple & Minimalist PHP Framework</p>

                <?php if (!$is_logged_in): ?>
                    <p>Build fast, secure web applications with minimal code.</p>
                    <a href="<?php echo e($_SESSION['google_auth_url']); ?>" class="btn btn-google">
                        <svg width="16" height="16" viewBox="0 0 24 24">
                            <path fill="white" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                            <path fill="white" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                            <path fill="white" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                            <path fill="white" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                        </svg>
                        Get Started with Google
                    </a>
                <?php else: ?>
                    <p>Welcome back, <strong><?php echo e($_SESSION['user']['name']); ?></strong>!</p>
                    <a href="/dashboard" class="btn">Go to Dashboard</a>
                <?php endif; ?>
            </div>
            <?php
            break;
    }
    ?>
</div>
