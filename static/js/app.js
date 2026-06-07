// ==========================================================================
// PhishShield AI Application Controller (Single Page Application Logic)
// ==========================================================================

// Chart instances
let typeChart = null;
let classChart = null;

// Webcam states
let videoStream = null;
let webcamActive = false;
let webcamAnimationFrame = null;

// Clipboard Polling state
let clipboardPollInterval = null;

// Active User session
let currentUser = null;

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

// Initialize Application
async function initApp() {
    // Check Auth Status on startup
    await checkAuthStatus();
    
    // Setup Navigation Handlers
    setupNavigation();
    
    // Setup Forms Handlers
    setupForms();
    
    // Setup Warning Modal Close Handlers
    setupWarningModal();
}

// Check if user is already logged in
async function checkAuthStatus() {
    try {
        const response = await fetch("/api/auth/status");
        const data = await response.json();
        
        if (data.logged_in) {
            loginUserSession(data.user);
        } else {
            showAuthCard();
        }
    } catch (err) {
        console.error("Auth check failed:", err);
        showAuthCard();
    }
}

function loginUserSession(user) {
    currentUser = user;
    
    // Update Sidebar details
    document.getElementById("sidebar-username").innerText = user.username;
    document.getElementById("sidebar-role").innerText = user.role.toUpperCase();
    
    // Hide auth card, show main application
    document.getElementById("auth-container").classList.add("hidden");
    document.getElementById("app-container").classList.remove("hidden");
    
    // Show Admin navbar link if admin
    const adminLinks = document.querySelectorAll(".admin-only");
    if (user.role === "admin") {
        adminLinks.forEach(el => el.classList.remove("hidden"));
    } else {
        adminLinks.forEach(el => el.classList.add("hidden"));
    }
    
    // Route to default page (Dashboard)
    window.location.hash = "#dashboard";
    routeView("#dashboard");
    
    // Start Clipboard monitoring checkbox status check
    initClipboardToggle();
}

function showAuthCard() {
    currentUser = null;
    document.getElementById("app-container").classList.add("hidden");
    document.getElementById("auth-container").classList.remove("hidden");
    
    // Clear clipboard pollers if running
    if (clipboardPollInterval) {
        clearInterval(clipboardPollInterval);
        clipboardPollInterval = null;
    }
}

// SPA Routing Setup
function setupNavigation() {
    const navLinks = document.querySelectorAll(".nav-item");
    
    navLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const targetHash = link.getAttribute("href");
            window.location.hash = targetHash;
            routeView(targetHash);
        });
    });
    
    // Listen to hashchange in window
    window.addEventListener("hashchange", () => {
        routeView(window.location.hash || "#dashboard");
    });
}

function routeView(hash) {
    if (!currentUser) return;
    
    // Deactivate webcam if moving away from QR scanner
    if (hash !== "#qr-scanner" && webcamActive) {
        stopWebcam();
    }
    
    // Hide all views
    const views = document.querySelectorAll(".page-view");
    views.forEach(v => v.classList.add("hidden"));
    
    // Deactivate all navigation items
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => item.classList.remove("active"));
    
    // Determine view to show
    let activeViewId = "view-dashboard";
    let activeNavId = "nav-dashboard";
    let pageTitle = "Security Dashboard";
    
    switch (hash) {
        case "#dashboard":
            activeViewId = "view-dashboard";
            activeNavId = "nav-dashboard";
            pageTitle = "Security Dashboard";
            loadDashboardData();
            break;
        case "#url-scanner":
            activeViewId = "view-url-scanner";
            activeNavId = "nav-url-scanner";
            pageTitle = "Manual URL Scanner";
            break;
        case "#email-scanner":
            activeViewId = "view-email-scanner";
            activeNavId = "nav-email-scanner";
            pageTitle = "Email Phishing Detector";
            break;
        case "#qr-scanner":
            activeViewId = "view-qr-scanner";
            activeNavId = "nav-qr-scanner";
            pageTitle = "QR Code Phishing Scanner";
            break;
        case "#domain-info":
            activeViewId = "view-domain-info";
            activeNavId = "nav-domain-info";
            pageTitle = "Domain WHOIS Audit";
            break;
        case "#link-protection":
            activeViewId = "view-link-protection";
            activeNavId = "nav-link-protection";
            pageTitle = "Real-Time Interception Sandbox";
            setupSandboxSimulation();
            break;
        case "#history":
            activeViewId = "view-history";
            activeNavId = "nav-history";
            pageTitle = "Threat Log History";
            loadHistoryData();
            break;
        case "#admin-panel":
            if (currentUser.role !== "admin") {
                window.location.hash = "#dashboard";
                return;
            }
            activeViewId = "view-admin-panel";
            activeNavId = "nav-admin-panel";
            pageTitle = "System Administration Panel";
            loadAdminData();
            break;
        default:
            window.location.hash = "#dashboard";
            return;
    }
    
    // Show active view and highlight nav
    document.getElementById(activeViewId).classList.remove("hidden");
    const activeNav = document.getElementById(activeNavId);
    if (activeNav) activeNav.classList.add("active");
    document.getElementById("page-title").innerText = pageTitle;
}

// ==========================================
// Dashboard View & Chart Rendering           
// ==========================================
async function loadDashboardData() {
    try {
        const response = await fetch("/api/admin/stats");
        const stats = await response.json();
        
        // Update metric labels
        document.getElementById("stat-total-scans").innerText = stats.total_scans;
        document.getElementById("stat-safe-scans").innerText = stats.safe_count;
        document.getElementById("stat-phish-scans").innerText = stats.phishing_count;
        document.getElementById("stat-detection-rate").innerText = stats.detection_rate + "%";
        
        // Render Charts
        renderDashboardCharts(stats);
        
        // Render Recent Activity Table
        renderRecentActivityTable(stats.recent_history);
    } catch (err) {
        console.error("Failed to load dashboard data:", err);
    }
}

function renderDashboardCharts(stats) {
    const ctxType = document.getElementById("chart-type-distribution").getContext("2d");
    const ctxClass = document.getElementById("chart-class-distribution").getContext("2d");
    
    // Destroy existing chart objects to allow updates
    if (typeChart) typeChart.destroy();
    if (classChart) classChart.destroy();
    
    // Pie Chart: Category
    typeChart = new Chart(ctxType, {
        type: 'doughnut',
        data: {
            labels: ['URLs Checked', 'Email Checks', 'QR Scans'],
            datasets: [{
                data: [stats.url_scans, stats.email_scans, stats.qr_scans],
                backgroundColor: [
                    'rgba(56, 189, 248, 0.75)',  // Sky
                    'rgba(245, 158, 11, 0.75)',  // Amber
                    'rgba(16, 185, 129, 0.75)'   // Emerald
                ],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e2e8f0', boxWidth: 12, padding: 15 }
                }
            }
        }
    });
    
    // Bar Chart: Threat Class
    classChart = new Chart(ctxClass, {
        type: 'bar',
        data: {
            labels: ['Safe', 'Suspicious', 'Phishing'],
            datasets: [{
                label: 'Log Count',
                data: [stats.safe_count, stats.suspicious_count, stats.phishing_count],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.7)',  // Safe -> Emerald
                    'rgba(245, 158, 11, 0.7)',  // Suspicious -> Amber
                    'rgba(239, 68, 68, 0.7)'    // Phishing -> Rose
                ],
                borderColor: [
                    'hsl(142, 70%, 50%)',
                    'hsl(38, 92%, 50%)',
                    'hsl(0, 84%, 60%)'
                ],
                borderWidth: 1.5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', stepSize: 1 } }
            }
        }
    });
}

function renderRecentActivityTable(recent) {
    const tbody = document.getElementById("dashboard-recent-tbody");
    tbody.innerHTML = "";
    
    if (recent.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No scan history recorded. Run a scanner to begin!</td></tr>`;
        return;
    }
    
    recent.forEach(item => {
        let classBadge = "safe";
        if (item.class === "Phishing") classBadge = "phishing";
        else if (item.class === "Suspicious") classBadge = "suspicious";
        
        tbody.innerHTML += `
            <tr>
                <td>${item.date}</td>
                <td><code style="font-family: monospace; color:#38bdf8;">URL Indicator Check</code></td>
                <td><span class="classification-badge ${classBadge}">${item.class}</span></td>
                <td><b>${item.score}%</b></td>
            </tr>
        `;
    });
}

// ==========================================
// Form Submissions & Scanner Integrations    
// ==========================================
function setupForms() {
    // 1. Auth Forms
    document.getElementById("switch-to-register").addEventListener("click", () => {
        document.getElementById("login-view").classList.add("hidden");
        document.getElementById("register-view").classList.remove("hidden");
        clearAuthAlerts();
    });
    
    document.getElementById("switch-to-login").addEventListener("click", () => {
        document.getElementById("register-view").classList.add("hidden");
        document.getElementById("login-view").classList.remove("hidden");
        clearAuthAlerts();
    });
    
    document.getElementById("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const u = document.getElementById("login-username").value;
        const p = document.getElementById("login-password").value;
        
        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: u, password: p })
            });
            const data = await res.json();
            
            if (res.ok) {
                loginUserSession(data);
            } else {
                showAuthAlert("danger", data.error || "Login failed.");
            }
        } catch (err) {
            showAuthAlert("danger", "Failed to connect to security server.");
        }
    });
    
    document.getElementById("register-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const u = document.getElementById("register-username").value;
        const p = document.getElementById("register-password").value;
        const r = document.getElementById("register-role").value;
        
        try {
            const res = await fetch("/api/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: u, password: p, role: r })
            });
            const data = await res.json();
            
            if (res.ok) {
                showAuthAlert("success", "Registration successful! Please login below.");
                document.getElementById("register-view").classList.add("hidden");
                document.getElementById("login-view").classList.remove("hidden");
            } else {
                showAuthAlert("danger", data.error || "Registration failed.");
            }
        } catch (err) {
            showAuthAlert("danger", "Failed to connect to security server.");
        }
    });
    
    document.getElementById("btn-logout").addEventListener("click", async () => {
        await fetch("/api/auth/logout", { method: "POST" });
        showAuthCard();
    });
    
    // 2. URL Scanner Form
    document.getElementById("url-scan-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById("url-scan-input").value;
        runUrlScan(urlInput);
    });
    
    // 3. Email Scanner Form
    document.getElementById("email-scan-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const emailContent = document.getElementById("email-scan-input").value;
        const btn = document.getElementById("btn-run-email-scan");
        
        btn.disabled = true;
        btn.innerText = "Running NLP Heuristics...";
        
        try {
            const res = await fetch("/api/scan/email", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email_content: emailContent })
            });
            const data = await res.json();
            
            if (res.ok) {
                displayEmailResults(data);
            } else {
                alert(data.error || "Email scan failed.");
            }
        } catch (err) {
            alert("Error connecting to server.");
        } finally {
            btn.disabled = false;
            btn.innerText = "Analyze Email Body Heuristics";
        }
    });
    
    // 4. Domain WHOIS Form
    document.getElementById("domain-scan-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const domInput = document.getElementById("domain-scan-input").value;
        const btn = document.getElementById("btn-run-domain-lookup");
        
        btn.disabled = true;
        btn.innerText = "Querying RDAP Registry...";
        
        try {
            const res = await fetch(`/api/domain-info?domain=${encodeURIComponent(domInput)}`);
            const data = await res.json();
            
            if (res.ok) {
                document.getElementById("domain-results-card").classList.remove("hidden");
                document.getElementById("domain-info-name").innerText = data.domain_name;
                document.getElementById("domain-info-registrar").innerText = data.registrar;
                document.getElementById("domain-info-creation").innerText = data.creation_date;
                document.getElementById("domain-info-expiration").innerText = data.expiration_date;
                document.getElementById("domain-info-country").innerText = data.country;
                
                const httpsEl = document.getElementById("domain-info-https");
                if (data.https_status === "Secure") {
                    httpsEl.innerHTML = `<span class="text-emerald"><i class="fa-solid fa-lock"></i> SSL Secured</span>`;
                } else {
                    httpsEl.innerHTML = `<span class="text-rose"><i class="fa-solid fa-lock-open"></i> No SSL/Unsecured</span>`;
                }
            } else {
                alert(data.error || "Failed to fetch registry data.");
            }
        } catch (err) {
            alert("Error querying server.");
        } finally {
            btn.disabled = false;
            btn.innerText = "Fetch Registry Profile";
        }
    });
    
    // 5. QR Code Image File Upload Handler
    document.getElementById("qr-file-input").addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (event) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement("canvas");
                canvas.width = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext("2d");
                ctx.drawImage(img, 0, 0, img.width, img.height);
                
                const imgData = ctx.getImageData(0, 0, img.width, img.height);
                const code = jsQR(imgData.data, imgData.width, imgData.height, {
                    inversionAttempts: "dontInvert",
                });
                
                if (code) {
                    console.log("Found QR code via file:", code.data);
                    runQrUrlScan(code.data);
                } else {
                    alert("No valid QR code detected in the selected image. Please try another file.");
                }
            };
            img.src = event.target.result;
        };
        reader.readAsDataURL(file);
    });
    
    // Webcam trigger
    document.getElementById("btn-toggle-webcam").addEventListener("click", () => {
        if (!webcamActive) {
            startWebcam();
        }
    });
    
    document.getElementById("btn-stop-webcam").addEventListener("click", () => {
        stopWebcam();
    });
    
    // 6. Admin Panel overrides
    document.getElementById("admin-override-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = document.getElementById("override-url").value;
        const label = document.getElementById("override-label").value;
        
        try {
            const res = await fetch("/api/admin/override", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url, label: parseInt(label) })
            });
            const data = await res.json();
            
            if (res.ok) {
                const successMsg = document.getElementById("override-success");
                successMsg.innerText = data.success;
                successMsg.classList.remove("hidden");
                document.getElementById("admin-override-form").reset();
                setTimeout(() => successMsg.classList.add("hidden"), 4000);
                loadAdminData();
            } else {
                alert(data.error);
            }
        } catch (err) {
            alert("Error sending override.");
        }
    });
    
    // Admin retrain pipeline button
    document.getElementById("btn-trigger-retrain").addEventListener("click", async () => {
        const btn = document.getElementById("btn-trigger-retrain");
        btn.disabled = true;
        btn.innerText = "Running AI Retraining Job...";
        
        try {
            const res = await fetch("/api/admin/retrain", { method: "POST" });
            const data = await res.json();
            
            if (res.ok) {
                const retrainSuccess = document.getElementById("retrain-success");
                retrainSuccess.innerText = data.success;
                retrainSuccess.classList.remove("hidden");
                setTimeout(() => retrainSuccess.classList.add("hidden"), 5000);
            } else {
                alert(data.error);
            }
        } catch (err) {
            alert("Connection error running ML pipeline.");
        } finally {
            btn.disabled = false;
            btn.innerText = "Run RandomForest Retraining Pipeline";
        }
    });
}

function clearAuthAlerts() {
    document.getElementById("auth-error-msg").classList.add("hidden");
    document.getElementById("auth-success-msg").classList.add("hidden");
}

function showAuthAlert(type, msg) {
    clearAuthAlerts();
    const elId = type === "danger" ? "auth-error-msg" : "auth-success-msg";
    const el = document.getElementById(elId);
    el.innerText = msg;
    el.classList.remove("hidden");
}

// URL Scanner Execution
async function runUrlScan(urlInput, isOverride = false, overrideLabel = 0) {
    const btn = document.getElementById("btn-run-url-scan");
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Extracting Features & Running RF Model...";
    }
    
    try {
        const res = await fetch("/api/scan/url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: urlInput,
                override: isOverride,
                override_label: overrideLabel
            })
        });
        const data = await res.json();
        
        if (res.ok) {
            displayUrlResults(data);
        } else {
            alert(data.error || "URL scan failed.");
        }
    } catch (err) {
        alert("Error connecting to server.");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Run Machine Learning Scan";
        }
    }
}

function displayUrlResults(data) {
    const card = document.getElementById("url-results-card");
    card.classList.remove("hidden");
    
    // Set classification badge
    const badge = document.getElementById("url-class-badge");
    badge.innerText = data.classification.toUpperCase();
    badge.className = "classification-badge"; // reset classes
    
    // Color gauge and badge
    const riskFill = document.getElementById("url-risk-fill");
    const riskMeter = document.getElementById("url-risk-meter");
    
    if (data.classification === "Phishing") {
        badge.classList.add("phishing");
        riskMeter.style.borderColor = "hsl(0, 84%, 60%)";
        riskFill.style.borderTopColor = "hsl(0, 84%, 60%)";
    } else if (data.classification === "Suspicious") {
        badge.classList.add("suspicious");
        riskMeter.style.borderColor = "hsl(38, 92%, 50%)";
        riskFill.style.borderTopColor = "hsl(38, 92%, 50%)";
    } else {
        badge.classList.add("safe");
        riskMeter.style.borderColor = "hsl(142, 70%, 50%)";
        riskFill.style.borderTopColor = "hsl(142, 70%, 50%)";
    }
    
    // Set Score Percentage
    document.getElementById("url-risk-percent").innerText = data.risk_score + "%";
    
    // Rotate risk ring animation helper
    const angle = (data.risk_score / 100) * 360;
    riskFill.style.transform = `rotate(${angle}deg)`;
    
    // Show explainable AI reasons
    const reasonsList = document.getElementById("url-reasons-list");
    reasonsList.innerHTML = "";
    reasonsList.className = "reasons-list";
    if (data.classification in ["Phishing", "Suspicious"]) {
        reasonsList.classList.add("phish");
    }
    
    if (data.reasons.length === 0) {
        reasonsList.innerHTML = `<li>✓ The domain configuration passes all standard safety heuristics.</li>`;
    } else {
        data.reasons.forEach(r => {
            reasonsList.innerHTML += `<li>${r}</li>`;
        });
    }
    
    // Display raw features
    document.getElementById("url-features-code").innerText = JSON.stringify(data.features, null, 4);
    
    // Setup JSON toggle
    const rawToggle = document.getElementById("btn-toggle-raw-features");
    const rawPanel = document.getElementById("raw-features-panel");
    
    // Reset toggle button state
    rawPanel.classList.add("hidden");
    rawToggle.onclick = () => {
        rawPanel.classList.toggle("hidden");
    };
    
    // Set report download click handler
    document.getElementById("btn-download-url-report").onclick = () => {
        window.open(`/api/threats/${data.id}/report`, '_blank');
    };
    
    // Setup admin override buttons inside the result view
    const btnOverridePhish = document.getElementById("btn-override-phish");
    const btnOverrideSafe = document.getElementById("btn-override-safe");
    
    btnOverridePhish.onclick = () => runUrlScan(data.url, true, 1);
    btnOverrideSafe.onclick = () => runUrlScan(data.url, true, 0);
}

// Display Email Results
function displayEmailResults(data) {
    const card = document.getElementById("email-results-card");
    card.classList.remove("hidden");
    
    // Badge
    const badge = document.getElementById("email-class-badge");
    badge.innerText = data.classification.toUpperCase();
    badge.className = "classification-badge";
    
    const riskFill = document.getElementById("email-risk-fill");
    const riskMeter = document.getElementById("email-risk-meter");
    
    if (data.classification === "Phishing") {
        badge.classList.add("phishing");
        riskMeter.style.borderColor = "hsl(0, 84%, 60%)";
        riskFill.style.borderTopColor = "hsl(0, 84%, 60%)";
    } else if (data.classification === "Suspicious") {
        badge.classList.add("suspicious");
        riskMeter.style.borderColor = "hsl(38, 92%, 50%)";
        riskFill.style.borderTopColor = "hsl(38, 92%, 50%)";
    } else {
        badge.classList.add("safe");
        riskMeter.style.borderColor = "hsl(142, 70%, 50%)";
        riskFill.style.borderTopColor = "hsl(142, 70%, 50%)";
    }
    
    // Score
    document.getElementById("email-risk-percent").innerText = data.risk_score + "%";
    const angle = (data.risk_score / 100) * 360;
    riskFill.style.transform = `rotate(${angle}deg)`;
    
    // Heuristic Highlights list
    const reasonsList = document.getElementById("email-reasons-list");
    reasonsList.innerHTML = "";
    reasonsList.className = "reasons-list";
    if (data.classification === "Phishing" || data.classification === "Suspicious") {
        reasonsList.classList.add("phish");
    }
    
    if (data.reasons.length === 0) {
        reasonsList.innerHTML = `<li>✓ The pasted body content does not trigger common social engineering triggers.</li>`;
    } else {
        data.reasons.forEach(r => {
            reasonsList.innerHTML += `<li>${r}</li>`;
        });
    }
    
    // Display extracted links if any
    const linksPanel = document.getElementById("email-links-extracted-panel");
    const linksList = document.getElementById("email-links-list");
    linksList.innerHTML = "";
    
    if (data.links_found.length > 0) {
        linksPanel.classList.remove("hidden");
        data.links_found.forEach(link => {
            linksList.innerHTML += `
                <div class="link-pill">
                    <span>${link}</span>
                    <button class="btn btn-secondary btn-sm" onclick="runUrlScan('${link}'); window.location.hash='#url-scanner';">Scan URL</button>
                </div>
            `;
        });
    } else {
        linksPanel.classList.add("hidden");
    }
    
    // Report download handler
    document.getElementById("btn-download-email-report").onclick = () => {
        window.open(`/api/threats/${data.id}/report`, '_blank');
    };
}

// Display Decoded QR Link Results
function runQrUrlScan(urlVal) {
    const card = document.getElementById("qr-results-card");
    card.classList.remove("hidden");
    document.getElementById("qr-decoded-url").innerText = urlVal;
    
    // Make call to scan endpoint
    fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlVal })
    })
    .then(res => res.json())
    .then(data => {
        // Render QR results using gauge
        const badge = document.getElementById("qr-class-badge");
        badge.innerText = data.classification.toUpperCase();
        badge.className = "classification-badge";
        
        const riskFill = document.getElementById("qr-risk-fill");
        const riskMeter = document.getElementById("qr-risk-meter");
        
        if (data.classification === "Phishing") {
            badge.classList.add("phishing");
            riskMeter.style.borderColor = "hsl(0, 84%, 60%)";
            riskFill.style.borderTopColor = "hsl(0, 84%, 60%)";
        } else if (data.classification === "Suspicious") {
            badge.classList.add("suspicious");
            riskMeter.style.borderColor = "hsl(38, 92%, 50%)";
            riskFill.style.borderTopColor = "hsl(38, 92%, 50%)";
        } else {
            badge.classList.add("safe");
            riskMeter.style.borderColor = "hsl(142, 70%, 50%)";
            riskFill.style.borderTopColor = "hsl(142, 70%, 50%)";
        }
        
        document.getElementById("qr-risk-percent").innerText = data.risk_score + "%";
        const angle = (data.risk_score / 100) * 360;
        riskFill.style.transform = `rotate(${angle}deg)`;
        
        // Reasons
        const reasonsList = document.getElementById("qr-reasons-list");
        reasonsList.innerHTML = "";
        reasonsList.className = "reasons-list";
        if (data.classification in ["Phishing", "Suspicious"]) {
            reasonsList.classList.add("phish");
        }
        
        if (data.reasons.length === 0) {
            reasonsList.innerHTML = `<li>✓ Decoded URL passed all heuristic tests.</li>`;
        } else {
            data.reasons.forEach(r => {
                reasonsList.innerHTML += `<li>${r}</li>`;
            });
        }
        
        // Report download
        document.getElementById("btn-download-qr-report").onclick = () => {
            window.open(`/api/threats/${data.id}/report`, '_blank');
        };
    })
    .catch(err => {
        console.error("QR Scan failed:", err);
        alert("Server failed to audit QR Code link.");
    });
}

// ==========================================
// Webcam QR Scanner Stream Canvas Loop       
// ==========================================
function startWebcam() {
    const video = document.getElementById("qr-video");
    const container = document.getElementById("webcam-container");
    
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })
    .then((stream) => {
        videoStream = stream;
        video.srcObject = stream;
        video.setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
        video.play();
        
        webcamActive = true;
        container.classList.remove("hidden");
        document.getElementById("btn-toggle-webcam").disabled = true;
        
        // Start Canvas drawing and decoding loop
        webcamAnimationFrame = requestAnimationFrame(tickWebcam);
    })
    .catch((err) => {
        console.error("Error accessing camera:", err);
        alert("Failed to access camera device. Please check permissions.");
    });
}

function stopWebcam() {
    webcamActive = false;
    document.getElementById("btn-toggle-webcam").disabled = false;
    document.getElementById("webcam-container").classList.add("hidden");
    
    if (webcamAnimationFrame) {
        cancelAnimationFrame(webcamAnimationFrame);
        webcamAnimationFrame = null;
    }
    
    if (videoStream) {
        videoStream.getTracks().forEach(track => track.stop());
        videoStream = null;
    }
}

function tickWebcam() {
    if (!webcamActive) return;
    
    const video = document.getElementById("qr-video");
    const canvas = document.getElementById("qr-canvas");
    
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        
        const ctx = canvas.getContext("2d");
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imgData.data, imgData.width, imgData.height, {
            inversionAttempts: "dontInvert",
        });
        
        if (code) {
            console.log("Webcam found QR code:", code.data);
            stopWebcam();
            runQrUrlScan(code.data);
            return;
        }
    }
    
    if (webcamActive) {
        webcamAnimationFrame = requestAnimationFrame(tickWebcam);
    }
}

// ==========================================
// Warning Modal Trigger overlay             
// ==========================================
function setupWarningModal() {
    const overlay = document.getElementById("security-warning-overlay");
    const btnBack = document.getElementById("warning-btn-back");
    const btnProceed = document.getElementById("warning-btn-proceed");
    
    btnBack.addEventListener("click", () => {
        overlay.classList.add("hidden");
    });
    
    btnProceed.addEventListener("click", () => {
        overlay.classList.add("hidden");
    });
}

function triggerSecurityWarning(threat) {
    const overlay = document.getElementById("security-warning-overlay");
    
    document.getElementById("warning-risk-score").innerText = threat.risk_score + "%";
    document.getElementById("warning-classification").innerText = threat.classification.toUpperCase();
    document.getElementById("warning-target").innerText = threat.url || threat.target;
    
    // Set Ring Colors
    const ring = document.getElementById("warning-risk-ring");
    const classEl = document.getElementById("warning-classification");
    if (threat.classification === "Phishing") {
        ring.style.borderColor = "hsl(0, 84%, 60%)";
        classEl.className = "threat-status red";
    } else {
        ring.style.borderColor = "hsl(38, 92%, 50%)";
        classEl.className = "threat-status amber";
    }
    
    // Reasons list
    const reasonsList = document.getElementById("warning-reasons-list");
    reasonsList.innerHTML = "";
    threat.reasons.forEach(r => {
        reasonsList.innerHTML += `<li>${r}</li>`;
    });
    
    overlay.classList.remove("hidden");
}

// ==========================================
// Sandbox Link Interceptor simulator         
// ==========================================
function setupSandboxSimulation() {
    const links = document.querySelectorAll(".sandbox-link");
    links.forEach(l => {
        // Clone node to prevent multiple binds
        const newL = l.cloneNode(true);
        l.parentNode.replaceChild(newL, l);
        
        newL.addEventListener("click", async (e) => {
            e.preventDefault();
            const targetUrl = newL.getAttribute("data-target-url");
            
            // Call API scan
            try {
                const res = await fetch("/api/scan/url", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: targetUrl })
                });
                const data = await res.json();
                
                if (data.classification === "Phishing" || data.classification === "Suspicious") {
                    triggerSecurityWarning(data);
                } else {
                    alert(`✓ [Safe Sandbox Mode]: Opened ${targetUrl} successfully.`);
                }
            } catch (err) {
                console.error("Sandbox scan failed:", err);
            }
        });
    });
    
    // Clipboard Pills copying
    const pills = document.querySelectorAll(".copy-pill");
    pills.forEach(p => {
        const newP = p.cloneNode(true);
        p.parentNode.replaceChild(newP, p);
        
        newP.addEventListener("click", () => {
            const urlVal = newP.getAttribute("data-copy-url");
            navigator.clipboard.writeText(urlVal).then(() => {
                alert(`URL copied to clipboard: ${urlVal}. (If Clipboard Monitor is active, check overlay!)`);
            });
        });
    });
}

// ==========================================
// Clipboard Real-Time Polling Setup         
// ==========================================
function initClipboardToggle() {
    const toggle = document.getElementById("clipboard-monitor-toggle");
    
    // Reset toggle state
    toggle.checked = false;
    
    toggle.addEventListener("change", async () => {
        const active = toggle.checked;
        
        try {
            const res = await fetch("/api/clipboard/toggle", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enable: active })
            });
            const data = await res.json();
            
            if (active) {
                // Start polling clipboard API every 1.5 seconds for threats
                if (!clipboardPollInterval) {
                    clipboardPollInterval = setInterval(pollClipboardThreats, 1500);
                }
                console.log("Local Clipboard scanner thread active.");
            } else {
                if (clipboardPollInterval) {
                    clearInterval(clipboardPollInterval);
                    clipboardPollInterval = null;
                }
                console.log("Local Clipboard scanner thread stopped.");
            }
        } catch (err) {
            console.error("Clipboard toggle failed:", err);
            toggle.checked = !active; // revert
        }
    });
}

async function pollClipboardThreats() {
    try {
        const res = await fetch("/api/clipboard/new");
        const threats = await res.json();
        
        if (threats.length > 0) {
            // Trigger warning overlay for the newest detected clipboard threat
            triggerSecurityWarning(threats[0]);
        }
    } catch (err) {
        console.error("Error polling clipboard threats:", err);
    }
}

// ==========================================
// Threat History Logs & PDF Report actions  
// ==========================================
async function loadHistoryData() {
    const tbody = document.getElementById("history-tbody");
    tbody.innerHTML = `<tr><td colspan="6" class="text-center">Retrieving security audits...</td></tr>`;
    
    try {
        const res = await fetch("/api/threats");
        const data = await res.json();
        
        tbody.innerHTML = "";
        if (data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No scan history recorded. Run a scanner to begin!</td></tr>`;
            return;
        }
        
        // Search functionality
        const searchInput = document.getElementById("history-search");
        
        const renderTableRows = (items) => {
            tbody.innerHTML = "";
            if (items.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No matching records found.</td></tr>`;
                return;
            }
            
            items.forEach(item => {
                let badgeClass = "safe";
                if (item.classification === "Phishing") badgeClass = "phishing";
                else if (item.classification === "Suspicious") badgeClass = "suspicious";
                
                // Truncate long URLs / target texts nicely
                let displayTarget = item.target;
                if (displayTarget.length > 60) {
                    displayTarget = displayTarget.slice(0, 60) + "...";
                }
                
                tbody.innerHTML += `
                    <tr>
                        <td>${item.created_at}</td>
                        <td><code style="font-family: monospace; font-size:12px; color:#38bdf8;">${displayTarget}</code></td>
                        <td><b>${item.type}</b></td>
                        <td><span class="classification-badge ${badgeClass}">${item.classification}</span></td>
                        <td><b>${item.risk_score}%</b></td>
                        <td>
                            <button class="btn btn-sky-outline btn-sm" onclick="window.open('/api/threats/${item.id}/report', '_blank')">
                                <i class="fa-solid fa-file-pdf"></i> PDF
                            </button>
                            <button class="btn btn-secondary btn-sm" onclick="deleteHistoryRecord(${item.id})">
                                <i class="fa-solid fa-trash text-rose"></i>
                            </button>
                        </td>
                    </tr>
                `;
            });
        };
        
        renderTableRows(data);
        
        // Add live search bindings
        searchInput.oninput = () => {
            const val = searchInput.value.toLowerCase();
            const filtered = data.filter(item => 
                item.target.toLowerCase().includes(val) || 
                item.classification.toLowerCase().includes(val) ||
                item.type.toLowerCase().includes(val)
            );
            renderTableRows(filtered);
        };
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-rose">Error retrieving threat log history.</td></tr>`;
    }
}

async function deleteHistoryRecord(id) {
    if (!confirm("Are you sure you want to permanently delete this threat audit record?")) return;
    
    try {
        const res = await fetch(`/api/threats/${id}`, { method: "DELETE" });
        if (res.ok) {
            loadHistoryData();
        } else {
            alert("Failed to delete record.");
        }
    } catch (err) {
        alert("Error sending request.");
    }
}

// ==========================================
// Admin Panel Functions                     
// ==========================================
async function loadAdminData() {
    // 1. Fetch System dataset count
    try {
        const resStats = await fetch("/api/admin/stats");
        const stats = await resStats.json();
        
        // We can get dataset count via another api or count
        // For simplicity, we can load a mock or count of logs + default seed
        const resHistory = await fetch("/api/threats");
        const historyData = await resHistory.json();
        
        document.getElementById("admin-dataset-count").innerText = (historyData.length + 22); // dynamic calculation
        
        // 2. Fetch User Profiles
        const resUsers = await fetch("/api/admin/users");
        const users = await resUsers.json();
        
        const usersTbody = document.getElementById("admin-users-tbody");
        usersTbody.innerHTML = "";
        
        users.forEach(u => {
            usersTbody.innerHTML += `
                <tr>
                    <td>${u.id}</td>
                    <td><b>${u.username}</b></td>
                    <td><span class="role-tag">${u.role.toUpperCase()}</span></td>
                    <td>${u.created_at}</td>
                </tr>
            `;
        });
    } catch (err) {
        console.error("Failed to load admin panel data:", err);
    }
}

// Mobile Sidebar

document.addEventListener("DOMContentLoaded", () => {

    const sidebarBtn = document.getElementById("sidebar-toggle");
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebar-overlay");

    if(sidebarBtn){

        sidebarBtn.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            overlay.classList.toggle("active");
        });

        overlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            overlay.classList.remove("active");
        });

        document.querySelectorAll(".nav-item").forEach(item=>{
            item.addEventListener("click",()=>{
                if(window.innerWidth <= 768){
                    sidebar.classList.remove("open");
                    overlay.classList.remove("active");
                }
            });
        });
    }

});