document.addEventListener("DOMContentLoaded", async () => {
    // Session verification
    try {
        const response = await fetch("/api/me", {
            method: "GET",
            credentials: "include",
            headers: {
                "Accept": "application/json"
            }
        });

        if (!response.ok) {
            window.location.replace("login.html");
            return;
        }

        const data = await response.json();

        if (data.status !== "success" || !data.user) {
            window.location.replace("login.html");
            return;
        }

        // Populate user details in the dashboard header
        const user = data.user;
        const nameElement = document.getElementById("dashboardUserName");
        const avatarElement = document.getElementById("dashboardAvatar");

        if (nameElement && user.name) {
            nameElement.textContent = user.name;
        }

        if (avatarElement && user.name) {
            avatarElement.textContent = user.name.charAt(0).toUpperCase();
        }

    } catch (err) {
        console.error("Session verification fetch error:", err);
        window.location.replace("login.html");
        return;
    }

    // Load dynamic scan statistics and recent activity
    await loadDashboardStats();

    // Attach logout click listener
    const logoutLinks = document.querySelectorAll('a[href="index.html"]');
    logoutLinks.forEach(link => {
        if (link.textContent.includes("Logout")) {
            link.addEventListener("click", async (e) => {
                e.preventDefault();
                try {
                    await fetch("/api/logout", {
                        method: "POST",
                        credentials: "include"
                    });
                } catch (logoutErr) {
                    console.error("Logout request failed:", logoutErr);
                } finally {
                    window.location.href = "login.html";
                }
            });
        }
    });

    // Mobile sidebar toggle
    const menuToggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }
});

async function loadDashboardStats() {
    try {
        const response = await fetch("/api/dashboard-stats", {
            method: "GET",
            credentials: "include",
            headers: {
                "Accept": "application/json"
            }
        });

        if (!response.ok) return;

        const data = await response.json();

        // Update counter cards
        const totalElem = document.getElementById("statTotalScans");
        const safeElem = document.getElementById("statSafeScans");
        const threatsElem = document.getElementById("statThreatsDetected");
        const protectionScoreElem = document.getElementById("statProtectionScore");

        if (totalElem) totalElem.textContent = data.total_scans;
        if (safeElem) safeElem.textContent = data.safe_scans;
        if (threatsElem) threatsElem.textContent = data.threats_detected;

        // Calculate dynamic protection health score
        if (protectionScoreElem) {
            if (data.total_scans === 0) {
                protectionScoreElem.textContent = "100%";
            } else {
                const healthPercentage = Math.round((data.safe_scans / data.total_scans) * 100);
                protectionScoreElem.textContent = `${healthPercentage}%`;
            }
        }

        // Render recent activity rows
        const activityTableBody = document.getElementById("recentScansTableBody");
        if (activityTableBody && data.recent_scans) {
            activityTableBody.innerHTML = "";
            if (data.recent_scans.length === 0) {
                activityTableBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="empty-state">
                            No scan activity yet. Start your first scan!
                        </td>
                    </tr>`;
            } else {
                data.recent_scans.forEach(item => {
                    const tr = document.createElement("tr");

                    let badgeClass = "badge-low";
                    if (item.score >= 70) {
                        badgeClass = "badge-critical";
                    } else if (item.score >= 35) {
                        badgeClass = "badge-moderate";
                    }

                    tr.innerHTML = `
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.target}">${item.target}</td>
                        <td>${item.type}</td>
                        <td><span class="threat-type-badge ${badgeClass}">${item.result}</span></td>
                        <td style="color: #94a3b8; font-size: 13px;">${item.date}</td>
                    `;
                    activityTableBody.appendChild(tr);
                });
            }
        }
    } catch (err) {
        console.error("Failed to load dashboard metrics:", err);
    }
}