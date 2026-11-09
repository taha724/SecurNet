document.addEventListener("DOMContentLoaded", () => {
    const scanBtn = document.getElementById("scanUrlBtn");
    const urlInput = document.getElementById("urlInput");

    const resultBox = document.getElementById("urlResultBox");
    const verdictBadge = document.getElementById("urlVerdictBadge");
    const severityLabel = document.getElementById("urlSeverityLabel");
    const scoreText = document.getElementById("urlScoreText");
    const scoreBar = document.getElementById("urlScoreBar");
    const domainLabel = document.getElementById("parsedDomainLabel");
    const flagsList = document.getElementById("urlFlagsList");

    if (!scanBtn) return;

    scanBtn.addEventListener("click", async () => {
        const rawUrl = urlInput ? urlInput.value.trim() : "";

        if (!rawUrl) {
            alert("Please enter a URL or domain to scan.");
            return;
        }

        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning Target...";

        try {
            const response = await fetch("/api/scan-url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                credentials: "include",
                body: JSON.stringify({ url: rawUrl })
            });

            const data = await response.json();

            if (!response.ok) {
                alert(data.message || "Failed to scan URL.");
                return;
            }

            if (resultBox) resultBox.style.display = "block";

            // Verdict Badge
            if (verdictBadge) {
                verdictBadge.textContent = data.verdict || "Unknown";
                verdictBadge.className = "threat-type-badge";
                if (data.severity === "Critical") {
                    verdictBadge.classList.add("badge-critical");
                } else if (data.severity === "Moderate") {
                    verdictBadge.classList.add("badge-moderate");
                } else {
                    verdictBadge.classList.add("badge-low");
                }
            }

            // Severity text
            if (severityLabel) {
                if (data.severity === "Critical") {
                    severityLabel.textContent = "Critical Risk";
                    severityLabel.style.color = "#ef4444";
                } else if (data.severity === "Moderate") {
                    severityLabel.textContent = "Moderate Risk";
                    severityLabel.style.color = "#f59e0b";
                } else {
                    severityLabel.textContent = "Safe / Low Risk";
                    severityLabel.style.color = "#22c55e";
                }
            }

            // Score meter
            if (scoreText) scoreText.textContent = (data.score || 0) + "%";
            if (scoreBar) {
                scoreBar.style.width = (data.score || 0) + "%";
                scoreBar.style.backgroundColor =
                    data.severity === "Critical" ? "#ef4444" :
                    data.severity === "Moderate" ? "#f59e0b" : "#22c55e";
            }

            // Parsed domain
            if (domainLabel) {
                domainLabel.textContent = data.domain ? `Analyzed Host: ${data.domain}` : "";
            }

            // Indicator flags
            if (flagsList && Array.isArray(data.flags)) {
                flagsList.innerHTML = "";
                data.flags.forEach(flag => {
                    const li = document.createElement("li");
                    li.textContent = flag;
                    flagsList.appendChild(li);
                });
            }

            if (resultBox) resultBox.scrollIntoView({ behavior: "smooth" });

        } catch (err) {
            console.error("URL scan request error:", err);
            alert("An error occurred during URL scan.");
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = "Scan URL";
        }
    });
});