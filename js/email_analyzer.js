document.addEventListener("DOMContentLoaded", () => {
    const analyzeBtn = document.getElementById("analyzeBtn");
    const subjectInput = document.getElementById("emailSubject");
    const bodyInput = document.getElementById("emailBody");

    const resultBox = document.getElementById("resultBox");
    const threatTypeBadge = document.getElementById("threatTypeBadge");
    const severityLabel = document.getElementById("severityLabel");
    const likelihoodText = document.getElementById("likelihoodText");
    const likelihoodBar = document.getElementById("likelihoodBar");
    const breakdownGrid = document.getElementById("breakdownGrid");
    const flagsList = document.getElementById("flagsList");
    const mlPredictionNote = document.getElementById("mlPredictionNote");

    if (!analyzeBtn) return;

    analyzeBtn.addEventListener("click", async () => {
        const subject = subjectInput ? subjectInput.value.trim() : "";
        const body = bodyInput ? bodyInput.value.trim() : "";

        if (!subject && !body) {
            alert("Please provide an email subject or body text to analyze.");
            return;
        }

        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "Analyzing Threat...";

        try {
            const response = await fetch("/api/analyze-email", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                credentials: "include",
                body: JSON.stringify({ subject, body })
            });

            const data = await response.json();

            if (!response.ok) {
                alert(data.message || "Failed to analyze email.");
                return;
            }

            // Display results container
            if (resultBox) resultBox.style.display = "block";

            // Update classification & severity
            if (threatTypeBadge) {
                threatTypeBadge.textContent = data.threat_type || "Unknown";
                threatTypeBadge.className = "threat-type-badge";
                if (data.severity === "Critical") {
                    threatTypeBadge.classList.add("badge-critical");
                } else if (data.severity === "Moderate") {
                    threatTypeBadge.classList.add("badge-moderate");
                } else {
                    threatTypeBadge.classList.add("badge-low");
                }
            }

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

            // Update likelihood percentage & bar
            if (likelihoodText) likelihoodText.textContent = (data.threat_likelihood || 0) + "%";
            if (likelihoodBar) {
                likelihoodBar.style.width = (data.threat_likelihood || 0) + "%";
                likelihoodBar.style.backgroundColor = 
                    data.severity === "Critical" ? "#ef4444" : 
                    data.severity === "Moderate" ? "#f59e0b" : "#22c55e";
            }

            // Update ML note
            if (mlPredictionNote) {
                mlPredictionNote.textContent = data.ml_result ? `AI Model Prediction: ${data.ml_result}` : "";
            }

            // Populate category breakdown grid
            if (breakdownGrid) {
                breakdownGrid.innerHTML = "";
                if (data.breakdown) {
                    for (const [catName, score] of Object.entries(data.breakdown)) {
                        const card = document.createElement("div");
                        card.className = "breakdown-item";
                        card.innerHTML = `
                            <span>${catName}</span>
                            <strong>${score}% Match</strong>
                        `;
                        breakdownGrid.appendChild(card);
                    }
                }
            }

            // Populate flags
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
            console.error("Analysis request error:", err);
            alert("An error occurred during email analysis.");
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Analyze Threat";
        }
    });
});