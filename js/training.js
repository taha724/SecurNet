document.addEventListener("DOMContentLoaded", () => {
    const scenarios = [
        {
            type: "Email",
            text: "From: admin-support@university-portal.xyz\nSubject: Account Deactivation Notice\n\nDear student,\nYour university portal session will be terminated within 2 hours due to unauthorized login attempts. Confirm your student credentials immediately at http://bit.ly/student-reverify to restore full access.",
            isThreat: true,
            explanation: "Malicious: Uses a high-risk `.xyz` domain, artificial urgency, credential verification prompts, and a shortened `bit.ly` link to hide the real destination."
        },
        {
            type: "URL",
            text: "Target URL: https://portal.office.com/landing?auth=2",
            isThreat: false,
            explanation: "Safe: Belongs to Microsoft's genuine second-level domain `office.com` with a valid HTTPS certificate and no suspicious redirectors."
        },
        {
            type: "Email",
            text: "From: accounts-department@vendor.org\nSubject: Pending Settlement Invoice\n\nPlease find attached the remittance invoice for order #8841. Download payment_receipt.xlsm and enable macros to decrypt the document ledger.",
            isThreat: true,
            explanation: "Malicious: Delivery vector using a macro-enabled Excel sheet (`.xlsm`) and asking the user to disable security controls (enable macros)."
        }
    ];

    let currentIndex = 0;
    let totalScore = 0;
    let questionsAnswered = 0;

    const scenarioContent = document.getElementById("scenarioContent");
    const counterLabel = document.getElementById("challengeCounter");
    const scoreLabel = document.getElementById("scoreDisplay");
    const feedbackBox = document.getElementById("quizFeedback");
    const btnMalicious = document.getElementById("btnMalicious");
    const btnLegitimate = document.getElementById("btnLegitimate");
    const btnNext = document.getElementById("btnNext");

    function renderCurrentScenario() {
        const item = scenarios[currentIndex];
        if (!item) return;

        scenarioContent.textContent = item.text;
        counterLabel.textContent = `Scenario ${currentIndex + 1} of ${scenarios.length}`;
        feedbackBox.style.display = "none";
        btnNext.style.display = "none";

        btnMalicious.disabled = false;
        btnLegitimate.disabled = false;
        btnMalicious.className = "btn-option";
        btnLegitimate.className = "btn-option";
    }

    function checkAnswer(userChoiceThreat) {
        const item = scenarios[currentIndex];
        const isCorrect = userChoiceThreat === item.isThreat;

        questionsAnswered++;
        if (isCorrect) totalScore++;

        scoreLabel.textContent = `Score: ${totalScore} / ${questionsAnswered}`;

        btnMalicious.disabled = true;
        btnLegitimate.disabled = true;

        if (item.isThreat) {
            btnMalicious.classList.add("correct");
            if (!userChoiceThreat) btnLegitimate.classList.add("wrong");
        } else {
            btnLegitimate.classList.add("correct");
            if (userChoiceThreat) btnMalicious.classList.add("wrong");
        }

        feedbackBox.style.display = "block";
        feedbackBox.style.background = isCorrect ? "rgba(34, 197, 94, 0.15)" : "rgba(239, 68, 68, 0.15)";
        feedbackBox.style.border = isCorrect ? "1px solid #22c55e" : "1px solid #ef4444";
        feedbackBox.style.color = isCorrect ? "#4ade80" : "#f87171";
        feedbackBox.innerHTML = `<strong>${isCorrect ? "Correct Assessment!" : "Incorrect Assessment."}</strong> ${item.explanation}`;

        if (currentIndex < scenarios.length - 1) {
            btnNext.style.display = "inline-block";
        }
    }

    btnMalicious.addEventListener("click", () => checkAnswer(true));
    btnLegitimate.addEventListener("click", () => checkAnswer(false));
    btnNext.addEventListener("click", () => {
        currentIndex++;
        renderCurrentScenario();
    });

    renderCurrentScenario();
});