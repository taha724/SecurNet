// ==========================================
// SecureNet Authentication System
// Flask Backend Integration
// ==========================================

// ------------------------------------------
// Message Display
// ------------------------------------------

function showMessage(message, success = false) {
    const element = document.getElementById("formMessage");

    if (!element) return;

    element.textContent = message;
    element.style.color = success ? "#22c55e" : "#ff5c5c";
}

// ------------------------------------------
// Password Visibility
// ------------------------------------------

document.querySelectorAll(".toggle-password").forEach(button => {
    button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.target);

        if (!input) return;

        const hidden = input.type === "password";

        input.type = hidden ? "text" : "password";
        button.textContent = hidden ? "Hide" : "Show";
    });
});

// ------------------------------------------
// Backend API Request
// ------------------------------------------

async function apiRequest(endpoint, data) {
    const response = await fetch(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include", // Allows session cookies to be stored
        body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
        throw new Error(result.message || "Something went wrong.");
    }

    return result;
}

// ------------------------------------------
// Registration
// ------------------------------------------

const registerForm = document.getElementById("registerForm");

if (registerForm) {
    registerForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim().toLowerCase();
        const password = document.getElementById("password").value;
        const confirmPassword = document.getElementById("confirmPassword").value;
        const terms = document.getElementById("terms").checked;

        if (!name || !email || !password || !confirmPassword) {
            showMessage("Please fill in all fields.");
            return;
        }

        if (password.length < 8) {
            showMessage("Password must contain at least 8 characters.");
            return;
        }

        if (password !== confirmPassword) {
            showMessage("Passwords do not match.");
            return;
        }

        if (!terms) {
            showMessage("Please accept the Terms and Privacy Policy.");
            return;
        }

        const submitButton = registerForm.querySelector('[type="submit"]');

        if (submitButton) submitButton.disabled = true;

        try {
            const result = await apiRequest("/api/register", {
                name,
                email,
                password
            });

            showMessage(result.message, true);
            registerForm.reset();

            setTimeout(() => {
                window.location.href = "login.html";
            }, 1200);

        } catch (error) {
            showMessage(error.message);
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });
}

// ------------------------------------------
// Standard Form Login
// ------------------------------------------

const loginForm = document.getElementById("loginForm");

if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const email = document.getElementById("email").value.trim().toLowerCase();
        const password = document.getElementById("password").value;
        const remember = document.getElementById("remember")?.checked;

        if (!email || !password) {
            showMessage("Please enter your email and password.");
            return;
        }

        const submitButton = loginForm.querySelector('[type="submit"]');

        if (submitButton) submitButton.disabled = true;

        try {
            const result = await apiRequest("/api/login", {
                email,
                password,
                remember
            });

            showMessage("Login successful! Opening dashboard...", true);

            setTimeout(() => {
                window.location.href = "dashboard.html";
            }, 800);

        } catch (error) {
            showMessage(error.message);
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });
}

// ------------------------------------------
// Google OAuth Sign-In Handler
// ------------------------------------------

window.handleGoogleCredentialResponse = async function (response) {
    if (!response || !response.credential) {
        showMessage("Failed to retrieve Google credentials.");
        return;
    }

    try {
        showMessage("Signing in with Google...", true);

        const result = await apiRequest("/api/google-login", {
            credential: response.credential
        });

        showMessage("Google login successful! Opening dashboard...", true);

        // Buffer allows the browser storage engine to persist the session cookie
        setTimeout(() => {
            window.location.href = "dashboard.html";
        }, 1000);

    } catch (error) {
        console.error("Backend error:", error);
        showMessage(error.message || "Google sign-in failed.");
    }
};

// Directly called by the Google script onload attribute
window.renderGoogleButton = function () {
    if (window.google && google.accounts && google.accounts.id) {
        google.accounts.id.initialize({
            client_id: "719826006412-gls5t8vu33i832btarvdbijrv4qjkfd3.apps.googleusercontent.com",
            callback: window.handleGoogleCredentialResponse,
            context: "signin",
            ux_mode: "popup",
            auto_select: false
        });

        const btnContainer = document.getElementById("googleButtonContainer");
        if (btnContainer) {
            google.accounts.id.renderButton(btnContainer, {
                type: "standard",
                shape: "rectangular",
                theme: "outline",
                text: "signin_with",
                size: "large",
                logo_alignment: "left"
            });
        }
    }
};

// Fallback execution if Google's script finished loading prior to auth.js
if (window.google && google.accounts && google.accounts.id) {
    window.renderGoogleButton();
}