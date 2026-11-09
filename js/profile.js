
document.addEventListener("DOMContentLoaded", function () {

    const SESSION_KEY = "secureNetUser";
    const USERS_KEY = "secureNetUsers";
    const HISTORY_KEY = "secureNetHistory";

    const form = document.getElementById("profileForm");
    const editButton = document.getElementById("editButton");
    const cancelButton = document.getElementById("cancelButton");
    const formActions = document.getElementById("formActions");

    let user = null;
    let storage = null;

    // Get the currently logged-in user.
    function getCurrentUser() {
        try {
            const sessionUser = sessionStorage.getItem(SESSION_KEY);

            if (sessionUser) {
                storage = sessionStorage;
                return JSON.parse(sessionUser);
            }

            const localUser = localStorage.getItem(SESSION_KEY);

            if (localUser) {
                storage = localStorage;
                return JSON.parse(localUser);
            }

            return null;

        } catch (error) {
            return null;
        }
    }

    // Load user information.
    function loadUser() {

        user = getCurrentUser();

        if (!user) {
            window.location.href = "login.html";
            return;
        }

        document.getElementById("fullName").value = user.name || "";
        document.getElementById("email").value = user.email || "";
        document.getElementById("phone").value = user.phone || "";
        document.getElementById("createdAt").value =
            user.createdAt || "Not available";

        document.getElementById("profileName").textContent =
            user.name || "User";

        document.getElementById("profileEmail").textContent =
            user.email || "Email not available";

        document.getElementById("profileAvatar").textContent =
            (user.name || "U").charAt(0).toUpperCase();
    }

    // Enable or disable editing.
    function setEditing(enabled) {

        document.getElementById("fullName").disabled = !enabled;
        document.getElementById("phone").disabled = !enabled;
        document.getElementById("email").disabled = true;

        formActions.style.display = enabled ? "flex" : "none";
        editButton.style.display = enabled ? "none" : "block";
    }

    // Edit button.
    editButton.addEventListener("click", function () {
        setEditing(true);
    });

    // Cancel button.
    cancelButton.addEventListener("click", function () {
        loadUser();
        setEditing(false);
    });

    // Save updated profile.
    form.addEventListener("submit", function (event) {

        event.preventDefault();

        const updatedName =
            document.getElementById("fullName").value.trim();

        const updatedPhone =
            document.getElementById("phone").value.trim();

        if (!updatedName) {
            alert("Please enter your full name.");
            return;
        }

        user.name = updatedName;
        user.phone = updatedPhone;

        // Update the active login session.
        storage.setItem(SESSION_KEY, JSON.stringify(user));

        // Update the registered account record.
        try {
            const users = JSON.parse(
                localStorage.getItem(USERS_KEY)
            ) || [];

            const index = users.findIndex(
                account => account.id === user.id
            );

            if (index !== -1) {
                users[index].name = user.name;
                users[index].phone = user.phone;

                localStorage.setItem(
                    USERS_KEY,
                    JSON.stringify(users)
                );
            }

        } catch (error) {
            console.error("Could not update account record:", error);
        }

        loadUser();
        setEditing(false);

        alert("Profile updated successfully!");
    });

    // Load security activity.
    function loadActivity() {

        let history = [];

        try {
            history = JSON.parse(
                localStorage.getItem(HISTORY_KEY)
            ) || [];
        } catch (error) {
            history = [];
        }

        const safe = history.filter(
            item => item.result === "Safe"
        ).length;

        const threats = history.filter(
            item => item.result === "Threat"
        ).length;

        document.getElementById("totalScans").textContent =
            history.length;

        document.getElementById("safeScans").textContent = safe;

        document.getElementById("threatScans").textContent = threats;
    }

    loadUser();

    if (user) {
        loadActivity();
    }

});