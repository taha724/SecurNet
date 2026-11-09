document.addEventListener("DOMContentLoaded", () => {
    const tableBody = document.getElementById("reportsTableBody");
    const filterType = document.getElementById("filterType");
    const filterSeverity = document.getElementById("filterSeverity");
    const exportBtn = document.getElementById("exportCsvBtn");

    let currentReports = [];

    async function fetchReports() {
        const typeVal = filterType ? filterType.value : "all";
        const sevVal = filterSeverity ? filterSeverity.value : "all";

        try {
            const res = await fetch(`/api/reports?type=${typeVal}&severity=${sevVal}`, {
                credentials: "include"
            });
            const data = await res.json();

            if (!res.ok || data.status !== "success") return;

            currentReports = data.reports || [];
            renderTable(currentReports);
        } catch (err) {
            console.error("Failed to load reports:", err);
        }
    }

    function renderTable(reports) {
        if (!tableBody) return;
        tableBody.innerHTML = "";

        if (reports.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No matching security scans recorded.</td></tr>`;
            return;
        }

        reports.forEach(r => {
            const tr = document.createElement("tr");

            let badgeClass = "badge-low";
            if (r.severity === "Critical") badgeClass = "badge-critical";
            else if (r.severity === "Moderate") badgeClass = "badge-moderate";

            tr.innerHTML = `
                <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.target}">
                    ${r.target}
                </td>
                <td>${r.type}</td>
                <td><span class="threat-type-badge ${badgeClass}">${r.result}</span></td>
                <td><strong>${r.score}%</strong></td>
                <td style="color: #94a3b8; font-size: 13px;">${r.date}</td>
            `;
            tableBody.appendChild(tr);
        });
    }

    function exportToCSV() {
        if (!currentReports.length) {
            alert("No logs available to export.");
            return;
        }

        const headers = ["ID", "Target", "Vector Type", "Threat Verdict", "Score", "Severity", "Timestamp"];
        const rows = currentReports.map(r => [
            r.id,
            `"${r.target.replace(/"/g, '""')}"`,
            r.type,
            `"${r.result}"`,
            `${r.score}%`,
            r.severity,
            `"${r.date}"`
        ]);

        const csvContent = [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", `SecureNet_Security_Audit_Report_${new Date().toISOString().slice(0, 10)}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    if (filterType) filterType.addEventListener("change", fetchReports);
    if (filterSeverity) filterSeverity.addEventListener("change", fetchReports);
    if (exportBtn) exportBtn.addEventListener("click", exportToCSV);

    fetchReports();
});