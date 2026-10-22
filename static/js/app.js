/**
 * TLScope Frontend Application Script
 * Handles real-time scan initiation, progressive loading telemetry,
 * clipboard copy utilities, and history operations.
 */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scan-form");
    const targetInput = document.getElementById("target-input");
    const portInput = document.getElementById("port-input");
    const scanBtn = document.getElementById("scan-submit-btn");
    const loadingState = document.getElementById("scanner-loading");
    const errorAlert = document.getElementById("scanner-error-alert");
    const errorMessage = document.getElementById("scanner-error-message");

    // Quick fill domain pills
    const samplePills = document.querySelectorAll(".sample-domain-pill");
    samplePills.forEach(pill => {
        pill.addEventListener("click", (e) => {
            e.preventDefault();
            const domain = pill.getAttribute("data-domain");
            if (targetInput) {
                targetInput.value = domain;
                targetInput.focus();
            }
        });
    });

    // Form Submission
    if (scanForm) {
        scanForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const targetVal = targetInput.value.trim();
            if (!targetVal) {
                showError("Please enter a domain name or URL to analyze.");
                return;
            }

            hideError();
            setLoading(true);

            // Progressive step simulation for visual feedback during scan
            const steps = [
                { id: "step-1", delay: 100 },
                { id: "step-2", delay: 400 },
                { id: "step-3", delay: 900 },
                { id: "step-4", delay: 1400 },
                { id: "step-5", delay: 1900 },
            ];

            const stepTimers = steps.map(s => {
                return setTimeout(() => {
                    const el = document.getElementById(s.id);
                    if (el) {
                        el.classList.add("active");
                        const icon = el.querySelector("i");
                        if (icon) {
                            icon.className = "bi bi-arrow-repeat spin me-2 text-cyan-bright";
                        }
                    }
                }, s.delay);
            });

            try {
                const response = await fetch("/api/scan", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({
                        target: targetVal,
                        port: portInput ? portInput.value : 443
                    })
                });

                stepTimers.forEach(t => clearTimeout(t));

                const result = await response.json();

                if (!response.ok || !result.success) {
                    setLoading(false);
                    const msg = result.error || "An unexpected error occurred during TLS analysis.";
                    const category = result.category ? `[${result.category}] ` : "";
                    showError(category + msg);
                    return;
                }

                // Scan completed successfully -> Navigate to detailed results page
                if (result.redirect_url) {
                    window.location.href = result.redirect_url;
                }
            } catch (err) {
                stepTimers.forEach(t => clearTimeout(t));
                setLoading(false);
                showError("Network error: Could not contact TLScope backend service. Please verify the server is running.");
            }
        });
    }

    function setLoading(isLoading) {
        if (!loadingState || !scanBtn) return;
        if (isLoading) {
            loadingState.style.display = "block";
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2 text-cyan-bright"></span>Inspecting...';
        } else {
            loadingState.style.display = "none";
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="bi bi-lightning-charge-fill me-1"></i> Analyze';
        }
    }

    function showError(msg) {
        if (!errorAlert || !errorMessage) return;
        errorMessage.textContent = msg;
        errorAlert.classList.remove("d-none");
    }

    function hideError() {
        if (!errorAlert) return;
        errorAlert.classList.add("d-none");
    }

    // Clear History Action
    const clearHistoryBtn = document.getElementById("clear-history-btn");
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear all local scan history?")) {
                return;
            }
            try {
                const res = await fetch("/api/history/clear", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    window.location.reload();
                } else {
                    alert("Error clearing history: " + data.error);
                }
            } catch (err) {
                alert("Failed to communicate with database service.");
            }
        });
    }
});

// Copy to clipboard helper
function copyToClipboard(text, btnElement) {
    if (!navigator.clipboard) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
    } else {
        navigator.clipboard.writeText(text);
    }

    if (btnElement) {
        const originalHtml = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="bi bi-check2 text-success"></i> Copied';
        setTimeout(() => {
            btnElement.innerHTML = originalHtml;
        }, 1800);
    }
}
