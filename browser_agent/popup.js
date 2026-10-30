document.addEventListener("DOMContentLoaded", async () => {
    const activeHostEl = document.getElementById("activeHost");
    const statusBadgeEl = document.getElementById("statusBadge");
    const riskMeterEl = document.getElementById("riskMeter");
    const riskScoreEl = document.getElementById("riskScore");
    const engineDotEl = document.getElementById("engineDot");
    const engineStatusEl = document.getElementById("engineStatus");
    const toastMsgEl = document.getElementById("toastMsg");
    const btnWhitelist = document.getElementById("btnWhitelist");
    const btnReport = document.getElementById("btnReport");
    const btnDashboard = document.getElementById("btnDashboard");
    const btnOptions = document.getElementById("btnOptions");

    let currentUrl = "";
    let currentDomain = "";

    function showToast(msg) {
        toastMsgEl.textContent = msg;
        setTimeout(() => { toastMsgEl.textContent = ""; }, 3000);
    }

    // 1. Get current active tab
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            currentUrl = tab.url;
            try {
                const u = new URL(tab.url);
                currentDomain = u.hostname;
                activeHostEl.textContent = currentDomain || "Bilinmeyen Sayfa";
            } catch(e) {
                activeHostEl.textContent = tab.url.substring(0, 30);
            }

            // 2. Query tab status from background
            chrome.runtime.sendMessage({ action: "getTabStatus", tabId: tab.id }, (res) => {
                const data = res?.result?.data;
                if (!data) {
                    statusBadgeEl.className = "status-badge badge-safe";
                    statusBadgeEl.textContent = "🛡️ Taranıyor / Güvenli";
                    riskMeterEl.style.width = "0%";
                    riskScoreEl.textContent = "0%";
                    return;
                }

                const score = Math.max(data.url_score || 0, data.text_score || 0);
                riskScoreEl.textContent = `${score}%`;
                riskMeterEl.style.width = `${score}%`;

                if (data.is_fake || data.action === "BLOCK") {
                    statusBadgeEl.className = "status-badge badge-danger";
                    statusBadgeEl.textContent = "🚫 Tehdit Engellendi";
                    riskMeterEl.className = "meter-fill danger";
                } else if (data.show_toast || data.action === "SUSPICIOUS") {
                    statusBadgeEl.className = "status-badge badge-warning";
                    statusBadgeEl.textContent = "⚠️ Şüpheli Bağlantı";
                    riskMeterEl.className = "meter-fill warning";
                } else {
                    statusBadgeEl.className = "status-badge badge-safe";
                    statusBadgeEl.textContent = "🛡️ Güvenli Sayfa";
                    riskMeterEl.className = "meter-fill";
                }
            });
        }
    } catch(err) {
        console.error("Popup yükleme hatası:", err);
    }

    // 3. Heartbeat check with backend AI engine
    fetch("http://127.0.0.1:8001/api/logs")
        .then(res => {
            if (res.ok) {
                engineDotEl.className = "dot";
                engineStatusEl.textContent = "Motor: Aktif (8001)";
            } else {
                engineDotEl.className = "dot offline";
                engineStatusEl.textContent = "Motor: Çevrimdışı";
            }
        })
        .catch(() => {
            engineDotEl.className = "dot offline";
            engineStatusEl.textContent = "Motor: Çevrimdışı";
        });

    // 4. Button Handlers
    btnWhitelist.addEventListener("click", () => {
        if (!currentDomain) return;
        chrome.runtime.sendMessage({ action: "addWhitelist", domain: currentDomain }, (res) => {
            if (res && res.status === "success") {
                showToast(`✓ ${currentDomain} beyaz listeye eklendi`);
            } else {
                showToast(res?.message || "Hata oluştu");
            }
        });
    });

    btnReport.addEventListener("click", () => {
        if (!currentUrl) return;
        chrome.runtime.sendMessage({ action: "reportPhish", url: currentUrl, reason: "Popup Kullanıcı Bildirimi" }, (res) => {
            if (res && res.status === "success") {
                showToast("✓ Tehdit istihbaratına bildirildi");
            } else {
                showToast(res?.message || "Bildirilemedi");
            }
        });
    });

    btnDashboard.addEventListener("click", () => {
        chrome.tabs.create({ url: "http://127.0.0.1:8001/dashboard" });
    });

    if (btnOptions) {
        btnOptions.addEventListener("click", () => {
            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
            } else {
                window.open(chrome.runtime.getURL("options.html"));
            }
        });
    }
});
