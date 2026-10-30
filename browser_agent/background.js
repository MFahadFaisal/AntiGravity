const tabSecurityStatus = {};
const DEFAULT_SERVER_URL = "http://127.0.0.1:8001";

function getServerUrl() {
    return new Promise((resolve) => {
        if (chrome.storage && chrome.storage.sync) {
            chrome.storage.sync.get(["serverUrl"], (res) => {
                resolve((res && res.serverUrl) ? res.serverUrl.replace(/\/+$/, "") : DEFAULT_SERVER_URL);
            });
        } else {
            resolve(DEFAULT_SERVER_URL);
        }
    });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // 1. Tehdit / Sayfa Analiz İstemi
    if (request.action === "analyze") {
        const tabId = sender?.tab?.id || "active";
        getServerUrl().then((serverUrl) => {
            fetch(`${serverUrl}/analyze`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: request.url,
                    page_text: request.page_text,
                    html_source: request.html_source,
                    has_password_field: Boolean(request.has_password_field),
                    has_credit_card_field: Boolean(request.has_credit_card_field),
                    favicon_url: request.favicon_url || ""
                })
            })
            .then(response => response.json())
            .then(data => {
                tabSecurityStatus[tabId] = {
                    url: request.url,
                    data: data,
                    timestamp: Date.now()
                };
                sendResponse(data);
            })
            .catch(error => {
                console.error("AntiGravity AI Engine Bağlantı Hatası:", error);
                sendResponse({ is_fake: false, details: "Sunucuya ulaşılamadı", status: "offline" });
            });
        });

        return true; // Asenkron yanıt için kesinlikle gerekli
    }

    // 2. Chrome Masaüstü Bildirim Servisi
    if (request.action === "showNotification") {
        if (chrome.storage && chrome.storage.sync) {
            chrome.storage.sync.get(["notificationsEnabled"], (res) => {
                if (res && res.notificationsEnabled === false) {
                    sendResponse({ status: "skipped_notifications_disabled" });
                    return;
                }
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "🛡️ AntiGravity Adli Güvenlik Uyarısı",
                    message: request.message || "Zararlı veya şüpheli bir bağlantı engellendi!"
                }, (notificationId) => {
                    if (chrome.runtime.lastError) {
                        console.log("Bildirim oluşturulamadı:", chrome.runtime.lastError.message);
                    }
                });
                sendResponse({ status: "success" });
            });
            return true;
        }

        chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "🛡️ AntiGravity Adli Güvenlik Uyarısı",
            message: request.message || "Zararlı veya şüpheli bir bağlantı engellendi!"
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.log("Bildirim oluşturulamadı:", chrome.runtime.lastError.message);
            }
        });
        sendResponse({ status: "success" });
        return true;
    }

    // 3. Popup Arayüzü için Aktif Sekme Durumu
    if (request.action === "getTabStatus") {
        const tabId = request.tabId || "active";
        const result = tabSecurityStatus[tabId] || tabSecurityStatus["active"] || null;
        sendResponse({ status: "success", result });
        return true;
    }

    // 4. Şüpheli URL Bildirimi (Report Phishing)
    if (request.action === "reportPhish") {
        getServerUrl().then((serverUrl) => {
            fetch(`${serverUrl}/api/report-phish`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: request.url, reason: request.reason || "Kullanıcı Bildirimi" })
            })
            .then(res => res.json())
            .then(data => sendResponse(data))
            .catch(err => sendResponse({ status: "error", message: "Sunucuya bağlanılamadı" }));
        });
        return true;
    }

    // 5. Hızlı Beyaz Liste Ekleme
    if (request.action === "addWhitelist") {
        getServerUrl().then((serverUrl) => {
            fetch(`${serverUrl}/api/whitelist/add`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: request.domain })
            })
            .then(res => res.json())
            .then(data => sendResponse(data))
            .catch(err => sendResponse({ status: "error", message: "Sunucuya bağlanılamadı" }));
        });
        return true;
    }
});
