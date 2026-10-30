try {
    importScripts('antigravity_client_engine.js');
} catch (e) {
    console.warn("AntiGravity Client Engine could not be imported via importScripts:", e);
}

const tabSecurityStatus = {};
const DEFAULT_SERVER_URL = "http://127.0.0.1:8001";

const FREE_HOSTING_SUFFIXES = [
    "pages.dev", "firebaseapp.com", "vercel.app", "netlify.app",
    "ngrok.io", "ngrok-free.app", "github.io", "glitch.me", "000webhostapp.com",
    "wixsite.com", "weebly.com", "render.com", "railway.app", "fly.dev"
];

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

function evaluateEdgeZeroTrust(request) {
    try {
        const u = new URL(request.url);
        const host = u.hostname.toLowerCase();

        // 1. IDN Homograph / Punycode Trap
        if (host.includes("xn--")) {
            return {
                is_fake: true,
                is_hard_block: true,
                block: true,
                is_blocked: true,
                action: "BLOCK",
                status: "block",
                url_score: 100,
                details: `Edge Zero-Trust Koruması: '${host}' Uluslararası Karakter Sahtekarlığı (IDN/Punycode Homograph Saldırısı)!`,
                reason: `Edge Zero-Trust: '${host}' IDN Homograph Phishing`,
                mitre_tag: "T1566.002: Homograph Phishing"
            };
        }

        // 2. Cloud Host Credential Harvesting Trap
        if (request.has_password_field || request.has_credit_card_field) {
            const isFreeHost = FREE_HOSTING_SUFFIXES.some(suffix => host === suffix || host.endsWith("." + suffix));
            if (isFreeHost) {
                return {
                    is_fake: true,
                    is_hard_block: true,
                    block: true,
                    is_blocked: true,
                    action: "BLOCK",
                    status: "block",
                    url_score: 100,
                    details: `Edge Zero-Trust Koruması: '${host}' Ücretsiz bulut altyapısında yetkisiz şifre toplama formu engellendi!`,
                    reason: `Edge Zero-Trust: '${host}' Credential Harvesting on Cloud`,
                    mitre_tag: "T1056: Input Capture"
                };
            }
        }

        // 3. Raw IP Host with Password Trap
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) && (request.has_password_field || request.has_credit_card_field)) {
            return {
                is_fake: true,
                is_hard_block: true,
                block: true,
                is_blocked: true,
                action: "BLOCK",
                status: "block",
                url_score: 100,
                details: `Edge Zero-Trust Koruması: Doğrudan IP adresinde (${host}) şifre girişi tespit edildi!`,
                reason: `Edge Zero-Trust: Direct IP Credential Trap (${host})`,
                mitre_tag: "T1566.002: Direct IP Threat"
            };
        }
    } catch(e) {}
    return null;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // 1. Tehdit / Sayfa Analiz İstemi
    if (request.action === "analyze") {
        const tabId = sender?.tab?.id || "active";

        // Fast-path Edge Zero-Trust evaluation
        const edgeDecision = evaluateEdgeZeroTrust(request);
        if (edgeDecision) {
            tabSecurityStatus[tabId] = {
                url: request.url,
                data: edgeDecision,
                timestamp: Date.now()
            };
            sendResponse(edgeDecision);
            return true;
        }

        // Sub-millisecond Client AI Pre-evaluation (32-Feature Offline Model)
        let clientDecision = null;
        if (typeof AntiGravityClientEngine !== 'undefined') {
            try {
                clientDecision = AntiGravityClientEngine.predict(request.url);
                // If definitive zero-day threat with extreme confidence, edge block immediately
                if (clientDecision && clientDecision.is_fake && clientDecision.url_score >= 88) {
                    clientDecision.is_hard_block = true;
                    clientDecision.block = true;
                    tabSecurityStatus[tabId] = {
                        url: request.url,
                        data: clientDecision,
                        timestamp: Date.now()
                    };
                    sendResponse(clientDecision);
                    return true;
                }
            } catch (e) {
                console.debug("Client AI pre-check error:", e);
            }
        }

        // Full SOC Deep Inspection via Python AI Engine
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
                console.warn("AntiGravity Backend Offline. Offline 32-feature AI active:", error);
                const fallback = clientDecision || edgeDecision || {
                    is_fake: false,
                    details: "Sunucu çevrimdışı - Edge koruma devrede",
                    status: "offline"
                };
                tabSecurityStatus[tabId] = {
                    url: request.url,
                    data: fallback,
                    timestamp: Date.now()
                };
                sendResponse(fallback);
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
