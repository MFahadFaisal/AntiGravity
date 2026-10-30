chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // 1. Tehdit / Sayfa Analiz İstemi
    if (request.action === "analyze") {
        fetch("http://127.0.0.1:8001/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: request.url,
                page_text: request.page_text,
                html_source: request.html_source
            })
        })
        .then(response => response.json())
        .then(data => {
            sendResponse(data);
        })
        .catch(error => {
            console.error("AntiGravity AI Engine Bağlantı Hatası:", error);
            sendResponse({ is_fake: false, details: "Sunucuya ulaşılamadı" });
        });

        return true; // Asenkron yanıt için kesinlikle gerekli
    }

    // 2. Chrome Masaüstü Bildirim Servisi
    if (request.action === "showNotification") {
        chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png", // Varsa uzantı klasöründeki ikon
            title: "🛡️ Adli Güvenlik Uyarısı",
            message: request.message || "Zararlı veya şüpheli bir bağlantı engellendi!"
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.log("Bildirim oluşturulamadı:", chrome.runtime.lastError.message);
            }
        });
        sendResponse({ status: "success" });
    }
});