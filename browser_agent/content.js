window.addEventListener("load", () => {
    // Uzantı bağlamı geçersiz kılındıysa hatayı önlemek için kontrol et
    if (!chrome.runtime?.id) return;

    const currentUrl = window.location.href;
    const pageText = document.body ? document.body.innerText.substring(0, 1500) : "";
    const htmlSource = document.documentElement ? document.documentElement.outerHTML.substring(0, 100000) : "";

    if (currentUrl.includes("127.0.0.1:8001") || currentUrl.startsWith("chrome-extension://")) return;

    // Zero-Day Trap: Sayfadaki kimlik avı formları ve kart giriş alanlarını tara
    const hasPassword = document.querySelector('input[type="password"]') !== null;
    const hasCreditCard = document.querySelector('input[autocomplete*="cc"], input[name*="card"], input[name*="cvv"], input[name*="cvc"], input[id*="card"]') !== null;

    // Visual Spoofing Trap: Favicon URL tespiti
    const faviconEl = document.querySelector('link[rel*="icon"]');
    let faviconUrl = "";
    try {
        if (faviconEl && faviconEl.href) {
            faviconUrl = faviconEl.href;
        } else if (window.location.origin && window.location.origin.startsWith("http")) {
            faviconUrl = window.location.origin + "/favicon.ico";
        }
    } catch(e) {
        faviconUrl = "";
    }

    // DOM Gözlemcisi: Sayfaya sonradan dinamik eklenen şüpheli iframe veya scriptleri engeller
    try {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach((node) => {
                        if (node.tagName === "IFRAME" || node.tagName === "SCRIPT") {
                            if (node.src && (node.src.includes("ads") || node.src.includes("malicious"))) {
                                console.warn("[AntiGravity] Dinamik şüpheli öge engellendi:", node.src);
                                node.remove();
                            }
                        }
                    });
                }
            });
        });
        if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
        }
    } catch (e) {
        console.error("Observer hatası:", e);
    }

    try {
        chrome.runtime.sendMessage(
            { 
                action: "analyze", 
                url: currentUrl, 
                page_text: pageText,
                html_source: htmlSource,
                has_password_field: hasPassword,
                has_credit_card_field: hasCreditCard,
                favicon_url: faviconUrl
            },
            (response) => {
                if (chrome.runtime.lastError || !response) return;

                // 1. ŞÜPHELİ DURUM: Kalkan inmez, sağ alttan bildirim çıkar
                if (response.show_toast || response.action === "SUSPICIOUS" || response.status === "suspicious") {
                    showAntiGravityToast(response.details || response.reason || "Şüpheli içerik tespit edildi.");
                    enableSpecificLinkInterception(); // Arama sonuçlarındaki linkleri tıklamaya karşı denetle
                    return;
                }

                // 2. KESİN ENGEL DURUMU: Cinsel içerik veya zararlı siteler
                if (response.is_fake) {
                    try {
                        chrome.runtime.sendMessage({
                            action: "showNotification",
                            message: `Zararlı bağlantı engellendi: ${currentUrl}`
                        });
                    } catch(e) {}

                    if (response.is_hard_block) {
                        showAntiGravityOverlay(currentUrl, response.details, true);
                    } else {
                        enableSpecificLinkInterception();
                    }
                }
            }
        );
    } catch (err) {
        console.log("AntiGravity bağlam hatası yakalandı:", err);
    }
});

let linkInterceptionActive = false;

function enableSpecificLinkInterception() {
    if (linkInterceptionActive) return;
    linkInterceptionActive = true;

    document.addEventListener("click", (event) => {
        if (!chrome.runtime?.id) return;
        if (event.target && event.target.id === "antigravity-shield") return;

        const target = event.target && event.target.closest ? event.target.closest("a") : null;
        if (!target || !target.href || typeof target.href !== "string") return;

        const clickedUrl = target.href;
        if (clickedUrl.startsWith("chrome-extension://") || clickedUrl.includes("127.0.0.1:8001")) return;

        if (!/^https?:/i.test(clickedUrl)) return;
        if (clickedUrl.split("#")[0] === window.location.href.split("#")[0]) return;

        event.preventDefault();
        event.stopPropagation();

        const openInNewTab = target.target === "_blank" || event.ctrlKey || event.metaKey || event.shiftKey;
        const proceed = () => {
            if (openInNewTab) {
                window.open(clickedUrl, "_blank", "noopener");
            } else {
                window.location.href = clickedUrl;
            }
        };

        try {
            chrome.runtime.sendMessage(
                {
                    action: "analyze",
                    url: clickedUrl,
                    page_text: target.innerText || "",
                    html_source: "<div>Tıklanan Link Analizi</div>"
                },
                (response) => {
                    if (chrome.runtime.lastError || !response) {
                        proceed();
                        return;
                    }

                    if (response.show_toast || response.action === "SUSPICIOUS" || response.status === "suspicious") {
                        showAntiGravityToast(response.details || "Tıklanan bağlantı şüpheli olarak değerlendirildi.");
                        proceed();
                    } else if (response.is_fake) {
                        try {
                            chrome.runtime.sendMessage({
                                action: "showNotification",
                                message: `Şüpheli link engellendi: ${clickedUrl}`
                            });
                        } catch(e) {}

                        showAntiGravityOverlay(clickedUrl, response.details, false);
                    } else {
                        proceed();
                    }
                }
            );
        } catch (err) {
            proceed();
        }
    }, true);
}

// ------------------------------------------------------------------
// SAĞ ALT BİLDİRİM EKRANI (TOAST NOTIFICATION)
// ------------------------------------------------------------------
function showAntiGravityToast(message) {
    const oldToast = document.getElementById("antigravity-toast");
    if (oldToast) oldToast.remove();

    const toast = document.createElement("div");
    toast.id = "antigravity-toast";
    toast.style.cssText = `
        position: fixed !important;
        bottom: 25px !important;
        right: 25px !important;
        z-index: 2147483647 !important;
        background: #1e1e2d !important;
        border-left: 5px solid #f39c12 !important;
        color: #ffffff !important;
        padding: 14px 18px !important;
        border-radius: 10px !important;
        box-shadow: 0 10px 30px rgba(0,0,0,0.6) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 13px !important;
        max-width: 360px !important;
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        transition: all 0.4s ease-in-out !important;
    `;

    toast.innerHTML = `
        <div style="font-size: 22px; line-height: 1;">⚠️</div>
        <div>
            <strong style="display:block; color: #f39c12; font-size: 14px; margin-bottom: 2px;">AntiGravity Uyarısı</strong>
            <span style="color: #cccccc; font-size: 12px; line-height: 1.4; display: block;">${message}</span>
        </div>
    `;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(10px)";
        setTimeout(() => toast.remove(), 400);
    }, 6000);
}

// ------------------------------------------------------------------
// TAM EKRAN ENGELLEME PERDESİ (SHADOW DOM OVERLAY)
// ------------------------------------------------------------------
function showAntiGravityOverlay(blockedUrl, blockReason, isHardBlock = false) {
    if (document.getElementById("antigravity-shield")) return;

    let cleanUrl = blockedUrl;
    try {
        const parsedObj = new URL(blockedUrl);
        cleanUrl = parsedObj.origin + parsedObj.pathname;
        if (cleanUrl.length > 60) cleanUrl = cleanUrl.substring(0, 57) + "...";
    } catch(e) {}

    const host = document.createElement("div");
    host.id = "antigravity-shield";
    host.style.cssText = "all: initial; position: fixed; inset: 0; z-index: 2147483647;";
    const shadow = host.attachShadow({ mode: "closed" });

    shadow.innerHTML = `
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }

            .overlay {
                position: fixed;
                inset: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 24px;
                overflow-y: auto;
                font-family: 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif;
                color: #fff;
                background:
                    radial-gradient(circle at 20% 15%, rgba(239, 68, 68, 0.35), transparent 45%),
                    radial-gradient(circle at 80% 85%, rgba(249, 115, 22, 0.25), transparent 45%),
                    linear-gradient(135deg, #1a0b0b 0%, #2b0d12 50%, #12060a 100%);
                backdrop-filter: blur(14px);
                -webkit-backdrop-filter: blur(14px);
                animation: fadeIn 0.5s ease-out;
            }

            .grid {
                position: absolute;
                inset: 0;
                background-image:
                    linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px);
                background-size: 48px 48px;
                mask-image: radial-gradient(circle at center, #000 30%, transparent 75%);
                -webkit-mask-image: radial-gradient(circle at center, #000 30%, transparent 75%);
                pointer-events: none;
            }

            .card {
                position: relative;
                width: 100%;
                max-width: 620px;
                padding: 48px 40px 40px;
                text-align: center;
                background: rgba(255, 255, 255, 0.06);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 24px;
                box-shadow: 0 30px 80px rgba(0, 0, 0, 0.55),
                            0 0 0 1px rgba(239, 68, 68, 0.15),
                            inset 0 1px 0 rgba(255, 255, 255, 0.12);
                animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
            }

            .icon-wrap {
                position: relative;
                width: 112px;
                height: 112px;
                margin: 0 auto 28px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .icon-wrap::before,
            .icon-wrap::after {
                content: "";
                position: absolute;
                inset: 0;
                border-radius: 50%;
                border: 2px solid rgba(239, 68, 68, 0.6);
                animation: pulse 2.2s ease-out infinite;
            }
            .icon-wrap::after { animation-delay: 1.1s; }

            .icon-circle {
                position: relative;
                width: 96px;
                height: 96px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, #ef4444, #b91c1c);
                box-shadow: 0 10px 30px rgba(239, 68, 68, 0.5);
            }

            .badge {
                display: inline-block;
                margin-bottom: 16px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                color: #fecaca;
                background: rgba(239, 68, 68, 0.18);
                border: 1px solid rgba(239, 68, 68, 0.4);
                border-radius: 999px;
            }

            h1 {
                font-size: 38px;
                font-weight: 800;
                line-height: 1.15;
                margin-bottom: 8px;
                letter-spacing: -0.02em;
            }

            h2 {
                font-size: 17px;
                font-weight: 500;
                color: #fca5a5;
                margin-bottom: 26px;
            }

            .url-box {
                display: flex;
                align-items: center;
                gap: 10px;
                margin: 0 auto 14px;
                padding: 12px 16px;
                text-align: left;
                background: rgba(0, 0, 0, 0.35);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
                font-size: 13px;
                color: #fecaca;
            }
            .url-box svg { flex-shrink: 0; }
            .url-text {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            .reason-box {
                display: flex;
                align-items: flex-start;
                gap: 14px;
                margin-bottom: 32px;
                padding: 16px 18px;
                text-align: left;
                background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(249, 115, 22, 0.12));
                border: 1px solid rgba(239, 68, 68, 0.45);
                border-left: 4px solid #ef4444;
                border-radius: 12px;
            }
            .reason-icon {
                flex-shrink: 0;
                width: 36px;
                height: 36px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(239, 68, 68, 0.25);
                border-radius: 10px;
            }
            .reason-label {
                display: block;
                margin-bottom: 4px;
                font-size: 11.5px;
                font-weight: 700;
                letter-spacing: 0.12em;
                text-transform: uppercase;
                color: #fca5a5;
            }
            .reason-text {
                font-size: 15.5px;
                font-weight: 600;
                line-height: 1.5;
                color: #fff;
                word-break: break-word;
            }

            button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                padding: 16px 40px;
                font-family: inherit;
                font-size: 17px;
                font-weight: 700;
                color: #b91c1c;
                background: #fff;
                border: none;
                border-radius: 14px;
                cursor: pointer;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.35);
                transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
            }
            button:hover {
                transform: translateY(-2px);
                background: #fff1f1;
                box-shadow: 0 14px 32px rgba(0, 0, 0, 0.45);
            }
            button:active { transform: translateY(0); }
            button:focus-visible { outline: 3px solid #fca5a5; outline-offset: 3px; }

            .footer {
                margin-top: 28px;
                font-size: 12.5px;
                letter-spacing: 0.04em;
                color: rgba(255, 255, 255, 0.45);
            }

            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes slideUp {
                from { opacity: 0; transform: translateY(30px) scale(0.97); }
                to   { opacity: 1; transform: translateY(0) scale(1); }
            }
            @keyframes pulse {
                0%   { transform: scale(0.85); opacity: 0.9; }
                100% { transform: scale(1.7);  opacity: 0; }
            }

            @media (max-width: 520px) {
                .card { padding: 36px 22px 30px; }
                h1 { font-size: 28px; }
                .reason-text { font-size: 14.5px; }
            }
        </style>

        <div class="overlay" role="alertdialog" aria-modal="true" aria-label="AntiGravity güvenlik uyarısı">
            <div class="grid"></div>
            <div class="card">
                <div class="icon-wrap">
                    <div class="icon-circle">
                        <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/>
                            <line x1="12" y1="8" x2="12" y2="13"/>
                            <circle cx="12" cy="16.5" r="0.6" fill="#fff"/>
                        </svg>
                    </div>
                </div>

                <span class="badge">Adli Güvenlik Koruması</span>
                <h1>Erişim Engellendi</h1>
                <h2>Adli Bilişim Sistem Koruması</h2>

                <div class="url-box">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="4.9" y1="4.9" x2="19.1" y2="19.1"/>
                    </svg>
                    <span class="url-text" id="ag-url"></span>
                </div>

                <div class="reason-box">
                    <div class="reason-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fca5a5" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    </div>
                    <div>
                        <span class="reason-label">Tespit</span>
                        <span class="reason-text" id="ag-reason"></span>
                    </div>
                </div>

                <button id="ag-safe-return" type="button">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M19 12H5"/>
                        <path d="m12 19-7-7 7-7"/>
                    </svg>
                    Güvenliğe Geri Dön
                </button>

                <div class="footer">Korunuyorsunuz &bull; AntiGravity AI Engine</div>
            </div>
        </div>
    `;

    shadow.getElementById("ag-url").textContent = cleanUrl;
    shadow.getElementById("ag-reason").textContent =
        blockReason || "Tehdit veya şüpheli içerik tespit edildi.";

    document.documentElement.appendChild(host);

    const prevHtmlOverflow = document.documentElement.style.overflow;
    const prevBodyOverflow = document.body ? document.body.style.overflow : "";
    
    if (isHardBlock) {
        document.documentElement.style.overflow = "hidden";
        if(document.body) document.body.style.overflow = "hidden";
    }

    shadow.getElementById("ag-safe-return").addEventListener("click", () => {
        if (isHardBlock) {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = "about:blank";
            }
            return;
        }

        const shield = document.getElementById("antigravity-shield");
        if (shield) shield.remove();
        document.documentElement.style.overflow = prevHtmlOverflow;
        if(document.body) document.body.style.overflow = prevBodyOverflow;
    });
}