const I18N = {
    en: {
        tagline: "Zero-Trust Real-Time Browser Threat Defense",
        sec1Title: "SOC AI Engine Server Connection",
        sec1Desc: "Specify the endpoint of your local or remote AntiGravity SOC Python backend.",
        btnTest: "Ping Server",
        sec2Title: "Zero-Trust Protection Sensitivity",
        sec2Desc: "Select defense posture or fine-tune minimum machine learning risk threshold.",
        modeStrict: "Strict (Paranoid)",
        modeStrictDesc: "Aggressive Zero-Day blocking (Threshold: 70%)",
        modeBalanced: "Balanced (Default)",
        modeBalancedDesc: "Optimized precision and zero false positives (80%)",
        modePermissive: "Permissive",
        modePermissiveDesc: "High-confidence alerts only (Threshold: 90%)",
        lblSlider: "Custom AI Block Threshold:",
        sec3Title: "Advanced Detection Vectors",
        sec3Desc: "Enable or disable specialized deep inspection defense engines.",
        modVision: "Visual Logo Perceptual Hashing (dHash)",
        modVisionDesc: "Detects visual brand impersonation and cloned favicons using 64-bit difference hashing.",
        modHomograph: "IDN Homograph & Punycode Trap",
        modHomographDesc: "Intercepts lookalike Cyrillic/Greek characters disguising malicious spoof domains.",
        modForms: "Credential Trap (Free Cloud Hosting)",
        modFormsDesc: "Instantly blocks password fields deployed on free cloud hosts (pages.dev, firebaseapp, etc.).",
        sec4Title: "Alerts & System Feedback",
        sec4Desc: "Configure how the extension communicates security events to the analyst.",
        optNotify: "Chrome Desktop Notifications",
        optNotifyDesc: "Display native system notification popups when malicious links are neutralized.",
        sec5Title: "Verified Operator Whitelist",
        sec5Desc: "Domains listed here bypass all AI and heuristic scoring entirely.",
        btnAdd: "Add Domain",
        loading: "Loading whitelist...",
        emptyWhite: "No custom domains in whitelist.",
        btnReset: "Reset Defaults",
        btnSave: "Save Settings",
        toastSaved: "✓ Settings saved and synced successfully.",
        toastReset: "Defaults restored.",
        pingOk: "✓ Server Online: {service} (v{version}) - Latency: {lat}ms",
        pingFail: "✕ Server unreachable. Make sure python3 ai_engine/main.py is running on port 8001."
    },
    tr: {
        tagline: "Sıfır-Güven Gerçek Zamanlı Tarayıcı Tehdit Savunması",
        sec1Title: "SOC AI Motoru Sunucu Bağlantısı",
        sec1Desc: "Yerel veya uzak AntiGravity SOC Python arka ucunun adresini belirtin.",
        btnTest: "Sunucuyu Test Et",
        sec2Title: "Sıfır-Güven Koruma Hassasiyeti",
        sec2Desc: "Savunma modunu seçin veya minimum makine öğrenimi risk eşiğini ayarlayın.",
        modeStrict: "Katı (Paranoyak)",
        modeStrictDesc: "Agresif Sıfır-Gün engellemesi (Eşik: %70)",
        modeBalanced: "Dengeli (Varsayılan)",
        modeBalancedDesc: "Optimize edilmiş hassasiyet ve sıfır hatalı pozitif (%80)",
        modePermissive: "Esnek (İzleme)",
        modePermissiveDesc: "Yalnızca yüksek kesinlikli alarmlar (Eşik: %90)",
        lblSlider: "Özel AI Bloklama Eşiği:",
        sec3Title: "Gelişmiş Tespit Vektörleri",
        sec3Desc: "Özel derin denetim savunma motorlarını etkinleştirin veya devre dışı bırakın.",
        modVision: "Görsel Logo Algısal Özetleme (dHash)",
        modVisionDesc: "64-bit fark özetleme ile marka taklidi ve klon faviconları tespit eder.",
        modHomograph: "IDN Homograph & Punycode Tuzağı",
        modHomographDesc: "Alan adlarını taklit eden Kiril/Grek harfli oltalama tuzaklarını engeller.",
        modForms: "Kimlik Bilgisi Tuzağı (Ücretsiz Bulut)",
        modFormsDesc: "Ücretsiz bulut alanlarında (pages.dev, firebaseapp vb.) şifre formlarını engeller.",
        sec4Title: "Alarmlar & Sistem Bildirimleri",
        sec4Desc: "Eklentinin güvenlik olaylarını analiste nasıl ileteceğini yapılandırın.",
        optNotify: "Chrome Masaüstü Bildirimleri",
        optNotifyDesc: "Zararlı bağlantılar engellendiğinde yerel sistem bildirimi gösterir.",
        sec5Title: "Doğrulanmış Operatör Beyaz Listesi",
        sec5Desc: "Buradaki alan adları tüm yapay zeka denetimlerini tamamen atlar.",
        btnAdd: "Alan Ekle",
        loading: "Beyaz liste yükleniyor...",
        emptyWhite: "Beyaz listede özel alan adı yok.",
        btnReset: "Varsayılana Sıfırla",
        btnSave: "Ayarları Kaydet",
        toastSaved: "✓ Ayarlar başarıyla kaydedildi ve senkronize edildi.",
        toastReset: "Varsayılan ayarlar yüklendi.",
        pingOk: "✓ Sunucu Aktif: {service} (v{version}) - Gecikme: {lat}ms",
        pingFail: "✕ Sunucuya ulaşılamadı. Python sunucusunun çalıştığından emin olun."
    }
};

let currentLang = "en";

function setLang(lang) {
    currentLang = lang;
    document.getElementById("btnLangEN").classList.toggle("active", lang === "en");
    document.getElementById("btnLangTR").classList.toggle("active", lang === "tr");

    document.querySelectorAll("[data-i18n]").forEach(el => {
        const key = el.getAttribute("data-i18n");
        if (I18N[lang] && I18N[lang][key]) {
            el.textContent = I18N[lang][key];
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const serverUrlInput = document.getElementById("serverUrl");
    const btnPing = document.getElementById("btnPing");
    const pingResult = document.getElementById("pingResult");
    const thresholdSlider = document.getElementById("thresholdSlider");
    const thresholdVal = document.getElementById("thresholdVal");
    const modeCards = document.querySelectorAll(".mode-card");
    const chkVisualHasing = document.getElementById("chkVisualHasing");
    const chkPunycode = document.getElementById("chkPunycode");
    const chkForms = document.getElementById("chkForms");
    const chkNotifications = document.getElementById("chkNotifications");
    const whiteInput = document.getElementById("whiteInput");
    const btnAddWhite = document.getElementById("btnAddWhite");
    const whiteListWrap = document.getElementById("whiteListWrap");
    const btnSave = document.getElementById("btnSave");
    const btnReset = document.getElementById("btnReset");
    const toastStatus = document.getElementById("toastStatus");

    let currentMode = "balanced";

    function showToast(msg) {
        toastStatus.textContent = msg;
        setTimeout(() => { toastStatus.textContent = ""; }, 3500);
    }

    // Language switchers
    document.getElementById("btnLangEN").addEventListener("click", () => setLang("en"));
    document.getElementById("btnLangTR").addEventListener("click", () => setLang("tr"));

    // Sensitivity mode cards
    modeCards.forEach(card => {
        card.addEventListener("click", () => {
            modeCards.forEach(c => c.classList.remove("active"));
            card.classList.add("active");
            currentMode = card.getAttribute("data-mode");

            if (currentMode === "strict") {
                thresholdSlider.value = 70;
            } else if (currentMode === "balanced") {
                thresholdSlider.value = 80;
            } else if (currentMode === "permissive") {
                thresholdSlider.value = 90;
            }
            thresholdVal.textContent = `${thresholdSlider.value}%`;
        });
    });

    thresholdSlider.addEventListener("input", (e) => {
        thresholdVal.textContent = `${e.target.value}%`;
        // deselect mode cards if custom value
        const val = parseInt(e.target.value);
        modeCards.forEach(c => c.classList.remove("active"));
        if (val <= 70) document.querySelector('[data-mode="strict"]')?.classList.add("active");
        else if (val <= 85) document.querySelector('[data-mode="balanced"]')?.classList.add("active");
        else document.querySelector('[data-mode="permissive"]')?.classList.add("active");
    });

    // Load Settings
    function loadSettings() {
        if (!chrome.storage || !chrome.storage.sync) {
            serverUrlInput.value = "http://127.0.0.1:8001";
            fetchWhitelist();
            return;
        }

        chrome.storage.sync.get([
            "serverUrl",
            "sensitivityMode",
            "threshold",
            "visualHashing",
            "punycode",
            "forms",
            "notificationsEnabled",
            "lang"
        ], (cfg) => {
            serverUrlInput.value = cfg.serverUrl || "http://127.0.0.1:8001";
            const val = cfg.threshold || 80;
            thresholdSlider.value = val;
            thresholdVal.textContent = `${val}%`;

            chkVisualHasing.checked = cfg.visualHashing !== false;
            chkPunycode.checked = cfg.punycode !== false;
            chkForms.checked = cfg.forms !== false;
            chkNotifications.checked = cfg.notificationsEnabled !== false;

            if (cfg.lang) setLang(cfg.lang);

            const mode = cfg.sensitivityMode || "balanced";
            modeCards.forEach(c => {
                c.classList.toggle("active", c.getAttribute("data-mode") === mode);
            });

            fetchWhitelist();
        });
    }

    // Save Settings
    btnSave.addEventListener("click", () => {
        const serverUrl = serverUrlInput.value.trim().replace(/\/+$/, "") || "http://127.0.0.1:8001";
        const cfg = {
            serverUrl: serverUrl,
            sensitivityMode: currentMode,
            threshold: parseInt(thresholdSlider.value),
            visualHashing: chkVisualHasing.checked,
            punycode: chkPunycode.checked,
            forms: chkForms.checked,
            notificationsEnabled: chkNotifications.checked,
            lang: currentLang
        };

        if (chrome.storage && chrome.storage.sync) {
            chrome.storage.sync.set(cfg, () => {
                showToast(I18N[currentLang].toastSaved);
            });
        } else {
            localStorage.setItem("antigravity_config", JSON.stringify(cfg));
            showToast(I18N[currentLang].toastSaved);
        }
    });

    // Reset Defaults
    btnReset.addEventListener("click", () => {
        serverUrlInput.value = "http://127.0.0.1:8001";
        thresholdSlider.value = 80;
        thresholdVal.textContent = "80%";
        chkVisualHasing.checked = true;
        chkPunycode.checked = true;
        chkForms.checked = true;
        chkNotifications.checked = true;
        modeCards.forEach(c => c.classList.toggle("active", c.getAttribute("data-mode") === "balanced"));
        showToast(I18N[currentLang].toastReset);
    });

    // Ping Server
    btnPing.addEventListener("click", async () => {
        const url = serverUrlInput.value.trim().replace(/\/+$/, "") || "http://127.0.0.1:8001";
        pingResult.style.color = "var(--text-muted)";
        pingResult.textContent = "Connecting to " + url + "...";

        const t0 = performance.now();
        try {
            const res = await fetch(`${url}/health`);
            const lat = Math.round(performance.now() - t0);
            if (res.ok) {
                const data = await res.json();
                pingResult.style.color = "var(--safe)";
                pingResult.textContent = I18N[currentLang].pingOk
                    .replace("{service}", data.service || "AntiGravity SOC")
                    .replace("{version}", data.version || "2.1")
                    .replace("{lat}", lat);
            } else {
                throw new Error("HTTP " + res.status);
            }
        } catch(err) {
            pingResult.style.color = "var(--danger)";
            pingResult.textContent = I18N[currentLang].pingFail;
        }
    });

    // Whitelist Manager
    async function fetchWhitelist() {
        const url = serverUrlInput.value.trim().replace(/\/+$/, "") || "http://127.0.0.1:8001";
        try {
            const res = await fetch(`${url}/api/whitelist`);
            if (!res.ok) throw new Error();
            const list = await res.json();
            renderWhitelist(list);
        } catch(e) {
            whiteListWrap.innerHTML = `<div class="white-item" style="color:var(--text-muted); justify-content:center;">${I18N[currentLang].emptyWhite}</div>`;
        }
    }

    function renderWhitelist(list) {
        if (!list || !list.length) {
            whiteListWrap.innerHTML = `<div class="white-item" style="color:var(--text-muted); justify-content:center;">${I18N[currentLang].emptyWhite}</div>`;
            return;
        }

        whiteListWrap.innerHTML = list.map(item => `
            <div class="white-item">
                <span>🛡️ ${item.domain}</span>
                <button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px;" data-domain="${item.domain}">Remove</button>
            </div>
        `).join("");

        whiteListWrap.querySelectorAll("button").forEach(b => {
            b.addEventListener("click", async () => {
                const dom = b.getAttribute("data-domain");
                const url = serverUrlInput.value.trim().replace(/\/+$/, "") || "http://127.0.0.1:8001";
                await fetch(`${url}/api/whitelist/remove`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain: dom })
                });
                fetchWhitelist();
            });
        });
    }

    btnAddWhite.addEventListener("click", async () => {
        const dom = whiteInput.value.trim();
        if (!dom) return;
        const url = serverUrlInput.value.trim().replace(/\/+$/, "") || "http://127.0.0.1:8001";
        try {
            const res = await fetch(`${url}/api/whitelist/add`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: dom })
            });
            const data = await res.json();
            whiteInput.value = "";
            showToast(data.message || "Domain updated");
            fetchWhitelist();
        } catch(e) {
            showToast("Failed to connect to backend");
        }
    });

    loadSettings();
});
