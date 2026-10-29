\# 🛡️ AntiGravity: Zero-Trust Web Security \& Phishing Detector



AntiGravity, oltalama (phishing) sitelerini ve sahte içerikleri gerçek zamanlı olarak tespit edip engelleyen, yapay zeka destekli hibrit bir siber güvenlik projesidir.



\## 🚀 Proje Mimarisi

Sistem iki ana bileşenden oluşur:

1\. \*\*Chrome Agent (Eklenti):\*\* Ziyaret edilen web sayfalarının URL yapısını ve sayfa içeriğini (DOM) anlık olarak yakalayıp yerel AI motoruna iletir. CORS korumalarını aşmak için arka plan servisi (background.js) kullanır.

2\. \*\*AI Engine (FastAPI):\*\* Gelen verileri eğitilmiş Makine Öğrenmesi modellerinden geçirerek tehdit analizi yapar. 



\## 🧠 Hibrit Yapay Zeka Mantığı

\- \*\*URL Analizi:\*\* Random Forest algoritması ile URL'deki anormallikler, tire kullanımları, HTTP durumu ve oltalama kelimeleri (login, verify vb.) tespit edilir.

\- \*\*NLP (Metin Analizi):\*\* TF-IDF vektörizasyonu ve Multinomial Naive Bayes algoritması ile sayfa içindeki dolandırıcılık ve sahte haber metinleri taranır.



\## 📊 SOC Dashboard \& Veritabanı

FastAPI üzerinden yayın yapan entegre bir \*\*Güvenlik Operasyon Merkezi (SOC)\*\* paneline sahiptir.

\- Engellenen tehditler ve güvenli siteler canlı olarak izlenebilir.

\- Tüm loglar ve analiz detayları (Engelleme nedenleri) kalıcı olarak \*\*SQLite\*\* veritabanında saklanır.



\## 💻 Kurulum ve Çalıştırma

1\. Python bağımlılıklarını yükleyin: `pip install fastapi uvicorn pandas scikit-learn joblib`

2\. AI Motorunu başlatın: `cd ai\_engine` -> `uvicorn main:app --reload`

3\. Chrome'da `chrome://extensions/` adresine gidin.

4\. "Geliştirici modu"nu açın ve "Paketlenmemiş öğe yükle" diyerek `browser\_agent` klasörünü seçin.

5\. Canlı logları izlemek için tarayıcıda `http://127.0.0.1:8000/dashboard` adresine gidin.

