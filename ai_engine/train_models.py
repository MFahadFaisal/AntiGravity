import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

def train_with_all_available_datasets():
    print("[*] AntiGravity Çoklu Veri Seti Entegrasyonu Başlatılıyor...")
    datasets_dir = "datasets" if os.path.exists("datasets") else "."
    
    # Yüklemek istediğimiz aday veri setleri
    candidate_files = ["dataset.csv", "uci-ml-phishing-dataset.csv", "Nazario.csv"]
    loaded_dfs = []

    for file_name in candidate_files:
        file_path = os.path.join(datasets_dir, file_name) if datasets_dir != "." else file_name
        if os.path.exists(file_path):
            try:
                df = pd.read_csv(file_path, low_memory=False)
                # Fazladan index veya id sütunlarını temizleyelim
                for col in ['id', 'index', 'Unnamed: 0']:
                    if col in df.columns:
                        df = df.drop(columns=[col])
                loaded_dfs.append(df)
                print(f"[✓] Başarıyla yüklendi: {file_name} (Boyut: {df.shape})")
            except Exception as e:
                print(f"[!] {file_name} okunurken hata: {e}")

    if not loaded_dfs:
        print("[!] HATA: Hiçbir veri seti yüklenemedi!")
        return

    # Sütunları birebir uyuşan (UCI tabanlı) veri setlerini birleştirelim
    main_df = loaded_dfs[0]
    for i in range(1, len(loaded_dfs)):
        # Sütun isimleri uyuşuyorsa alt alta birleştirelim (concat)
        if set(main_df.columns) == set(loaded_dfs[i].columns):
            main_df = pd.concat([main_df, loaded_dfs[i]], ignore_index=True)
            print(f"[✓] {candidate_files[i]} ana havuza başarıyla eklendi.")
        else:
            print(f"[!] {candidate_files[i]} sütun yapıları farklı olduğu için bu turda atlandı.")

    print(f"[*] Birleştirilmiş Toplam Veri Havuzu Boyutu: {main_df.shape}")

    # Hedef (Label) sütunu tespiti ('Result' veya son sütun)
    target_column = 'Result' if 'Result' in main_df.columns else main_df.columns[-1]
    print(f"[*] Hedef Sütun: '{target_column}'")

    X = main_df.drop(columns=[target_column])
    y = main_df[target_column]

    # Etiket standardizasyonu (-1 -> 1 Zararlı, 1/0 -> 0 Güvenli)
    def map_labels(val):
        try:
            val = int(val)
            if val == -1:
                return 1
            elif val == 1:
                return 0
            elif val == 0:
                return 0
            else:
                return 1
        except:
            return 0

    y = y.apply(map_labels)
    print(f"[*] Düzenlenmiş Etiket Dağılımı (0: Güvenli, 1: Zararlı):\n{y.value_counts()}")

    if len(y.unique()) < 2:
        print("[!] HATA: Veri havuzunda tek sınıf kaldı!")
        return

    # Dinamik ve esnek eğitim için random_state=None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=None, stratify=y)

    print("[*] Random Forest modeli genişletilmiş veri havuzu ile eğitiliyor...")
    url_model = RandomForestClassifier(
        n_estimators=180, 
        max_depth=15,          
        min_samples_split=10,  
        min_samples_leaf=4,    
        random_state=None,     
        class_weight='balanced'
    )

    url_model.fit(X_train, y_train)

    # Test ve Değerlendirme
    y_pred = url_model.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n==================================================")
    print("   ANTIGRAVITY - ÇOKLU VERİ SETİ PERFORMANS RAPORU")
    print("==================================================")
    print(f"Test Başarısı (Accuracy): %{test_acc * 100:.2f}")
    print("\nSınıflandırma Raporu:")
    print(classification_report(y_test, y_pred, target_names=['Güvenli (0)', 'Zararlı (1)'], zero_division=0))
    print("--------------------------------------------------")
    print("Karışıklık Matrisi (Confusion Matrix):")
    print(cm)
    print("==================================================")

    # Modeli Kaydetme
    joblib.dump(url_model, "antigravity_url_model.pkl")
    print("[✓] Genişletilmiş model başarıyla 'antigravity_url_model.pkl' olarak kaydedildi.")

    # Görsel Matris Çizimi
    plt.figure(figsize=(7, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Tahmin: Güvenli', 'Tahmin: Zararlı'],
                yticklabels=['Gerçek: Güvenli', 'Gerçek: Zararlı'])
    plt.xlabel('Yapay Zeka Tahmini', fontweight='bold')
    plt.ylabel('Gerçek Durum (Ground Truth)', fontweight='bold')
    plt.title('AntiGravity SOC - Genişletilmiş Veri Seti Doğruluk Matrişi', fontsize=11, fontweight='bold')
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    train_with_all_available_datasets()