import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import hashlib
import os
import sqlite3

# Veritabanı bağlantısı ve tablonun oluşturulması

def create_db():
    conn = sqlite3.connect('hash_db.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    

# Hash hesaplama fonksiyonu
def calculate_hash(file_path):
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):  # Dosyayı 4KB'lık parçalar halinde oku
                hash_sha256.update(chunk)
        result = hash_sha256.hexdigest()
        print(f"{file_path} hash'i: {result}")  # Hata ayıklama
        return result
    except Exception as e:
        print(f"Hash hesaplama hatası: {e}")
        return None

# Dosyaları tarama ve hash hesaplama
def scan_files(file_paths):
    hashes = []
    file_paths_result = []
    
    for file_path in file_paths:
        if os.path.isfile(file_path):
            file_hash = calculate_hash(file_path)
            if file_hash:
                hashes.append(file_hash)
                file_paths_result.append(file_path)
        elif os.path.isdir(file_path):
            for root, _, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_hash(full_path)
                    if file_hash:
                        hashes.append(file_hash)
                        file_paths_result.append(full_path)
    return hashes, file_paths_result

# Veritabanındaki zararlı hash'leri yükleme
def load_malicious_hashes():
    conn = sqlite3.connect('hash_db.db')
    cursor = conn.cursor()
    cursor.execute('SELECT hash FROM malicious_hashes')
    hashes = cursor.fetchall()
    conn.close()
    print("Veritabanındaki Zararlı Hash'ler:", hashes)  # Hata ayıklama
    return [hash[0] for hash in hashes]
# Hash'leri veritabanına yükleme
def add_hashes_to_db(hashes):
    conn = sqlite3.connect('hash_db.db')
    cursor = conn.cursor()
    for hash_value in hashes:
        cursor.execute('INSERT INTO malicious_hashes (hash) VALUES (?)', (hash_value,))
    conn.commit()
    conn.close()
    print(f"{len(hashes)} hash veritabanına eklendi.")


# Zararlı hash kontrolü
def check_hash_in_db(user_hash):
    malicious_hashes = load_malicious_hashes()
    return user_hash in malicious_hashes

# Tarama işlemi ve zararlı dosya kontrolü
def scan_and_compare(file_paths):
    # Dosya hash'lerini al
    scan_hashes, file_paths_result = scan_files(file_paths)
    malicious_hashes = load_malicious_hashes()
    print("Taranan Hash'ler:", scan_hashes)
    print("Veritabanındaki Hash'ler:", malicious_hashes)

    # Zararlı hash'lerle karşılaştır
   
    infected_files = [
        (file_paths_result[i], scan_hashes[i]) 
        for i in range(len(scan_hashes)) 
        if scan_hashes[i] in malicious_hashes
    ]

    if infected_files:
        infected_info = "\n".join([f"Dosya: {file}, Hash: {hash}" for file, hash in infected_files])
        print(f"Zararlı dosyalar bulundu:\n{infected_info}")
        messagebox.showerror("Zararlı Yazılım Tespit Edildi", f"Zararlı dosyalar bulundu:\n{infected_info}")
    else:
        print("Zararlı dosya bulunamadı.")
        messagebox.showinfo("Temiz", "Zararlı dosya bulunmadı, dosyalar temiz.")


# Dosya seçip hash yükleme
def load_hashes_from_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        # Dosyanın hash'ini hesapla
        file_hash = calculate_hash(file_path)
        
        if file_hash:  # Dosya geçerli bir hash içeriyorsa
            # Dosya içindeki hash'leri veritabanına yükle
            with open(file_path, 'r') as file:
                hashes = [line.strip() for line in file.readlines()]
            add_hashes_to_db(hashes)
            print("Hash'ler veritabanına başarıyla yüklendi.")
        else:
            # Eğer dosya geçerli bir hash içermiyorsa, kullanıcıyı bilgilendir
            messagebox.showinfo("Uyarı", "Üzgünüz, bu içerik zararlı yazılım verileri içermiyor. Lütfen doğru bir dosya seçin.")
            load_hashes_from_file()  # Kullanıcıyı tekrar dosya seçmeye zorla

# Manuel hash girişi
def enter_hash_manually():
    user_hash = simpledialog.askstring("Manuel Hash Girişi", "Hash değerinizi girin:")
    if user_hash:
        if check_hash_in_db(user_hash):
            messagebox.showerror("Zararlı Yazılım", "Bu hash zararlı yazılıma ait!")
            print("Bu hash zararlı yazılıma ait!")
        else:
            messagebox.showinfo("Temiz", "Bu hash temiz, zararlı değil.")
            print("Bu hash temiz, zararlı değil.")

# Tkinter GUI
def browse_and_scan():
    # Kullanıcının dosya seçmesini sağlayın
    
    file_types = [".3g2", ".3gp", ".3gpp", ".3gpp2", ".a", ".aac", ".adts", ".ai", ".aif", ".aifc", ".aiff", ".ass", ".au", ".avi", ".avif", ".bat", ".bcpio", ".bin", ".bmp", ".c", ".cdf", ".cpio", ".csh", ".css", ".csv", ".dll", ".doc", ".dot", ".dvi", ".eml", ".eps", ".etx", ".exe", ".gif", ".gtar", ".h", ".h5", ".hdf", ".heic", ".heif", ".htm", ".html", ".ico", ".ief", ".jpe", ".jpeg", ".jpg", ".js", ".json", ".ksh", ".latex", ".loas", ".m1v", ".m3u", ".m3u8", ".man", ".me", ".mht", ".mhtml", ".mif", ".mjs", ".mov", ".movie", ".mp2", ".mp3", ".mp4", ".mpa", ".mpe", ".mpeg", ".mpg", ".ms", ".n3", ".nc", ".nq", ".nt", ".nws", ".o", ".obj", ".oda", ".opus", ".p12", ".p7c", ".pbm", ".pdf", ".pfx", ".pgm", ".pl", ".png", ".pnm", ".pot", ".ppa", ".ppm", ".pps", ".ppt", ".ps", ".pwz", ".py", ".pyc", ".pyo", ".qt", ".ra", ".ram", ".ras", ".rdf", ".rgb", ".roff", ".rtx", ".sgm", ".sgml", ".sh", ".shar", ".snd", ".so", ".src", ".srt", ".sv4cpio", ".sv4crc", ".svg", ".swf", ".t", ".tar", ".tcl", ".tex", ".texi", ".texinfo", ".tif", ".tiff", ".tr", ".trig", ".tsv", ".txt", ".ustar", ".vcf", ".vtt", ".wasm", ".wav", ".webm", ".webmanifest", ".wiz", ".wsdl", ".xbm", ".xlb", ".xls", ".xml", ".xpdl", ".xpm", ".xsl", ".xwd", ".zip"]  # İstenilen dosya türlerini buraya ekleyin
    file_paths = filedialog.askopenfilenames(filetypes=[("All Files", "*.*")] + [(f"{ft} Files", f"*{ft}") for ft in file_types])
    print(file_paths)
    if file_paths:
        scan_and_compare(file_paths)

def load_hashes_options():
    file_path = filedialog.askopenfilename()
    if file_path:
        # Dosyanın hash'ini hesapla
        file_hash = calculate_hash(file_path)
        
        if file_hash:  # Dosya geçerli bir hash içeriyorsa
            with open(file_path, 'r') as file:
                hashes = [line.strip() for line in file.readlines()]
            add_hashes_to_db(hashes)
            print("Hash'ler veritabanına başarıyla yüklendi.")
        else:
            # Eğer dosya geçerli bir hash içermiyorsa, kullanıcıyı bilgilendir
            messagebox.showinfo("Uyarı", "Üzgünüz, bu içerik zararlı yazılım verileri içermiyor. Lütfen doğru bir dosya seçin.")
            load_hashes_options()  # Kullanıcıyı tekrar dosya seçmeye zorla

# Ana pencereyi oluştur
root = tk.Tk()
root.title("Zararlı Yazılım Tarayıcı")

# Butonlar
button_browse = tk.Button(root, text="Gözat ve Tara", command=browse_and_scan)
button_browse.pack(pady=20)

button_manual_hash = tk.Button(root, text="Manuel Hash Girişi", command=enter_hash_manually)
button_manual_hash.pack(pady=20)


button_load_hashes = tk.Button(root, text="Veritabanına Zararlı Hash Yükle", command=load_hashes_options)
button_load_hashes.pack(pady=20)


# Veritabanı oluştur
create_db()

# Ana döngü
root.mainloop()     
