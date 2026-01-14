# ZiVPN UDP Tunnel

**ZiVPN UDP Tunnel** adalah solusi tunneling UDP premium dengan manajemen yang mudah, aman, dan otomatis. Dilengkapi dengan **API Server** dan **Telegram Bot** untuk pengelolaan user tanpa ribet.

---

## 🌟 Fitur Utama

*   **Minimalist CLI**: Installer dengan tampilan modern, bersih, dan elegan.
*   **Headless Management**: Manajemen user sepenuhnya via API atau Bot.
*   **Telegram Bot Integration**:
    *   **Free Bot**: Manajemen user (Create, Renew, Delete) dengan fitur **Backup & Restore**.
    *   **Paid Bot**: Integrasi Pakasir (QRIS) dengan **Admin Panel** tersembunyi.
*   **Robust User Management**:
    *   **Auto-Revoke**: User expired otomatis disconnect setiap jam 00:00 WIB (via Cron).
    *   **Clean Deletion**: Hapus user bersih total dari config dan database.
*   **Dynamic Security**: API Key dan sertifikat SSL digenerate otomatis.
*   **High Performance**: Core UDP ZiVPN yang dioptimalkan.

---

## 💳 Persiapan Payment Gateway (Pakasir)
Jika Anda ingin menggunakan **Paid Bot**, Anda wajib memiliki akun Pakasir.

1.  **Registrasi**: Daftar akun di [https://pakasir.com](https://pakasir.com).
2.  **Buat Proyek**: Buat proyek baru di dashboard Pakasir.
3.  **Ambil Kredensial**:
    *   **Project Slug**: ID unik proyek Anda.
    *   **API Key**: Kunci rahasia untuk akses API.
4.  **Saldo**: Pastikan akun Pakasir Anda aktif.

---

## 📥 Instalasi

Jalankan perintah berikut di terminal VPS Anda (sebagai root):

```bash
wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/install.sh && chmod +x install.sh && ./install.sh
```

### Konfigurasi Saat Instalasi
Saat script berjalan, Anda akan diminta memasukkan:
1.  **Domain**: Wajib diisi untuk generate sertifikat SSL (contoh: `vpn.domain.com`).
2.  **API Key**: Tekan **Enter** untuk auto-generate.
3.  **Telegram Bot** (Opsional):
    *   **Bot Token**: Token dari @BotFather.
    *   **Admin ID**: ID Telegram Anda (cek di @userinfobot).
    *   **Bot Type**: Free atau Paid.

---

## 🤖 Telegram Bot Usage

### Free Bot
*   **Public User**: Hanya bisa akses menu **Create**, **Renew**, **Delete**.
*   **Admin**: Akses penuh termasuk **List Users**, **System Info**, dan **Backup & Restore**.

### Paid Bot (Pakasir)
*   **Public User**: Hanya bisa membeli akun (Create) dan Cek Info.
*   **Admin**: Memiliki menu rahasia **🛠️ Admin Panel** yang berisi fitur manajemen dan **Backup & Restore**.

### Fitur Backup & Restore
*   **Backup**: Bot mengirim file ZIP berisi semua data server (`config.json`, `users.json`, dll).
*   **Restore**: Kirim file ZIP backup ke bot untuk restore data dan restart server otomatis.

---

## 📱 ZiVPN Manager App

Kelola server dan user Anda dengan mudah menggunakan aplikasi Android resmi **ZiVPN Manager**.

[**Download ZiVPN Manager (APK)**](https://github.com/AutoFTbot/ZiVPN/raw/main/App/app-release.apk)

### Screenshots
<p float="left">
  <img src="https://github.com/AutoFTbot/ZiVPN/raw/main/App/photo_2025-12-18_20-25-53.jpg" width="200" />
  <img src="https://github.com/AutoFTbot/ZiVPN/raw/main/App/photo_2025-12-18_20-26-05.jpg" width="200" />
  <img src="https://github.com/AutoFTbot/ZiVPN/raw/main/App/photo_2025-12-18_20-26-11.jpg" width="200" />
  <img src="https://github.com/AutoFTbot/ZiVPN/raw/main/App/photo_2025-12-18_20-26-15.jpg" width="200" />
  <img src="https://github.com/AutoFTbot/ZiVPN/raw/main/App/photo_2025-12-18_20-26-21.jpg" width="200" />
</p>

---

## 🔌 API Documentation

API berjalan di port `8080`. Gunakan **API Key** pada header `X-API-Key`.

**Base URL**: `http://<IP-VPS>:8080`
**Header**: `X-API-Key: <YOUR-API-KEY>`

### 1. Create User
*   **Endpoint**: `/api/user/create`
*   **Method**: `POST`
*   **Body**: `{ "password": "user1", "days": 30 }`

### 2. Delete User
*   **Endpoint**: `/api/user/delete`
*   **Method**: `POST`
*   **Body**: `{ "password": "user1" }`

### 3. Renew User
*   **Endpoint**: `/api/user/renew`
*   **Method**: `POST`
*   **Body**: `{ "password": "user1", "days": 30 }`

### 4. List Users
*   **Endpoint**: `/api/users`
*   **Method**: `GET`

### 5. System Info
*   **Endpoint**: `/api/info`
*   **Method**: `GET`

### 6. Cron Trigger (Expire Check)
*   **Endpoint**: `/api/cron/expire`
*   **Method**: `POST`
*   **Desc**: Trigger manual pengecekan expired (biasanya jalan otomatis jam 00:00 WIB).

---

## 🚀 Postman Collection
Anda dapat mengimpor koleksi API lengkap ke Postman menggunakan file JSON berikut:
[Download zivpn_postman_collection.json](zivpn_postman_collection.json)

---

## �🛠️ Pemecahan Masalah (Troubleshooting)

### 1. Log "TCP error" di Jurnal
Jika Anda melihat log seperti:
`ERROR TCP error {"addr": "140.213.xx.xx:..."}`

*   **Penyebab**: Koneksi client tidak stabil (sering terjadi pada jaringan seluler/Indosat) atau masalah MTU.
*   **Solusi**:
    *   Ini biasanya **bukan error server**. Jika user masih bisa connect, abaikan saja.
    *   Jika user sering disconnect, sarankan user menurunkan **MTU** di aplikasi client mereka (coba `1100` atau `1200`).

### 2. Bot Telegram Tidak Merespon
*   Pastikan service berjalan: `systemctl status zivpn-bot`
*   Cek log error: `journalctl -u zivpn-bot -f`
*   Pastikan **Bot Token** dan **Admin ID** benar di `/etc/zivpn/bot-config.json`.
*   Restart bot: `systemctl restart zivpn-bot`

### 3. API Error "Unauthorized"
*   Pastikan Anda menggunakan **API Key** yang benar di header `X-API-Key`.
*   Cek key yang aktif di server: `cat /etc/zivpn/apikey`

### 4. Service Gagal Start
*   Cek status: `systemctl status zivpn`
*   Pastikan port `5667` (UDP) dan `8080` (TCP) tidak terpakai aplikasi lain.
*   Cek config: `cat /etc/zivpn/config.json`

---

## 🗑️ Uninstall

Untuk menghapus ZiVPN, API, Bot, dan semua konfigurasi:

```bash
wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/uninstall.sh && chmod +x uninstall.sh && ./uninstall.sh
```
