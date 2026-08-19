# EmadNet — Railway Ready

## اجرا
Railway باید پروژه را از GitHub بگیرد و با `npm start` اجرا کند.

## متغیرهای Railway
این‌ها را در Railway Variables وارد کن:

- ADMIN_USER
- ADMIN_PASSWORD
- SESSION_SECRET
- RECOVERY_CONTACT
- TELEGRAM_BOT_TOKEN
- TELEGRAM_ADMIN_CHAT_ID
- SUPPLIER_API_KEY
- SUPPLIER_API_URL
- BACKUP_TOKEN

هیچ Secret واقعی را داخل GitHub قرار نده.

## تست بعد از Deploy
دامنه Railway را باز کن:

`https://YOUR-RAILWAY-DOMAIN/health`

باید JSON با `status: "ok"` ببینی.

اگر Frontend در `public/index.html` باشد، ریشه دامنه `/` همان فایل را نمایش می‌دهد.

## نکته مهم درباره db.json
این نسخه برای شروع از `data/db.json` استفاده می‌کند. برای نگهداری پایدار فایل روی Railway، در صورت نیاز باید Persistent Volume تنظیم شود. Cloudflare R2 فقط بکاپ است و جای دیتابیس اصلی را نمی‌گیرد.

## Backup
Endpoint بکاپ:

`GET /internal/backup/export`

با هدر:

`Authorization: Bearer YOUR_BACKUP_TOKEN`

این endpoint برای Cloudflare Worker است و بدون توکن 401 می‌دهد.
