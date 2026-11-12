# داشبورد تحلیل ترافیک MikroTik

یک داشبورد کاملاً Self-hosted برای مشاهده و نگهداری تاریخچهٔ ترافیک روترهای MikroTik است. برنامه داخل یک کانتینر RouterOS یا Docker اجرا می‌شود، شمارنده‌های رابط‌ها را از RouterOS API می‌خواند و اطلاعات دستگاه‌ها و پورت‌ها را از IPFIX دریافت می‌کند. تمام داده‌ها به‌صورت محلی در SQLite ذخیره می‌شوند و در زمان اجرا به سرویس ابری، CDN یا دیتابیس جداگانه نیاز نیست.

> این مخزن شامل هیچ رمز، دیتابیس، بکاپ روتر، کلید خصوصی، MAC، hostname یا اطلاعات شبکهٔ یک نصب واقعی نیست. تمام مقادیر شبکه در زمان اجرا تنظیم می‌شوند.

## امکانات

- نمای کلی سرعت لحظه‌ای دانلود و آپلود، WAN فعال، CPU، حافظه، uptime و حجم دیتابیس
- نمایش وضعیت و تاریخچهٔ هر Interface در بازه‌های زمانی مختلف
- تشخیص دستگاه‌ها از DHCP، ARP و Wi-Fi registration table
- محاسبهٔ مصرف هر IP یا hostname در بازهٔ انتخابی
- تفکیک مصرف upload و download بر اساس پورت، پروتکل و مقصد اینترنتی یا inter-LAN
- فهرست دستگاه‌های آنلاین و آخرین زمان مشاهده
- خروجی CSV برای تاریخچهٔ Interface و دستگاه
- SQLite با WAL، batching، index، rollup ساعتی/روزانه و retention قابل تنظیم
- تشخیص reset شدن counter یا reboot روتر
- رابط responsive با حالت روشن و تاریک و نمودارهای Canvas بدون کتابخانهٔ خارجی
- ورود امن، PBKDF2-SHA256، session سمت سرور، CSRF، محدودسازی تلاش ورود و TLS اختیاری
- محدودیت حافظه و backoff هنگام CPU بالا؛ خرابی collector روی routing روتر اثر نمی‌گذارد

## معماری

```text
RouterOS API (TCP 8728) ──> Collector ──> SQLite روی USB
RouterOS IPFIX (UDP 2055) ─> IPFIX parser ─┘
مرورگر (HTTP/HTTPS) ───────> Web/API server داخل همان کانتینر
```

ترافیک عادی شبکه از داخل کانتینر عبور نمی‌کند. کانتینر فقط آمار را از API و یک کپی IPFIX دریافت می‌کند؛ بنابراین توقف داشبورد نباید packet forwarding روتر را متوقف کند.

## پیش‌نیازها

برای اجرای مستقیم روی MikroTik:

- RouterOS 7 با پشتیبانی Container و package متناظر با نسخه و معماری روتر
- فعال‌بودن `container=yes` در Device Mode
- معماری پشتیبانی‌شده مانند `arm` یا `arm64` و image ساخته‌شده برای همان معماری
- حافظهٔ خارجی با فایل‌سیستم Linux مانند ext4؛ استفاده از NAND داخلی توصیه نمی‌شود
- فضای آزاد کافی برای root filesystem کانتینر و دیتابیس
- یک کاربر اختصاصی RouterOS با دسترسی فقط `read,api`
- دسترسی کابلی یا WinBox مطمئن هنگام تغییر Device Mode، فرمت USB و نصب package
- Docker Buildx روی رایانه برای ساخت image

برای اجرای آزمایشی با Docker فقط Docker/Compose، دسترسی شبکه به RouterOS API و امکان ارسال IPFIX از روتر لازم است.

## تنظیمات برنامه

فایل [.env.example](.env.example) را به `.env` کپی کنید و مقادیر را تغییر دهید. `.env` توسط Git نادیده گرفته می‌شود.

| متغیر | کاربرد | نمونه |
|---|---|---|
| `ROUTER_HOST` | آدرس RouterOS API | `172.30.0.1` |
| `ROUTER_PORT` | پورت API | `8728` |
| `ROUTER_USER` | کاربر اختصاصی collector | `traffic-monitor` |
| `ROUTER_PASSWORD` | رمز اختصاصی و تصادفی | بدون مقدار پیش‌فرض |
| `MONITORED_INTERFACES` | نام Interfaceها با کاما | `ether1,bridge` |
| `WAN_INTERFACES` | زیرمجموعهٔ Interfaceهای WAN | `ether1` |
| `LAN_NETWORKS` | نگاشت CIDR به Interface | `192.168.88.0/24=bridge` |
| `ROUTER_LAN_IPS` | آدرس‌های gateway که نباید دستگاه محسوب شوند | `192.168.88.1` |
| `WAN_ROUTE_COMMENTS` | نگاشت WAN به comment مسیر پیش‌فرض، اختیاری | `ether1=WAN-DEFAULT` |
| `IPFIX_SOURCE` | فقط IP مجاز برای ارسال IPFIX | `172.30.0.1` |
| `DATA_DIR` | محل SQLite | `/data` |
| `LISTEN_PORT` | پورت وب داخل کانتینر | `8080` |
| `TLS_CERT` / `TLS_KEY` | مسیر certificate و private key، اختیاری | `/certs/server.crt` |

چند شبکه یا نگاشت را با کاما جدا کنید:

```dotenv
MONITORED_INTERFACES=wan1,wan2,bridge-lan,wifi
WAN_INTERFACES=wan1,wan2
LAN_NETWORKS=192.168.10.0/24=bridge-lan,192.168.20.0/24=wifi
ROUTER_LAN_IPS=192.168.10.1,192.168.20.1
WAN_ROUTE_COMMENTS=wan1=PRIMARY-WAN,wan2=BACKUP-WAN
```

## اجرای آزمایشی با Docker Compose

```bash
cp .env.example .env
# مقادیر .env مخصوصاً ROUTER_PASSWORD و شبکه‌ها را ویرایش کنید
docker compose up -d --build
docker compose logs -f dashboard
```

در تنظیمات پیش‌فرض، داشبورد از `http://localhost:8080` باز می‌شود. در اولین ورود، نام کاربری و رمز مدیر داشبورد ساخته می‌شود؛ این حساب با حساب RouterOS متفاوت است.

برای دریافت دادهٔ IPFIX، در RouterOS یک Traffic Flow target با مقصد IP رایانهٔ Docker و پورت UDP 2055 بسازید. این پورت را فقط در شبکهٔ مورداعتماد باز کنید.

## ساخت image برای RouterOS

معماری را دقیقاً مطابق `/system/resource/print` انتخاب کنید:

```bash
# نمونه برای ARM 32-bit
docker buildx build --platform linux/arm/v7 -t router-analytics:1.1.7 --load .
docker save router-analytics:1.1.7 -o router-analytics-arm.tar

# نمونه برای ARM64
docker buildx build --platform linux/arm64 -t router-analytics:1.1.7 --load .
docker save router-analytics:1.1.7 -o router-analytics-arm64.tar
```

RouterOS باید بتواند archive تولیدشده را import کند. اگر نسخهٔ RouterOS شما archive ساخته‌شده با لایه‌های فشرده را نمی‌پذیرد، از Docker legacy save با لایه‌های uncompressed استفاده کنید.

## راه‌اندازی روی RouterOS

1. از تنظیمات روتر backup بگیرید و آن را خارج از روتر نگه دارید.
2. package کانتینر دقیقاً هم‌نسخه و هم‌معماری RouterOS را از MikroTik دریافت و نصب کنید.
3. با حضور فیزیکی `container=yes` را در Device Mode فعال کنید. دکمهٔ reset را نگه ندارید.
4. USB درست را با بررسی مدل، ظرفیت و serial شناسایی کنید؛ سپس فقط همان USB را ext4 فرمت کنید. این مرحله تمام اطلاعات USB را حذف می‌کند.
5. image را در `usb1-part1/images/`، داده را در `usb1-part1/analytics-data/` و certificateها را در `usb1-part1/analytics-certs/` قرار دهید.
6. یک certificate و private key مخصوص همان شبکه بسازید. کلید خصوصی را داخل Git یا image قرار ندهید.
7. فایل [deploy/routeros-deploy.rsc.example](deploy/routeros-deploy.rsc.example) را کپی کرده، تمام placeholderهای `__...__` را جایگزین و خط‌به‌خط بازبینی کنید.
8. اگر policy routing یا firewall سفارشی دارید، پیش از import مسیر دسترسی به subnet داخلی کانتینر و rule لازم برای LAN را متناسب با روتر خود اضافه کنید.
9. اسکریپت بازبینی‌شده را import کنید، پایان استخراج image را صبر کنید و سپس کانتینر را start کنید.
10. از یک سیستم داخل LAN داشبورد را باز کنید و حساب مدیر را در اولین اجرا بسازید.

فرمت `LAN_NETWORKS` در RouterOS همانند `.env` است. برای مثال عمومی:

```routeros
/container/envs/add list=analytics-env key=LAN_NETWORKS value="192.168.88.0/24=bridge"
```

اسکریپت نمونه عمداً اطلاعات نصب واقعی، certificate، رمز و نام Interface مشخصی ندارد و نباید بدون بازبینی مستقیم اجرا شود.

## TLS

برای LAN یک certificate با SAN شامل IP یا DNS واقعی داشبورد بسازید. نمونهٔ کلی:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
  -keyout server.key -out server.crt \
  -subj "/CN=router-analytics.local" \
  -addext "subjectAltName=DNS:router-analytics.local,IP:192.168.88.1"
```

`server.key` محرمانه است. برای حذف هشدار مرورگر، فقط `server.crt` را در دستگاه‌های مورداعتماد نصب کنید.

## تست توسعه

برنامه در runtime فقط به Python Standard Library وابسته است:

```bash
python -m py_compile app/app.py
python -m unittest discover -s tests -v
node --check app/static/app.js
node tests/test_chart_resize.js
```

## داده، backup و بازیابی

- دیتابیس در `DATA_DIR/traffic.db` قرار دارد و ممکن است شامل IP، MAC، hostname و الگوی مصرف باشد؛ آن را عمومی نکنید.
- برای backup سازگار، کانتینر را متوقف و فایل‌های `traffic.db`، `traffic.db-wal` و `traffic.db-shm` را با هم کپی کنید.
- خاموش یا خراب‌شدن USB فقط سرویس dashboard و تاریخچه را از دسترس خارج می‌کند؛ به شرطی که routing یا forwarding به کانتینر وابسته نشده باشد، عملکرد اصلی روتر ادامه می‌یابد.
- برای rollback، اسکریپت نمونهٔ [deploy/rollback.rsc.example](deploy/rollback.rsc.example) را ابتدا با تنظیمات خود تطبیق دهید. فایل‌های تاریخی روی USB عمداً حذف نمی‌شوند.

## محدودیت‌ها

- دستگاه‌های پشت یک NAT پایین‌دستی معمولاً فقط به‌صورت همان روتر NAT دیده می‌شوند.
- دقت per-device به ظرفیت cache و تنظیمات IPFIX وابسته است؛ این ابزار جایگزین packet capture یا سیستم billing تضمین‌شده نیست.
- جمع‌زدن شمارنده‌های WAN و LAN می‌تواند یک ترافیک را دوبار بشمارد؛ داشبورد جهت هر Interface را جدا نگه می‌دارد.
- استفاده از فلش USB ارزان برای نوشتن دائمی تضمین عمر ندارد. retention و checkpoint محافظه‌کارانه‌اند، اما SSD مناسب مطمئن‌تر است.
- نام Interfaceها، شبکه‌های LAN و route commentها باید دقیقاً با تنظیمات همان روتر هماهنگ شوند.

## نکات امنیتی

- API، داشبورد و IPFIX را از اینترنت منتشر نکنید.
- برای collector کاربر جداگانه با `read,api` و محدودیت IP بسازید.
- رمزها را فقط در RouterOS environment یا `.env` محلی نگه دارید.
- قبل از هر push، خروجی `git status` و `git diff --cached` را بررسی کنید.
- جزئیات بیشتر در [SECURITY.md](SECURITY.md) آمده است.
