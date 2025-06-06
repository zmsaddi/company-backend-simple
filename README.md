# نظام إدارة الشركة - Backend

نظام إدارة شركة متكامل وبسيط مبني بـ Flask يوفر APIs لإدارة الموظفين والمخزون.

## المميزات

- 🔐 نظام مصادقة آمن مع JWT
- 👥 إدارة الموظفين
- 📦 إدارة المخزون
- 📊 لوحة تحكم مع إحصائيات
- 🌐 دعم CORS للتكامل مع Frontend
- 💾 قاعدة بيانات في الذاكرة (للعرض التوضيحي)

## التثبيت والتشغيل

```bash
# تفعيل البيئة الافتراضية
source venv/bin/activate

# تشغيل الخادم
python src/main.py
```

## APIs المتاحة

### المصادقة
- `POST /api/auth/login` - تسجيل الدخول

### لوحة التحكم
- `GET /api/dashboard/stats` - إحصائيات النظام

### الموظفين
- `GET /api/employees` - جلب قائمة الموظفين
- `POST /api/employees` - إضافة موظف جديد

### المخزون
- `GET /api/inventory` - جلب قائمة المخزون
- `POST /api/inventory` - إضافة عنصر جديد للمخزون

### الصحة
- `GET /api/health` - فحص حالة الخادم

## بيانات تسجيل الدخول الافتراضية

```
البريد الإلكتروني: admin@company.com
كلمة المرور: admin123
```

## التقنيات المستخدمة

- Flask
- Flask-JWT-Extended
- Flask-CORS
- Python 3.11

## الإعداد للإنتاج

يمكن نشر هذا Backend على أي منصة تدعم Python مثل:
- Railway
- Heroku
- Vercel
- DigitalOcean

تأكد من تحديث متغيرات البيئة:
- `SECRET_KEY`
- `JWT_SECRET_KEY`

