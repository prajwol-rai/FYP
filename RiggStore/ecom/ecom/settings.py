

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure--nx@i2h&s8pevedk035)o1z0e205o62%glp@!8c$d#dzv_0-1='

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'riggstore',
    
    'users',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',  # Enables session support
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Manages user authentication via sessions
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

ROOT_URLCONF = 'ecom.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'riggstore.context_processors.cart_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'ecom.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]




# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = ['static/']
MEDIA_URL = 'media/'
MEDIA_ROOT = os.path.join(BASE_DIR,'media')

LOGIN_URL = '/login/'

ALLOWED_HOSTS = ['*']

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'riggstore.team@gmail.com'  
EMAIL_HOST_PASSWORD = 'myst ztbn hojt kzgh'  


STRIPE_PUBLIC_KEY = 'pk_test_51R80bEQ3t66hyN8808foRjbhHIh7SHskOgSNC8DFznlBsdDBAye8OSuwE10jZAnB8m5yYGJCTye2kCpIEJHVZ4Wt00b7ewK4oa'
STRIPE_SECRET_KEY = 'sk_test_51R80bEQ3t66hyN88K80k0nYmsr5KuUgHFK3mW2lxLhrR0TxZnXhdrgN2qIcyRK8BhTSZMROHT0epjt9dvoPb3JL500cZul03kb'



CSRF_TRUSTED_ORIGINS = [
    "https://c8ae-103-41-173-36.ngrok-free.app",
    "http://c8ae-103-41-173-36.ngrok-free.app"
]

STRIPE_WEBHOOK_SECRET= 'whsec_yUjYdMlYs1Z9rkufeShrn4jDmadT6EDX'


SITE_URL = "https://c8ae-103-41-173-36.ngrok-free.app"
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CORS_ALLOWED_ORIGINS = [
    "https://c8ae-103-41-173-36.ngrok-free.app",
    "http://c8ae-103-41-173-36.ngrok-free.app"
]


STRIPE_SUCCESS_URL = f"{SITE_URL}/payment-success/"
STRIPE_CANCEL_URL = f"{SITE_URL}/cart/"



KHALTI_SECRET_KEY = '3e2fd15e6d074033a23de0f715ea26fd' 
SITE_URL = "http://127.0.0.1:8000"