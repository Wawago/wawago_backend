try:
    from .settings import *
except:
    pass

DEBUG = False


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/home/ella/conf/wawago_backend_mysql.conf',
        },
    }
}