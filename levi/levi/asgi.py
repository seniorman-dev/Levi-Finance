"""
ASGI config for levi project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
import django
from django.core.asgi import get_asgi_application
from socketio import ASGIApp
import socketio

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'levi.settings')
django.setup()  # make sure Django apps are loaded first

# Import AFTER setup
from myapp.socket_handlers import sio  # ✅ now safe

django_asgi_app = get_asgi_application()

#for websocket (socket.io) config
application = socketio.ASGIApp(sio, django_asgi_app, socketio_path="socket.io")












