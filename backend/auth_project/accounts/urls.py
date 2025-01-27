from django.urls import path
from .views import register, login, password_reset_request, password_reset_confirm

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('password-reset/', password_reset_request, name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         password_reset_confirm, name='password_reset_confirm'),
    # Add password reset endpoints
]
