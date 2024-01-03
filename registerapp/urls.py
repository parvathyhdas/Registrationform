from django.urls import path
from registerapp.views import RegistrationAPIView
from registerapp.views import LoginAPIView,PasswordResetAPIView
from registerapp import views

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('registrationPage/', views.registration, name='registrationPage'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('passwordreset/', PasswordResetAPIView.as_view(), name='passwordreset'),

]