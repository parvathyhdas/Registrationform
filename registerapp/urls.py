from django.urls import path
from registerapp.views import RegistrationAPIView, CustomTokenObtainPairView
from registerapp.views import LoginAPIView,PasswordResetAPIView
from registerapp import views
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth.views import PasswordResetCompleteView
from django.contrib.auth.views import PasswordResetDoneView

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('registrationPage/', views.registration, name='registrationPage'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('password_reset/', PasswordResetAPIView.as_view(), name='password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset_complete/', PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('password_reset_done/', PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair')

]