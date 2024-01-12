# from django.shortcuts import render,redirect
from rest_framework import generics, status,permissions
# from rest_framework.response import Response
# # from registerapp.serializers import RegistrationSerializer,LoginSerializer,PasswordResetSerializer
# from django.contrib.auth import authenticate, login
# from django.core.mail import send_mail
# from rest_framework.views import APIView


from django.shortcuts import render,redirect
from registerapp.serializers import CustomUserSerializer,PasswordResetSerializer
from  rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from  registerapp.models import CustomUser

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.contrib.auth.password_validation import validate_password
from  registration import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

# Create your views here.

class RegistrationAPIView(APIView):
    def post(self,re):
        obj=CustomUserSerializer(data=re.data)
        obj.is_valid(raise_exception=True)
        obj.save()
        subject = f"You have successfully registered"
        message = f"Please login to your Account"
        from_mail = settings.EMAIL_HOST_USER
        to_list = [re.data['email']]
        send_mail(subject, message, from_mail, to_list, fail_silently=True)
        return redirect(registration)


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = CustomUser.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found.')

        if not user.check_password(password):
            raise AuthenticationFailed('Invalid password.')

        # If email and password are valid, generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'message': 'success',
            'access_token': access_token
        })
def registration(request):
    return render(request, "registration.html")


# class LoginAPIView(APIView):
#     permission_classes = [permissions.AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         email = request.data.get('email')
#         password = request.data.get('password')
#
#         user = authenticate(request, email=email, password=password)
#
#         if user:
#             login(request, user)
#             return Response({'detail': 'Login successful.'}, status=status.HTTP_200_OK)
#         else:
#             return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class PasswordResetAPIView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(request)
        return Response({'detail': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomUserSerializer
