from django.shortcuts import render,redirect
# authentication/views.py
from rest_framework import generics, status,permissions
from rest_framework.response import Response
from registerapp.models import CustomUser
from registerapp.serializers import RegistrationSerializer,LoginSerializer,PasswordResetSerializer
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from rest_framework.views import APIView

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetView as BasePasswordResetView
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.generics import CreateAPIView
from django.contrib.auth.forms import PasswordResetForm



class RegistrationAPIView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        send_mail(
            'Account Confirmation',
            'Thank you for registering.',
            'from@example.com',
            [serializer.validated_data['email']],
            fail_silently=False,
        )

        headers = self.get_success_headers(serializer.data)

        return redirect(registration)
        # return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

def registration(request):
    return render(request, "registration.html")


class LoginAPIView(APIView):
    serializer_class = LoginSerializer

    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #
    #     user = authenticate(request, email=serializer.validated_data['email'], password=serializer.validated_data['password'])
    #
    #     if user:
    #         login(request, user)
    #         return Response({'detail': 'Login successful.'}, status=status.HTTP_200_OK)
    #     else:
    #         return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


    permission_classes = [permissions.AllowAny]


    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)

        if user:
            login(request, user)
            return Response({'detail': 'Login successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


# class PasswordResetAPIView(generics.CreateAPIView):
#     serializer_class = PasswordResetSerializer
#
#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#
#         # Find the user with the provided email
#         try:
#             user = CustomUser.objects.get(email=serializer.validated_data['email'])
#         except CustomUser.DoesNotExist:
#             return Response({'detail': 'No account found with this email address.'}, status=status.HTTP_404_NOT_FOUND)
#
#         # Send password reset email
#         self.send_password_reset_email(user)
#
#         return Response({'detail': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)
#
#     def send_password_reset_email(self, user):
#         # Add your email sending logic here
#         subject = 'Password Reset'
#         message = f'Click the following link to reset your password: {self.get_reset_password_url(user)}'
#         send_mail(subject, message, 'from@example.com', [user.email], fail_silently=False)
#
#     def get_reset_password_url(self, user):
#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#         token = default_token_generator.make_token(user)
#         return reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

class PasswordResetAPIView(CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        form = PasswordResetForm({'email': email})

        if form.is_valid():
            form.save(request=request)

            return Response({'detail': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid email address.'}, status=status.HTTP_400_BAD_REQUEST)

