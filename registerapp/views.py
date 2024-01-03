from django.shortcuts import render,redirect
from rest_framework import generics, status,permissions
from rest_framework.response import Response
from registerapp.serializers import RegistrationSerializer,LoginSerializer,PasswordResetSerializer
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail


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

        # return redirect(registration)
        # return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        return Response({'msg':'Registration Successful'},status=status.HTTP_201_CREATED)
def registration(request):
    return render(request, "registration.html")


class LoginAPIView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(request, email=serializer.validated_data['email'], password=serializer.validated_data['password'])

        if user:
            login(request, user)
            return Response({'detail': 'Login successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


class PasswordResetAPIView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(request)
        return Response({'detail': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)



