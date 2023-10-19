from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.pagination import LimitOffsetPagination
from .serializers import (RegisterSerializer, ChangePasswordSerializer, UpdateUserSerializer, ListUserSerializer,
                          InviteUserSerializer, ForgotPasswordSerializer, ResetPasswordSerializer)
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework import generics
from user.models import User
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.authtoken.models import Token

sensitive_post_method = sensitive_post_parameters('password', 'password2')

@method_decorator(sensitive_post_method, name='dispatch')
class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'username': user.username,
                         'first_name': user.first_name, 'last_name': user.last_name,
                         'is_superuser': user.is_superuser, 'id': user.id})


@method_decorator(sensitive_post_method, name='dispatch')
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    # def post(self, request, *args, **kwargs):
    #     res = self.create(request, *args, **kwargs)
    #     # token, created = Token.objects.get_or_create(user=res.data)
    #     # res.data['token'] = token.key
    #     return res


class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer


class UpdateProfileView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateUserSerializer


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)
    serializer_class = ListUserSerializer
    pagination_class = LimitOffsetPagination


class InviteUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated, IsAdminUser)
    serializer_class = InviteUserSerializer


class ForgotPassword(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password reset link has been sent to your inbox.'})


sensitive_post_method = sensitive_post_parameters('new_password', 'confirm_password')


@method_decorator(sensitive_post_method, name='dispatch')
class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.reset_password()
        return Response({'message': 'Your password has been reset.'})

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['url_params'] = self.kwargs
        return context
