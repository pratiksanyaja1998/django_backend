from django.urls import path, re_path
from user.views import (RegisterView, ChangePasswordView, UpdateProfileView, UserListView, LoginView, InviteUserView,
                        ForgotPassword, ResetPassword)
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView


urlpatterns = [
    path('login/', LoginView.as_view(), name="login"),
    path('register/', RegisterView.as_view(), name='user_register'),
    path('change/password/<int:pk>/', ChangePasswordView.as_view(), name='user_change_password'),
    path('update/profile/<int:pk>/', UpdateProfileView.as_view(), name='user_update_profile'),
    path('list/', UserListView.as_view(), name="user_list"),
    path('invite/', InviteUserView.as_view(), name="user_invite"),
    # path('logout/', LogoutView.as_view(), name='user_logout'),

    path('forgot-password', ForgotPassword.as_view(), name='forgot-password'),
    re_path(r'^reset-password/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z\-]+)$', ResetPassword.as_view(),
            name='reset-password'),
]

