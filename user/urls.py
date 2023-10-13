from django.urls import path
from user.views import RegisterView, ChangePasswordView, UpdateProfileView, LogoutView, LogoutAllView, LoginView
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from rest_framework.authtoken.views import obtain_auth_token


urlpatterns = [
    path('login/', LoginView.as_view(), name="login"),
    # path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('change/password/<int:pk>/', ChangePasswordView.as_view(), name='auth_change_password'),
    path('update/profile/<int:pk>/', UpdateProfileView.as_view(), name='auth_update_profile'),
    # path()
    # path('logout/', LogoutView.as_view(), name='auth_logout'),
    # path('logout_all/', LogoutAllView.as_view(), name='auth_logout_all'),
]

