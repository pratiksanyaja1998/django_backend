from django.urls import path
from user.views import RegisterView, ChangePasswordView, UpdateProfileView, LogoutView, LogoutAllView, LoginView
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from rest_framework.usertoken.views import obtain_user_token


urlpatterns = [
    path('login/', LoginView.as_view(), name="login"),
    # path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='user_register'),
    path('change/password/<int:pk>/', ChangePasswordView.as_view(), name='user_change_password'),
    path('update/profile/<int:pk>/', UpdateProfileView.as_view(), name='user_update_profile'),
    # path('user/list/', UserListView.as_view(), name="user_list"),
    # path('logout/', LogoutView.as_view(), name='user_logout'),
    # path('logout_all/', LogoutAllView.as_view(), name='user_logout_all'),
]

