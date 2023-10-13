from django.urls import path
from user.views import RegisterView, ChangePasswordView, UpdateProfileView, UserListView, LoginView
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView


urlpatterns = [
    path('login/', LoginView.as_view(), name="login"),
    path('register/', RegisterView.as_view(), name='user_register'),
    path('change/password/<int:pk>/', ChangePasswordView.as_view(), name='user_change_password'),
    path('update/profile/<int:pk>/', UpdateProfileView.as_view(), name='user_update_profile'),
    path('list/', UserListView.as_view(), name="user_list"),
    # path('logout/', LogoutView.as_view(), name='user_logout'),
]

