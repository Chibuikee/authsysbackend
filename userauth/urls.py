from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView

from . import views
from .views import (
    ConfirmAccountView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    SignUpView,
)

urlpatterns = [
    path("sign-up", SignUpView.as_view(), name="sign-up"),
    # path("sign-up", views.sign_up, name="sign-up"),
    # Use custom throttled views for login and token refresh
    path("login", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    # path('token/refresh', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path("token/refresh", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify", TokenVerifyView.as_view(), name="token_verify"),
    path("confirm-account", ConfirmAccountView.as_view(), name="confirm-account"),
    # path("confirm-account", views.confirm_account, name="confirm-account"),
    path("users/<str:id>", views.get_user_info, name="user-info"),
]
