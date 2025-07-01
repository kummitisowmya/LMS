from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    UserProfileView,
    VerifyEmailView,
    GoogleLoginView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    RequestEmailOTPView,
    VerifyEmailOTPView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("verify-email/<uidb64>/<token>/", VerifyEmailView.as_view(), name="verify-email"),
    path("google-login/", GoogleLoginView.as_view(), name="google-login"),
    path("reset-password/", PasswordResetRequestView.as_view(), name="reset-password"),
    path("reset-password-confirm/", PasswordResetConfirmView.as_view(), name="reset-password-confirm"),
    path("request-otp/", RequestEmailOTPView.as_view(), name="request-otp"),
    path("verify-otp/", VerifyEmailOTPView.as_view(), name="verify-otp"),
]
