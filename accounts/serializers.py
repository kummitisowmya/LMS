from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.core.mail import EmailMessage
import requests
from datetime import timedelta
import random
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import User

User = get_user_model()

#User Profile Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "mobile_number",
            "date_of_birth",
            "role",
            "date_joined",
        ]

#Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "confirm_password",
            "first_name",
            "last_name",
            "mobile_number",
            "date_of_birth",
            "role"
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")

        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            mobile_number=validated_data.get("mobile_number", ""),
            date_of_birth=validated_data.get("date_of_birth"),
            role=validated_data.get("role", "student"),
            is_active=False  # Require email verification
        )

        # Email Verification
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        verify_url = f"https://yourdomain.com/verify-email/{uid}/{token}/"

        subject = "Verify Your Email - LMS"
        message = f"""
        Hi {user.first_name},
        Thank you for registering with LMS.
        Please verify your email address by clicking the link below:
        {verify_url}
        If you didn't request this, you can ignore this email.
        Regards,  
        LMS Team
        """
        email = EmailMessage(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        email.send(fail_silently=False)
        return user

# Login Serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_active:
            raise serializers.ValidationError("Email not verified. Please check your inbox.")

        return user

# JWT Token Serializer
class TokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()

    def validate(self, data):
        user = self.context["user"]
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }

# Google Sign-In Serializer
class GoogleAuthSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, data):
        token = data.get("token")
        response = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={token}")
        if response.status_code != 200:
            raise serializers.ValidationError("Invalid Google token")

        user_info = response.json()
        email = user_info.get("email")
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")

        user, created = User.objects.get_or_create(email=email, defaults={
            "first_name": first_name,
            "last_name": last_name,
            "is_active": True,
            "role": "student"
        })

        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

# Password Reset Request Serializer
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user with this email.")
        return value

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        reset_url = f"https://yourdomain.com/reset-password/{uid}/{token}/"

        subject = "Reset Your Password - LMS"
        message = f"""
        Hi {user.first_name},
        We received a request to reset your password.
        Click the link below to set a new password:
        {reset_url}
        If you did not make this request, you can ignore this email.
        Regards,  
        LMS Team
        """
        email = EmailMessage(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        email.send(fail_silently=False)

#Password Reset Confirm Serializer
class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=6, write_only=True)

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data["uidb64"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user.")

        if not token_generator.check_token(user, data["token"]):
            raise serializers.ValidationError("Invalid or expired token.")

        self.user = user
        return data

    def save(self):
        password = self.validated_data["new_password"]
        self.user.set_password(password)
        self.user.save()


# serializers.py
class EmailOTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("No user with this email.")
        return email

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)

        otp = f"{random.randint(100000, 999999)}"
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        send_mail(
            "Your OTP Code",
            f"Your login OTP is: {otp}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

class EmailOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or OTP.")

        # Optional: Check OTP expiry (e.g., 10 min)
        if not user.otp or user.otp != data["otp"]:
            raise serializers.ValidationError("Invalid OTP.")
        if timezone.now() - user.otp_created_at > timedelta(minutes=10):
            raise serializers.ValidationError("OTP has expired.")

        self.user = user
        return data

    def create(self, validated_data):
        from rest_framework_simplejwt.tokens import RefreshToken

        user = self.user
        user.otp = None
        user.otp_created_at = None
        user.save()

        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
