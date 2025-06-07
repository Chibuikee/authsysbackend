import logging

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Token, User
from .services import create_user, get_user_by_email, get_user_by_id
from .utils import decode_token

logger = logging.getLogger(__name__)


class UserInfoSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "unique_id",
            "is_confirmed",
            "is_active",
            "full_name",
            "email",
            "phone",
        ]


class ActivateUserSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        payload = decode_token(attrs.get("token"))
        user = get_user_by_id(payload["user_id"])
        attrs["user"] = user
        return super().validate(attrs)

    def create(self, validated_data):
        user = validated_data["user"]
        user.activate_account()
        return user

    def to_representation(self, instance):
        # Custom response to prevent django from trying to serialize the User object
        return {
            "message": "Account activated successfully",
            "user_id": str(instance.user_id),
            "email": instance.email,
            "is_confirmed": instance.is_confirmed,
        }


class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    role = serializers.CharField(required=True)
    phone = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )

    class Meta:
        model = User
        fields = [
            "email",
            "full_name",
            "password",
            # "areas",
            "role",
            "confirm_password",
            "phone",
        ]

    def validate(self, attrs):
        if attrs.get("role") not in User.get_role_list():
            roles = ", ".join(User.get_role_list())
            raise serializers.ValidationError(
                {"type": f"invalid role {attrs.get('role')}, role should be {roles}"}
            )

        validate_password(attrs.get("password"))

        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError({"password": "passwords do not match"})

        return super().validate(attrs)

    def create(self, validated_data):
        return create_user(
            user_id=validated_data["email"],
            password=validated_data["password"],
            full_name=validated_data["full_name"],
            role=validated_data["role"],
            # areas=validated_data["areas"],
            phone=validated_data["phone"],
        )


class UpdateUserInfoSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(
        required=False,
        allow_null=True,
        allow_blank=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )
    read_only_fields = ["user_id"]  # This makes the field non-editable

    class Meta:
        model = settings.AUTH_USER_MODEL
        fields = ["full_name", "email", "phone"]

    def validate_phone(self, value):
        if (
            value
            and User.objects.filter(phone=value)
            .exclude(user_id=self.instance.user_id)
            .exists()
        ):
            raise serializers.ValidationError("This phone number is already in use.")
        return value


class VerifyLawyerSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def create(self, validated_data):
        user = User.objects.filter(email=validated_data["email"]).first()

        user.save()
        return user


class AccountDeletionSerializer(serializers.Serializer):
    """
    Serializer for account deletion requests.
    Requires email and password verification for security.
    """

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        user = self.context["request"].user
        password = attrs.get("password")

        # Verify password
        if not user.check_password(password):
            raise serializers.ValidationError(
                {"password": "Current password is incorrect"}
            )

        return attrs


# class UnboardSerializer(serializers.Serializer):
#     email = serializers.EmailField(required=True)

#     def validate(self, attrs):
#         user = get_user_by_email(attrs.get("email"))
#         info = attrs.get("info")
#         for info_type, info_names in info:
#             add_user_onboarding_info(
#                 user=user, info_names=info_names, info_type=info_type
#             )
