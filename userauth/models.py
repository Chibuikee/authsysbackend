import datetime
import random
import secrets
import string
import uuid
from typing import Literal

from authentication.abstract_models import AbstractDateTime
from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError


class User(AbstractUser):
    # class Meta:
    #     db_table = "auth_user"

    class roles(models.TextChoices):
        SENIOR = "SENIOR", "Senior"
        JUNIOR = (
            "JUNIOR",
            "Junior",
        )

    user_id = models.UUIDField(
        # primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )
    is_active = models.BooleanField(
        default=True,
        help_text=(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    is_confirmed = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    token_version = models.IntegerField(default=0)
    phone = models.CharField(max_length=20, null=True, blank=True, unique=True)

    username = None
    first_name = None
    last_name = None
    email = models.EmailField(blank=False, unique=True)
    full_name = models.CharField(max_length=100)
    role = models.CharField(max_length=20, choices=roles.choices)
    unique_id = models.CharField(max_length=10, blank=True, unique=True)
    REQUIRED_FIELDS = []
    USERNAME_FIELD = "email"

    token_version = models.IntegerField(default=0)

    deletion_scheduled_at = models.DateTimeField(null=True, blank=True)

    def cancel_deletion(self):
        """Cancel a scheduled account deletion"""
        self.deletion_scheduled_at = None
        self.is_active = True
        self.save()

    def complete_deletion(self):
        """Complete the deletion process after the grace period"""
        self.is_deleted = True
        self.is_active = False
        self.email = f"deleted_{self.id}@example.com"  # Anonymize email
        self.full_name = "Deleted User"  # Anonymize name
        self.set_unusable_password()  # Disable the password
        self.save()

    # Added Custom user manager class
    class CustomUserManager(BaseUserManager):
        def create_user(self, email, password=None, **extra_fields):
            """
            Creates and saves a User with the given email and password.
            """
            if not email:
                raise ValueError("Users must have an email address")

            email = self.normalize_email(email)
            user = self.model(email=email, **extra_fields)
            user.set_password(password)
            user.save(using=self._db)
            return user

        def create_superuser(self, email, password=None, **extra_fields):
            """
            Creates and saves a superuser with the given email and password.
            """
            extra_fields.setdefault("is_staff", True)
            extra_fields.setdefault("is_superuser", True)
            extra_fields.setdefault("is_active", True)

            return self.create_user(email, password, **extra_fields)

    objects = CustomUserManager()

    # def create_unique_id(self):
    #     length = 6
    #     while True:
    #         suffix = "".join(random.choices(string.digits, k=length))

    #         prefix = self.role[:3]
    #         code = f"{prefix}-{suffix}"
    #         if not User.objects.filter(unique_id=code).exists():
    #             return code

    # def save(self, *args, **kwargs):
    #     if not self.unique_id:
    #         with transaction.atomic():  # Ensures atomicity
    #             self.unique_id = self.create_unique_id()
    #             while User.objects.filter(unique_id=self.unique_id).exists():
    #                 self.unique_id = self.create_unique_id()
    #     super().save(*args, **kwargs)

    def create_unique_id(self):
        length = 6
        prefix = self.role[:3].upper()  # Ensure consistent casing
        while True:
            suffix = "".join(random.choices(string.digits, k=length))
            code = f"{prefix}-{suffix}"
            if not User.objects.filter(unique_id=code).exists():
                return code

    def save(self, *args, **kwargs):
        if not self.unique_id:
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    with transaction.atomic():
                        self.unique_id = self.create_unique_id()
                        super().save(*args, **kwargs)
                        break
                except IntegrityError:
                    if attempt == max_retries - 1:
                        raise RuntimeError(
                            f"Failed to generate unique ID after {attempt} retries"
                        )
                    continue
        else:
            super().save(*args, **kwargs)

    def reset_password(self, password):
        self.set_password(raw_password=password)
        self.save()

    @staticmethod
    def get_role_list():
        role_list = [role[0] for role in User.roles.choices]
        return role_list

    def activate_account(self):
        if self.is_confirmed:
            raise ValidationError({"token": "Account is already confirmed"})
        self.is_confirmed = True
        self.save()


class Junior(User):
    class Meta:
        proxy = True

    def save(self, *args, **kwargs):
        if not self.pk:
            self.role = self.roles.JUNIOR
        return super().save(*args, **kwargs)


class Senior(User):
    class Meta:
        proxy = True

    def save(self, *args, **kwargs):
        if not self.pk:
            self.role = self.roles.SENIOR
        return super().save(*args, **kwargs)


class Token(AbstractDateTime):
    class TOKEN_TYPES(models.TextChoices):
        PASSWORD_RESET = "PASSWORD RESET", "password_reset"
        ACCOUNT_DELETION = "ACCOUNT DELETION", "account_deletion"

    id = models.AutoField(primary_key=True)
    token = models.CharField(max_length=150)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    type = models.CharField(max_length=50, choices=TOKEN_TYPES.choices)
    value = models.CharField(max_length=50, null=True)

    @staticmethod
    def generate_token():
        """Generate a secure random token for authentication purposes"""
        return secrets.token_hex(14)

    def is_valid(self):
        """
        Check if the token is still valid based on its creation time
        Returns True if token is valid, False if expired
        """
        otp_expiry = self.date_created + datetime.timedelta(
            minutes=int(settings.TOKEN_EXPIRY)
        )
        curr_time = timezone.now()

        if curr_time > otp_expiry:
            return False  # Token has expired
        return True  # Token is still valid

    @classmethod
    def cleanup_expired_tokens(cls):
        """
        Remove all expired tokens from the database.
        This helps keep the database clean and improves query performance.
        Should be called periodically via a scheduled task.
        """
        current_time = timezone.now()
        expired_count = 0

        # Get all tokens
        for token in cls.objects.all():
            # Check if token is expired
            if not token.is_valid():
                token.delete()
                expired_count += 1

        return expired_count
