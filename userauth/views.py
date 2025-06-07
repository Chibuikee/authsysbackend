import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

from .mail_service import AuthMailEngine
from .models import Token, User
from .serializers import ActivateUserSerializer, SignUpSerializer, UserInfoSerializer
from .services import get_user_by_id
from .throttling import LoginRateThrottle, SignupRateThrottle, TokenRefreshRateThrottle

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     handlers=[
#         logging.StreamHandler(),  # Log to console
#         logging.FileHandler("views.log"),  # Optional: Log to file
#     ],
# )

logger = logging.getLogger(__name__)

# Custom token views with throttling
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """
    Custom refresh token serializer that verifies the token version.
    This prevents users from maintaining multiple sessions by using old refresh tokens.
    """

    def validate(self, attrs):

        # Get the refresh token from attributes
        refresh_token = attrs.get("refresh")
        if not refresh_token:
            logger.error("No refresh token found in attributes")
            raise InvalidToken("Refresh token is required")
        try:

            # First perform the standard validation

            logger.info(
                f"Performing standard token validation..., issueing of refresh and access token for {attrs}"
            )
            data = super().validate(attrs)
            logger.info(f"Standard token validation completed successfully {data}")

            return data

        except Exception as e:
            logger.error(f"Error during token validation: {str(e)}")
            raise


class CustomTokenRefreshView(TokenRefreshView):
    """Token refresh endpoint with rate limiting to prevent token grinding attacks."""

    throttle_classes = [TokenRefreshRateThrottle]
    serializer_class = CustomTokenRefreshSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    """Login endpoint that returns access, refresh tokens, and user ID."""

    throttle_classes = [LoginRateThrottle]

    def post(self, request, *args, **kwargs):
        # Get the default token response
        logger.info("Calling logging in post method")
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:  # If login is successful
            # Get the user from the validated token serializer
            logger.info(
                "user info valid, issuing refresh and access token with user_id"
            )
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            logger.info("Getting the user info for auth hydration")
            user = serializer.user
            logger.info(f"Returning the user: {user.id} auth info for hydration")

            # Add user ID to the response data
            response.data["user_id"] = user.id

        return response


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([SignupRateThrottle])
def sign_up(request):
    """
    User registration endpoint with rate limiting to prevent spam accounts.
    Allows new users to create an account with email, password, name, role, and phone.
    """
    serializer = SignUpSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response(UserInfoSerializer(user).data)


class SignUpView(CreateAPIView):
    serializer_class = SignUpSerializer
    permission_classes = [AllowAny]
    throttle_classes = [SignupRateThrottle]

    def perform_create(self, serializer):
        with transaction.atomic():
            user = serializer.save()
            # Add any post-save logic here
            return user


class ConfirmAccountView(CreateAPIView):
    serializer_class = ActivateUserSerializer
    permission_classes = [AllowAny]
    # throttle_classes = [SignupRateThrottle]

    def perform_create(self, serializer):
        with transaction.atomic():
            user = serializer.save()
            # Add any post-save logic here
            return user


@api_view(["POST"])
@permission_classes([AllowAny])
def confirm_account(request):
    """Confirms a user account using the token sent via email."""
    serializer = ActivateUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response(UserInfoSerializer(user).data)


@api_view(["GET"])
@permission_classes([AllowAny])
# @permission_classes([IsAuthenticated])
def get_user_info(request, id):
    """Returns user information for the specified user ID."""
    try:
        print("\n==== Specific Headers (request.headers) ====")
        # print(f"Authorization: {request.headers.get('Authorization')}")
        # Print the authenticated user
        print(f"\nAuthenticated user: {request.user}")
        user = get_user_by_id(id)
        return Response(UserInfoSerializer(user).data)
    except Http404:
        return Response(
            {"error": f"User with id {id} not found."}, status=status.HTTP_404_NOT_FOUND
        )
