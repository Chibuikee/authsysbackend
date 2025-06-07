import json
import logging

from django.conf import settings
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404

from .mail_service import AuthMailEngine
from .models import User

logger = logging.getLogger(__name__)


def get_user_by_id(id):
    return get_object_or_404(User, pk=id)


def get_user_by_email(email):
    return get_object_or_404(User, email=email)


@transaction.atomic()
def create_user(
    user_id,
    full_name,
    password,
    role,
    phone,
):
    try:
        new_user: User = User.objects.create(
            email=user_id,
            full_name=full_name,
            role=role,
            phone=phone,
        )

        new_user.set_password(password)
        new_user.save()

        AuthMailEngine(new_user).send_confirmation_email()
        return new_user
    except IntegrityError as e:
        # if "phone" in str(e):
        #     raise ValueError("This phone number is already in use.")
        raise
