import jwt
from rest_framework.exceptions import ValidationError


def decode_token(token: str):
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except jwt.ExpiredSignatureError as error:
        raise ValidationError({"token": "Expired token"})
    except jwt.exceptions.DecodeError as error:
        raise ValidationError({"token": "Invalid token"})
