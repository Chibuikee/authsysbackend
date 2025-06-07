from datetime import datetime
from http import HTTPStatus

from rest_framework.serializers import ValidationError
from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status



def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)


    if response is not None:
        error_message = response.get('detail',"")
        if isinstance(exc, ValidationError):
            custom_errors = []
            errors = response.data
            for field, message in errors.items():
                print(f"{field} - {message[0]}")
                error_message = ""
                if isinstance(message, dict):
                    # process message
                    error_message = f"{field}: {message[0]}"
                elif isinstance(message, list):
                    # process message
                    error_message = f"{field}: {message[0]}"
                elif isinstance(message, str):
                    # process message
                    error_message = f"{field}: {message}"

                custom_errors.append(error_message)
            error_message = custom_errors

        if not error_message:
            error_message = response.data.get("detail","")
        error_payload = {"status_code": response.status_code,
                         "message": "",
                         "errors": error_message,
                         'time': datetime.now(),
                         'data': None}

        #  error = error_payload["error"]

        response.data = error_payload
    return response

class BadRequestException(APIException):
    detail = None
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, detail):
        super().__init__(detail, status.HTTP_400_BAD_REQUEST)
