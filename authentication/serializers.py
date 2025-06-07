from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # Increment the user's token version on each login
        user.token_version += 1
        user.save(update_fields=['token_version'])

        # Generate the token with the standard method
        token = super().get_token(user)

        # Add the token version to the payload
        token['token_version'] = user.token_version

        # Add your other custom claims
        token['username'] = user.get_username()
        token['account_type'] = user.role

        return token