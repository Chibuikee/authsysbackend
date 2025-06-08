import logging
import os
import socket
import ssl
import threading
from smtplib import SMTPException

from django.conf import settings
from django.core.mail import EmailMessage, send_mail
from django.template import Context
from django.template.loader import get_template, render_to_string
from django.utils.html import strip_tags
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User

logger = logging.getLogger(__name__)


class EmailThread(threading.Thread):
    """
    Thread for sending emails asynchronously to prevent API requests
    from being blocked waiting for email sending to complete.
    """

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        """
        Send the email in a separate thread and catch any exceptions
        to prevent thread crashes.
        """
        try:
            self.email.send(fail_silently=False)
            logger.info(f"Email sent successfully to {', '.join(self.email.to)}")
        except SMTPException as e:
            logger.error(
                f"SMTP error when sending email to {', '.join(self.email.to)}: {str(e)}"
            )
        except (socket.error, ssl.SSLError) as e:
            # Combined since SSLError is a subclass of OSError (like socket.error)
            logger.error(
                f"Network/SSL error when sending email to {', '.join(self.email.to)}: {str(e)}"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error when sending email to {', '.join(self.email.to)}: {str(e)}"
            )


class AuthMailEngine:
    """
    Email service for authentication-related communications.
    Handles templating, sending, and error handling for all auth emails.
    """

    def __init__(self, User: User):
        """
        Initialize the mail engine with a user and common email settings.

        Args:
            User: The user model instance to send emails to
        """
        self.User = User
        self.front_end_url = settings.FRONT_END_URL
        self.subject = ""
        self.email_from = settings.EMAIL_HOST_USER
        self.recipient_list = []
        # Log initialization for debugging
        logger.debug(f"AuthMailEngine initialized for user: {User.email}")

    def send_confirmation_email(self):
        """
        Send an email confirmation link to a newly registered user.
        Uses JWT token for secure verification.
        """
        try:
            BASE_URL = settings.FRONT_END_URL
            token = RefreshToken.for_user(self.User).access_token

            # Construct confirmation URL
            # http://localhost:3000/auth/verify-email?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
            # full_url = os.path.join(BASE_URL, "confirm-account")
            full_url = f"{"https://authsysdemo.vercel.app"}/verifyemail"
            # full_url = f"{BASE_URL}/verify-email"
            token_url = f"{full_url}/?token={token}"

            logger.info(f"Sending confirmation email to {self.User.email}")

            self.subject = "Confirm your email"
            context = {
                "link": token_url,
                "user": self.User.full_name,  # Add user name to context
            }

            self.message = self.render_html("email_confirmation.html", context)
            self.recipient_list = [
                self.User.email,
            ]

            self.send_mail()
            logger.info(f"Confirmation email queued for {self.User.email}")

        except Exception as e:
            logger.error(
                f"Error preparing confirmation email for {self.User.email}: {str(e)}"
            )
            raise

    @staticmethod
    def render_html(template_name, context):
        """
        Render an HTML email template with the given context.
        """
        try:
            template = get_template(template_name)
            message = template.render(context)
            return message
        except Exception as e:
            logger.error(f"Error rendering email template {template_name}: {str(e)}")
            logger.error(f"Template search path: {settings.TEMPLATES}")
            # Fall back to a simple message if template rendering fails
            return f"Please visit: {context.get('link', 'the website')} to complete your request."

    # def render_html(template_name, context):
    #     """
    #     Render an HTML email template with the given context.

    #     Args:
    #         template_name: The template file name
    #         context: Dictionary of variables to pass to the template

    #     Returns:
    #         str: Rendered HTML content
    #     """
    #     try:
    #         message = get_template(template_name).render(context)
    #         return message
    #     except Exception as e:
    #         logger.error(f"Error rendering email template {template_name}: {str(e)}")
    #         # Fall back to a simple message if template rendering fails
    #         return f"Please visit: {context.get('link', 'the website')} to complete your request."

    def send_mail(self):
        """
        Send an email with the configured subject, message and recipients.
        Uses threaded sending to avoid blocking the request.
        """
        mail_details = f"recipient:{self.recipient_list}," f"from:{self.email_from}"

        try:
            logger.info(f"Preparing to send mail: {mail_details}")

            email = EmailMessage(
                subject=self.subject,
                body=self.message,
                from_email=self.email_from,
                # to=["sopewenike@gmail.com"],
                to=self.recipient_list,
            )
            email.content_subtype = "html"

            # Use threading to send email asynchronously
            EmailThread(email).start()

            return True

        except SMTPException as e:
            logger.error(f"SMTP error sending email to {self.recipient_list}: {str(e)}")
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error sending email to {self.recipient_list}: {str(e)}"
            )
            return False
