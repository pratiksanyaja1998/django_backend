from urllib import request
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth import get_user_model
from django.conf import settings
from threading import Thread
import logging
from user.models import User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template

admins_logger = logging.getLogger('admins')


def send_account_email(user, email_type='activation'):
    """
    Google Mail doesn't support too many requests at a time. Try alternative in case of
    massive concurrent emails
    https://stackoverflow.com/questions/39097834/gmail-smtp-error-temporary-block
    """
    # this should be assigned to Celery worker instead of thread
    t = Thread(target=account_email_thread, args=(user, email_type))
    t.start()


def account_email_thread(user, email_type):
    try:
        tpl = get_template('mail/verification.html')
        subject = 'Activate Your Account'

        if email_type == 'forgot_password':
            tpl = get_template('mail/forgot_password.html')
            subject = 'Forgot Password'

        if email_type == 'invite_user':
            tpl = get_template('mail/invite_user.html')
            subject = 'You are invite'

        # if email_type == 'welcome':
        #     tpl = get_template('mail/welcome_user_email.html')
        #     subject = 'Successfully Register'

        d = {
            'user': user,
            'token': token_generator.make_token(user),
            'uid': force_str(urlsafe_base64_encode(force_bytes(user.pk))),
            'base_url': "http://localhost:3000"
        }

        msg = EmailMultiAlternatives(subject, '', settings.EMAIL_FROM, [user.username])
        msg.attach_alternative(tpl.render(d), "text/html")
        msg.send()

        print("Email sent for "+email_type + "on "+user.username)
    except Exception as e:
        admins_logger.exception(e)
        print(e)
