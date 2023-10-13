import random
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _
import uuid
import os


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, password, **extra_fields):
        """
        Create and save a user with the given email, and password.
        """
        print("looooooooooooooooooooooooo")
        if not username:
            raise ValueError('The given email must be set')
        email = self.normalize_email(username)
        user = self.model(username=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', False)
        return self._create_user(username, password, **extra_fields)

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    # USER_TYPE = (
    #     ('merchant', 'Merchant'),
    #     ('client', 'Client'),
    #     ('admin', 'Admin')
    # )
    # GENDER_TYPE = (
    #     ('male', 'male'),
    #     ('female', 'Female'),
    #     ('other', 'Other')
    # )
    username = models.EmailField(unique=True)
    first_name = models.CharField('first name', max_length=30, blank=True)
    last_name = models.CharField('last name', max_length=150, blank=True)
    is_staff = models.BooleanField(
        'staff status',
        default=False,
        help_text='Designates whether the user can log into this admin site.',
    )
    is_active = models.BooleanField(
        'active',
        default=False,
        help_text='Designates whether this user should be treated as active. ',
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    # fcm_token = models.CharField(max_length=250, default=None, null=True)
    # type = models.CharField(choices=USER_TYPE, max_length=8, default='client')
    # phone = models.CharField(max_length=15, unique=True)
    # gender = models.CharField(choices=GENDER_TYPE, max_length=8, default='male')
    # photo = models.ImageField(upload_to=get_profile_path, help_text='cover photo', blank=True)

    USERNAME_FIELD = 'username'
    objects = UserManager()

    def __str__(self):
        return self.username

    def get_full_name(self):
        return '{} {}'.format(self.first_name, self.last_name)

    def get_short_name(self):
        return self.get_full_name()
