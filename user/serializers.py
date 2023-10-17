from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model
from django.utils.encoding import DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from django.contrib.auth.tokens import default_token_generator as token_generator

from base.email import send_account_email
from user.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework.authtoken.models import Token
from rest_framework.utils.serializer_helpers import (
    BindingDict, BoundField, JSONBoundField, NestedBoundField, ReturnDict,
    ReturnList
)


class RegisterSerializer(serializers.ModelSerializer):
    username = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    token = serializers.CharField(read_only=True)
    id = serializers.IntegerField(read_only=True)

    class Meta:
        model = User
        fields = ('password', 'password2', 'username', 'first_name', 'last_name', 'token', 'invitation_code', 'id')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'invitation_code': {'required': False}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs
    @property
    def data(self):
        ret = super().data
        ret['token'] = self.token
        ret['is_superuser'] = False
        # ret['id'] = self.id
        return ReturnDict(ret, serializer=self)

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=True
        )

        user.set_password(validated_data['password'])
        user.save()

        token, created = Token.objects.get_or_create(user=user)
        self.token = token.key
        validated_data['token'] = token.key
        validated_data['id'] = user.pk
        return user


class InviteUserSerializer(serializers.ModelSerializer):
    username = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    class Meta:
        model = User
        fields = ('username', )
        # extra_kwargs = {
        #     'first_name': {'required': True},
        #     'last_name': {'required': True},
        # }

    @property
    def data(self):
        ret = super().data
        ret['is_superuser'] = False
        return ReturnDict(ret, serializer=self)

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            # first_name=validated_data['first_name'],
            # last_name=validated_data['last_name'],
            # is_active=True
            invitation_code='qwerty1234'
        )
        user.save()
        send_account_email(user, 'invite_user')
        return user


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):
        user = self.context['request'].user

        if user.pk != instance.pk or user.is_staff is True:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})

        instance.set_password(validated_data['password'])
        instance.save()

        return instance


class ListUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'id')


class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        return value

    def validate_username(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "This username is already in use."})
        return value

    def update(self, instance, validated_data):
        user = self.context['request'].user

        if user.pk != instance.pk or user.is_staff is True:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})

        instance.first_name = validated_data['first_name']
        instance.last_name = validated_data['last_name']
        instance.email = validated_data['email']
        instance.username = validated_data['username']

        instance.save()

        return instance


class ForgotPasswordSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True)

    class Meta:
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = self.context['request']

    def validate(self, data):
        # try:
        # user = get_user_model().objects.get_or_404(email=data.get('email'))
        # send_email(user.pk, email_type='forgot_password')
        # except get_user_model().DoesNotExist:
        #     pass
        user = get_object_or_404(get_user_model(), username=data.get('username'))
        print("Need to send email to user ->>>")
        send_account_email(user, email_type='forgot_password')
        return data


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    class Meta:
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.request = self.context['request']

    def validate(self, data):
        url_params = self.context['url_params']
        uid = url_params.get('uid')
        token = url_params.get('token')
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = get_user_model().objects.get(id=user_id)
        except get_user_model().DoesNotExist:
            raise ValidationError(detail='User does not exist')
        except DjangoUnicodeDecodeError:
            raise ValidationError(detail='Link was expired. Please resend link from forgot password')

        check_token = token_generator.check_token(user, token)

        if check_token:
            self.user = user
            return data
        else:
            send_account_email(user.pk, email_type='forgot_password')
            raise ValidationError(detail='Link was expired. Please check your inbox again.')

    def validate_new_password(self, new_password):
        data = self.initial_data
        if new_password != data.get('confirm_password'):
            raise ValidationError('Passwords do not match.')

        if validate_password(new_password) is None:
            return new_password

    def reset_password(self):
        self.user.set_password(self.validated_data.get('new_password'))
        self.user.save()
