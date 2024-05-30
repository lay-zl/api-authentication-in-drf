from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str,force_str,DjangoUnicodeDecodeError,force_bytes
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Utils
class RegisterSeralizer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model = User
        fields = ['email','name','tc','password','password2']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):#RegisterSeralizer(data=req.data) data give the all values to attrs
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('password dose not match')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSeralizer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=100)
    class Meta:
        model = User
        fields = ['email','password']

class UserProfileeSeralizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','email','name']

class ChangePassworderalizer(serializers.Serializer):
    password = serializers.CharField(max_length=100,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=100,style={'input_type':'password'},write_only=True)

    class Meta:
        fields = ['password','password2']

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password dosent not match')
        else:
            user.set_password(password)
            user.save()
            return attrs

class PasswordChangeEamilSerlaizer(serializers.Serializer):
    email = serializers.EmailField(max_length=100)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            link='http://localhost:3000/api/reset/'+uid+'/'+token
            body = 'click for reset '+' '+link
            data={
                'subject':"rese your password",
                'body':body,
                'to_email':user.email
            }
            Utils.send_email(data=data)
            return attrs
        else:
            raise serializers.ValidationError('You are not register user')

class UserPasswordRestSerlizer(serializers.Serializer):
    password = serializers.CharField(max_length=100, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=100, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
            raise serializers.ValidationError('Password dosent not match')
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise serializers.ValidationError('token is not valid or expired')

        else:
            user.set_password(password)
            user.save()
            return attrs