from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .seralizers import *
from django.contrib.auth import authenticate
from .renders import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    '''genate jwt token manullay'''
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# Create your views here.
class RegistrionView(APIView):
    renderer_classes = [UserRender]
    def post(self,req):
        serializer = RegisterSeralizer(data=req.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({'msg':'Register sucessfull','token':token},status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):

    def post(self,req):
        serializer = LoginSeralizer(data=req.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            user=authenticate(email=email,password=password)
            if user:
                token = get_tokens_for_user(user)
                return Response({'msg':'login sucesfuuly....','token':token})
            else:
                return Response({'error':{'non_field_errors':['email or password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
class PofileView(APIView):
    renderer_classes = [UserRender]
    permission_classes = [IsAuthenticated]#if not given then if login without token give error
    def get(self,req):
        serializer = UserProfileeSeralizer(req.user)
        return Response(serializer.data,status=status.HTTP_200_OK)


class ChangePassword(APIView):
    renderer_classes = [UserRender]
    permission_classes = [IsAuthenticated]

    def post(self,req):
        serializer = ChangePassworderalizer(data=req.data,context={'user':req.user})
        if serializer.is_valid(raise_exception=True):
        #here not use seralizer.save() beucse in sealizer.py we write validate() in that we save data.
        #if we use save() then we want to write create() in serlaizer.py
            return Response({'msg':'Password change sucesfully...'},status=status.HTTP_200_OK)
        else:
            return Response({'msg':serializer.errors})

class SendPasswordResetView(APIView):
    renderer_classes = [UserRender]

    def post(self,req):
        serializer = PasswordChangeEamilSerlaizer(data=req.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset link send. Please check your email'},status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors)


class UserPasswordRestView(APIView):
    renderer_classes = [UserRender]

    def post(self,req,uid,token):
        serializer = UserPasswordRestSerlizer(data=req.data,context={'uid':uid,'token':token})
        if serializer.is_valid():
            return Response({"msg":'password resetsucessfully'})
        else:
            return Response(serializer.errors)

