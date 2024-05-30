from django.urls import path
from .views import *
urlpatterns = [
    path('register/',RegistrionView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('user-profile/',PofileView.as_view()),
    path('change-password/',ChangePassword.as_view()),
    path('rest-password/',SendPasswordResetView.as_view()),
    path('rest/<uid>/<token>/',UserPasswordRestView.as_view())


]