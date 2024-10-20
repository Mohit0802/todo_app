from django.urls import path
from .views import signup_view, login_view, otp_verify_view,todo_list, add_task

urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('otp-verify/<str:username>/', otp_verify_view, name='otp_verify'),
    path('todo/', todo_list, name='todo_list'),
    path('todo/add/', add_task, name='add_task'),
]
