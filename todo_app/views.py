# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from .forms import SignupForm
from .models import TodoTask
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.cache import cache
from functools import wraps
import random
import json


def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Send Welcome Email
            send_mail(
                'Welcome to Todo App',
                'Thank you for signing up!',
                'from@example.com',
                [user.email],
                fail_silently=False,
            )
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})




otp_cache = {}  # Store OTPs temporarily, should use a more secure storage in production

def send_otp(user_email):
    otp = random.randint(1000, 9999)
    otp_cache[user_email] = otp
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}',
        'from@example.com',
        [user_email],
        fail_silently=False,
    )


def rate_limit(key_prefix, limit=5, timeout=300):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # Get client IP
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR'))
            key = f"{key_prefix}_{ip}"
            
            # Get current attempt count
            attempts = cache.get(key, 0)
            
            # Check if limit exceeded
            if attempts >= limit:
                return JsonResponse({
                    'success': False,
                    'message': 'Too many attempts. Please try again later.'
                })
            
            # Increment attempts
            cache.set(key, attempts + 1, timeout)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator



# @rate_limit('login', limit=5, timeout=300)  # 5 attempts per 5 minutes
@ensure_csrf_cookie
def login_view(request):
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            password = request.POST.get('password')

            # Basic validation
            if not username or not password:
                return JsonResponse({
                    'success': False,
                    'message': 'Please provide both username and password.'
                })

            # Authenticate user
            user = authenticate(request, username=username, password=password)

            if user is not None:
                try:
                    # Send OTP
                    send_otp(user.email)
                    
                    # Generate OTP verification URL
                    otp_url = reverse('otp_verify', kwargs={'username': username})
                    
                    return JsonResponse({
                        'success': True,
                        'message': 'OTP has been sent to your email.',
                        'redirect_url': otp_url
                    })
                except Exception as e:
                    return JsonResponse({
                        'success': False,
                        'message': 'Error sending OTP. Please try again.'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid username or password.'
                })

        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': 'An unexpected error occurred. Please try again.'
            })

    # GET request - render the login template
    return render(request, 'login.html')


def otp_verify_view(request, username):
    if request.method == 'POST':
        otp_input = request.POST.get('otp')
        try:
            user = User.objects.get(username=username)
            stored_otp = otp_cache.get(user.email)
            
            if stored_otp is not None and stored_otp == int(otp_input):
                login(request, user)
                # If it's an AJAX request, return JSON response
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'success',
                        'message': 'Login successful',
                        'redirect_url': reverse('todo_list')
                    })
                return redirect('todo_list')
            else:
                # If it's an AJAX request, return JSON response
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid OTP. Please try again.'
                    })
        except User.DoesNotExist:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': 'User not found'
                })
            
    return render(request, 'otp_verify.html', {'username': username})






@login_required
def todo_list(request):
    tasks = TodoTask.objects.filter(user=request.user)
    return render(request, 'todo_list.html', {'tasks': tasks})

@login_required
def add_task(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        TodoTask.objects.create(user=request.user, title=title, description=description)
        return redirect('todo_list')
    return render(request, 'add_task.html')
