from decimal import Decimal, InvalidOperation
import io
import random
import re
from urllib import request
from venv import logger
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render, redirect, get_object_or_404
import requests
from .forms import PrivacyPolicyForm
from itertools import chain
import time
import traceback
import uuid
import zipfile
import json
import os
from django.forms import ValidationError
from django.http import HttpResponseBadRequest, HttpResponseForbidden, JsonResponse, FileResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from ecom import settings

from .models import (
    Category, Commission, CommunityMember, DownloadHistory, EmailVerification, Game, Customer,
    Developer, Community, Order, OrderItem, PaymentDetail, Post, Comment, GameSubmission, GameScreenshot,
    Cart, CartItem, PrivacyPolicy
)
from .forms import (
    CustomPasswordChangeForm, SignUpForm, UserEditForm, CommunityForm,
    PostForm, 
)

import json
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect, render
from .models import Order, OrderItem, CartItem

# ======================
# Authentication Views
# ======================

def home(request):
    # Fetch all approved games from the database
    games = Game.objects.filter(approved=True)
    # Render the home page with the approved games
    return render(request, 'home.html', {'games': games})

def signup_user(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Store form data temporarily
            form_data = {
                'username': form.cleaned_data['username'],
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'email': email,
                'phone': form.cleaned_data['phone'],
                'account_type': form.cleaned_data['account_type'],
                'password': form.cleaned_data['password1']
            }
            if Customer.objects.filter(phone=form.cleaned_data['phone']).exists():
                form.add_error('phone', 'This phone number is already registered')
                return render(request, 'signup.html', {'form': form})
            # Create verification entry
            verification = EmailVerification.create_verification(email, form_data)
            
            # Send OTP email with explicit template paths
            try:
                subject = 'Verify Your RiggStore Account'
                text_content = f'Your OTP is: {verification.otp}\nValid for 5 minutes.'
                html_content = render_to_string('emails/otp_email.html', {
                    'otp': verification.otp,
                    'email': email
                })
                
                msg = EmailMultiAlternatives(
                    subject,
                    text_content,
                    settings.EMAIL_HOST_USER,
                    [email]
                )
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            except Exception as e:
                print(f"Error sending email: {str(e)}")
                messages.error(request, "Failed to send verification email")
                return redirect('signup')
            
            return redirect('verify_email', email=email)
        
        return render(request, 'signup.html', {'form': form})
    
    return render(request, 'signup.html', {'form': SignUpForm()})

def verify_email(request, email):
    if request.method == "POST":
        verification = get_object_or_404(EmailVerification, email=email)
        
        if verification.otp == request.POST.get('otp') and verification.is_valid():
            form_data = verification.form_data
            
            # Initial checks
            if User.objects.filter(username=form_data['username']).exists():
                return render(request, 'verify_email.html', {
                    'email': email,
                    'error': 'Username already taken'
                })
                
            if User.objects.filter(email=email).exists():
                return render(request, 'verify_email.html', {
                    'email': email,
                    'error': 'Email already registered'
                })

            try:
                with transaction.atomic():
                    # Create user (this triggers the Customer creation via signal)
                    user = User.objects.create_user(
                        username=form_data['username'],
                        password=form_data['password'],
                        first_name=form_data['first_name'],
                        last_name=form_data['last_name'],
                        email=form_data['email']
                    )
                    
                    # Update the auto-created Customer
                    customer = user.customer
                    customer.phone = form_data['phone']
                    customer.save()
                    
                    # Create developer profile if needed
                    if form_data['account_type'] == 'developer':
                        Developer.objects.create(
                            user=customer,
                            company_name='',
                            approved=False
                        )
                    
                    # Mark verification complete
                    verification.is_verified = True
                    verification.save()

                    # Email sending outside transaction
                    transaction.on_commit(lambda: send_welcome_email(user, form_data['account_type']))
                    
                    login(request, user)
                    return redirect('home')

            except IntegrityError as e:
                return render(request, 'verify_email.html', {
                    'email': email,
                    'error': f"Account conflict: {str(e)}"
                })

            except Exception as e:
                return render(request, 'verify_email.html', {
                    'email': email,
                    'error': "System error. Please try again later."
                })

        return render(request, 'verify_email.html', {
            'email': email,
            'error': 'Invalid or expired OTP'
        })
    
    return render(request, 'verify_email.html', {'email': email})

def send_welcome_email(user, account_type):
    """Send welcome email with retries and better error handling"""
    max_retries = 3
    attempt = 0
    
    while attempt < max_retries:
        try:
            is_developer = account_type == 'developer'
            subject = f'Welcome to RiggStore{" Developer" if is_developer else ""}!'
            context = {
                'first_name': user.first_name,
                'is_developer': is_developer,
                'email': user.email  # Add explicit email to context
            }
            
            text_content = render_to_string('emails/welcome_email.txt', context)
            html_content = render_to_string('emails/welcome_email.html', context)
            
            # Create email with explicit encoding
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
                reply_to=[settings.CONTACT_EMAIL],
            )
            email.attach_alternative(html_content, "text/html")
            
            # Add debug headers
            email.extra_headers['X-Email-Type'] = 'welcome-email'
            
            # Send with timeout
            email.send(fail_silently=False, timeout=10)
            print(f"Successfully sent welcome email to {user.email}")
            return
            
        except Exception as e:
            attempt += 1
            print(f"Attempt {attempt} failed: {str(e)}")
            if attempt >= max_retries:
                print(f"Failed to send welcome email after {max_retries} attempts")
                # Consider logging to error monitoring system
                return
            time.sleep(2 ** attempt)  # Exponential backoff
            
def resend_otp(request, email):
    verification = get_object_or_404(EmailVerification, email=email)
    if verification.is_valid():
        verification.delete()
    
    new_verification = EmailVerification.create_verification(
        email=email,
        form_data=verification.form_data
    )
    
    try:
        subject = 'Your New Verification Code'
        text_content = f'Your new OTP is: {new_verification.otp}\nValid for 5 minutes.'
        html_content = render_to_string('emails/otp_email.html', {
            'otp': new_verification.otp,
            'email': email
        })
        
        msg = EmailMultiAlternatives(
            subject,
            text_content,
            settings.EMAIL_HOST_USER,
            [email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()
    except Exception as e:
        print(f"Error resending OTP: {str(e)}")
        messages.error(request, "Failed to resend verification code")
    
    return redirect('verify_email', email=email)

# Handle user login, authenticate and redirect appropriately.
def login_user(request):
    # Check if the request method is POST (login form submission)
    if request.method == "POST":
        # Get username and password from POST data
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Authenticate the user
        user = authenticate(request, username=username, password=password)
        if user:
            # Log the user in if authentication is successful
            login(request, user)
            request.session.set_expiry(1209600)  # Set session expiration
            # Check if the user has admin privileges
            if user.is_staff or user.is_superuser:
                messages.success(request, "Admin logged in successfully")
                # Redirect to the admin panel if the user is an admin
                return redirect('admin_panel')
            # Regular user login success
            messages.success(request, "Logged In Successfully")
            # Redirect to the account page or to the next URL
            return redirect(request.POST.get('next', 'account'))
        
        # Login failed due to invalid credentials
        messages.error(request, "Invalid username or password")
    
    # Render the login page if the method is not POST
    return render(request, 'login.html', {})

# Log out the user and redirect to the home page.
def logout_user(request):
    # Log the user out of the session
    logout(request)
    messages.success(request, "Logged Out")  # Provide feedback to the user
    # Redirect the user to the home page after logout
    return redirect('home')

# ======================
# Community Views
# ======================

@login_required
def community(request):
    joined_communities = []
    discover_communities = Community.objects.filter(is_public=True).select_related('game').order_by('-created_at')

    if request.user.is_authenticated:
        customer = request.user.customer
        joined_communities = customer.joined_communities.select_related('game').order_by('-created_at')
        discover_communities = discover_communities.exclude(id__in=joined_communities.values_list('id', flat=True))

    # Set official status for all communities
    for community in chain(joined_communities, discover_communities):
        community.is_official = community.game is not None

    context = {
        'joined_communities': sorted(joined_communities, key=lambda c: not c.is_official),
        'discover_communities': sorted(discover_communities, key=lambda c: not c.is_official),
        'community_form': CommunityForm()
    }
    return render(request, 'community.html', context)


@receiver(post_save, sender=Game)
def create_official_community(sender, instance, **kwargs):
    print(f"Signal triggered for Game: {instance.name} (Approved: {instance.approved})")
    if instance.approved and not hasattr(instance, 'official_community'):
        print("Creating official community...")
        community = Community.objects.create(
            name=instance.name,
            game=instance,
            created_by=instance.developer.user,
            is_public=True
        )
        community.admins.add(instance.developer.user)
        community.members.add(instance.developer.user)
        print(f"Created community: {community}")

@login_required
@require_POST  # Ensure this view only handles POST requests
def create_community(request):
    try:
        # Instantiate the community form with POST data
        form = CommunityForm(request.POST)
        # Check if the form is valid
        if form.is_valid():
            community = form.save(commit=False)  # Create community instance without saving yet
            community.created_by = request.user.customer  # Set the creator of the community
            community.save()  # Save the community to the database
            # Add the creator as an admin and member of the community
            community.add_admin(request.user.customer)
            community.members.add(request.user.customer)  # Ensure the creator is a member as well
            return JsonResponse({
                'success': True,
                'community_name': community.name,
                'community_id': community.id
            }, status=201)  # Return success response
        # If form is not valid, return errors
        return JsonResponse({
            'success': False,
            'errors': form.errors.get_json_data()
        }, status=400)
    except Exception as e:
        # Handle any exceptions and return an error response
        return JsonResponse({
            'success': False,
            'errors': {'__all__': [str(e)]}
        }, status=500)
    

def community_list(request):
    # Get base querysets
    joined = list(getattr(request.user.customer, 'joined_communities', []))
    discover = Community.objects.filter(is_public=True).exclude(id__in=[c.id for c in joined])
    
    # Mark official communities
    for community in joined + list(discover):
        community.is_official = hasattr(community, 'game')
    
    # Sort with official first
    context = {
        'joined_communities': sorted(joined, key=lambda c: not c.is_official),
        'discover_communities': sorted(discover, key=lambda c: not c.is_official),
    }
    return render(request, 'community/list.html', context)


@login_required
def edit_community(request, community_id):
    # Get the community or return a 404 if not found
    community = get_object_or_404(Community, id=community_id)
    # Only allow editing by the creator of the community
    if request.user.customer != community.created_by:
        messages.error(request, "You are not authorized to edit this community.")
        return redirect('community_detail', community_id=community.id)

    # If the request method is POST, process the form submission
    if request.method == 'POST':
        form = CommunityForm(request.POST, instance=community)  # Bind form to the existing community instance
        if form.is_valid():
            form.save()  # Save the updated community information
            messages.success(request, "Community updated successfully!")  # Provide success feedback
            return redirect('community_detail', community_id=community.id)
    else:
        # If the request is not POST, instantiate the form with the existing community data
        form = CommunityForm(instance=community)
    
    # Render the edit community page with the form and community instance
    return render(request, 'edit_community.html', {'form': form, 'community': community})

# Render the details of a specific community and its posts.
def community_detail(request, community_id):
    community_obj = get_object_or_404(Community, id=community_id)
    community_obj.is_official = community_obj.game is not None 
    is_member = False
    is_community_creator = False

    if request.user.is_authenticated:
        user_customer = request.user.customer
        is_member = community_obj.members.filter(id=user_customer.id).exists()
        is_community_creator = user_customer == community_obj.created_by
    else:
        user_customer = None

    posts = Post.objects.none()
    if is_member or is_community_creator:
        # Order by pinned first, then by created_at (most recent)
        posts = Post.objects.filter(community=community_obj).order_by('-pinned', '-created_at')

    context = {
        'community_obj': community_obj,
        'posts': posts,
        'other_communities': Community.objects.exclude(id=community_obj.id).order_by('-created_at')[:5],
        'post_form': PostForm(),
        'is_member': is_member,
        'is_community_creator': is_community_creator,
    }
    return render(request, 'community_detail.html', context)


@login_required
@require_POST
def toggle_pin(request, post_id):
    try:
        post = get_object_or_404(Post, id=post_id)
        community = post.community
        user = request.user.customer

        if user != community.created_by and user not in community.admins.all():
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        if post.pinned:
            # Unpin the post
            post.pinned = False
            post.pinned_by = None
            post.pinned_at = None
        else:
            # Pin the post
            post.pinned = True
            post.pinned_by = user
            post.pinned_at = time.timezone.now()
            
        post.save()
        return JsonResponse({
            'success': True,
            'pinned': post.pinned,
            'pinned_by': post.pinned_by.f_name if post.pinned_by else '',
            'pinned_at': post.pinned_at.strftime("%b %d, %Y %H:%M") if post.pinned_at else ''
        })

    except Exception as e:
        logger.error(f"Pin toggle error: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Server error'}, status=500)
    
@login_required
@require_POST  # Ensure this view only handles POST requests
def join_community(request, community_id):
    # Retrieve the community object or return a 404 if not found
    community = get_object_or_404(Community, id=community_id)
    customer = request.user.customer  # Get the current logged-in customer's instance
    
    # Check if the customer is already a member of the community
    if community.members.filter(id=customer.id).exists():
        # If the customer is a member, remove them from the community
        community.members.remove(customer)
        joined = False  # Set joined status to False 
    else:
        # If the customer is not a member, add them to the community
        community.members.add(customer)
        joined = True  # Set joined status to True
    
    # Return JSON response with the result of the join operation
    return JsonResponse({
        'success': True,
        'joined': joined,  # Status indicating whether the user joined or left
        'member_count': community.members.count()  # Return the updated member count
    })

@login_required
def community_members(request, community_id):
    # Retrieve the community object or return a 404 if not found
    community = get_object_or_404(Community, id=community_id)
    
    # Check if the user is a member of the community
    user_membership = community.members.filter(user=request.user).first()
    
    is_admin = False  # Initialize admin status
    # Check if the user is an admin of the community
    if user_membership:
        is_admin = community.admins.filter(id=user_membership.id).exists()  # Verify if the user is listed as an admin

    # Retrieve all admins of the community
    admins = community.admins.all()
    
    # Get regular members excluding admins
    regular_members = community.members.exclude(id__in=admins.values('id'))

    # If the viewer is an admin, show all members, including regular members
    if is_admin:
        regular_members = community.members.all()

    # Retrieve moderators (assuming there is a way to identify them)
    moderators = community.members.filter(communitymember__role='moderator')

    # Prepare context data for rendering community members view
    context = {
        'community': community,  # The community object
        'admins': admins,  # List of admin members
        'moderators': moderators,  # List of moderator members
        'regular_members': regular_members,  # List of regular members excluding admins
        'regular_members_count': regular_members.count(),  # Count of regular members
        'is_admin': is_admin,  # Boolean indicating if the current user is an admin
    }
    # Render the community members template with the context data
    return render(request, 'community_members.html', context)

# Promote a user to moderator status in a specific community
@login_required 
def promote_to_moderator(request, community_id, user_id):
    # Retrieve the community or return a 404 if not found
    community = get_object_or_404(Community, id=community_id)
    # Retrieve the user or return a 404 if not found
    user = get_object_or_404(User, id=user_id)
    customer = user.customer  # Get the customer's instance associated with the user

    # Check if the current user is an admin of the community
    if request.user.customer in community.admins.all():
        # Get or create a CommunityMember entry for the user in the specified community
        member_entry, created = CommunityMember.objects.get_or_create(
            community=community,
            customer=customer,
            defaults={'role': 'moderator'}  # Default role is 'moderator'
        )
        if not created:
            # If the entry already exists, just update the role to 'moderator'
            member_entry.role = 'moderator'
            member_entry.save()
    
    # Redirect to the community members page
    return redirect('community_members', community_id=community.id)

@login_required
def demote_to_member(request, community_id, user_id):
    # Retrieve the community or return a 404 if not found
    community = get_object_or_404(Community, id=community_id)
    # Retrieve the user or return a 404 if not found
    user = get_object_or_404(User, id=user_id)
    customer = user.customer  # Get the customer's instance associated with the user

    # Check if the current user is an admin of the community
    if request.user.customer in community.admins.all():
        try:
            # Retrieve the CommunityMember entry for the user in the specified community
            member_entry = CommunityMember.objects.get(
                community=community,
                customer=customer
            )
            # Change the user's role to 'member'
            member_entry.role = 'member'
            member_entry.save()
        except CommunityMember.DoesNotExist:
            # If the member entry does not exist, do nothing
            pass
    
    # Redirect to the community members page
    return redirect('community_members', community_id=community.id)

@login_required
def kick_member(request, community_id, user_id):
    community = get_object_or_404(Community, id=community_id)
    user = get_object_or_404(User, id=user_id)
    customer = user.customer

    # Check if current user is admin OR moderator
    is_moderator = CommunityMember.objects.filter(
        community=community,
        customer=request.user.customer,
        role='moderator'
    ).exists()

    if customer == community.created_by:
        messages.error(request, "You cannot kick the community creator.")
        return redirect('community_members', community_id=community.id)

    # Updated condition to include moderators
    if request.user.customer in community.admins.all() or is_moderator:
        community.members.remove(customer)
        CommunityMember.objects.filter(
            community=community,
            customer=customer
        ).delete()
    
    return redirect('community_members', community_id=community.id)


# Delete a community if the user is the creator.
@login_required
@require_POST  # Ensure this view only handles POST requests
def delete_community(request, community_id):
    try:
        # Retrieve the community or return a 404 if not found
        community = get_object_or_404(Community, id=community_id)
        
        # Check if the current user is the creator of the community
        if request.user.customer != community.created_by:
            return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)
        
        # Delete the community from the database
        community.delete()
        # Return a success response with a redirect URL
        return JsonResponse({
            'success': True,
            'message': 'Community deleted successfully',
            'redirect_url': reverse('community')  # Redirect URL after deletion
        }, status=200)
    except Exception as e:
        # Handle any exceptions and return an error response
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
# ======================
# Post & Comment Views
# ======================

# Create a new post in a specific community.
@login_required
@require_POST  # Ensure this view only handles POST requests
def create_post(request, community_id):
    try:
        # Retrieve the community object or return a 404 if not found
        community_obj = get_object_or_404(Community, id=community_id)
        # Instantiate the post form with POST data and files
        form = PostForm(request.POST, request.FILES)
        
        # Validate the form data
        if form.is_valid():
            post = form.save(commit=False)  # Create post instance without saving yet
            post.community = community_obj  # Associate post with the specific community
            post.author = request.user.customer  # Set the post author
            post.save()  # Save the post to the database
            
            # Return a success response with post details
            return JsonResponse({
                'success': True,
                'post_id': post.id,
                'content': post.content,
                'author': post.author.f_name,
                'created_at': post.created_at.strftime('%b %d, %Y %H:%M')  # Format created date
            }, status=201)
        
        # If the form is not valid, return errors
        return JsonResponse({
            'success': False,
            'errors': form.errors.as_json()  # Serialize form errors to JSON
        }, status=400)
    
    except Exception as e:
        # Handle any exceptions and return an error response
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# Like or unlike a post and return the updated like count.
@login_required
@require_POST  # Ensure this view only handles POST requests
def like_post(request, post_id):
    try:
        # Retrieve the post or return a 404 if not found
        post = get_object_or_404(Post, id=post_id)
        customer = request.user.customer  # Get the current user's customer instance
        
        # Check if the customer has already liked the post
        if post.likes.filter(id=customer.id).exists():
            # If the post is already liked, unlike it
            post.likes.remove(customer)
            liked = False  # Set liked status to False
        else:
            # If not liked, like the post
            post.likes.add(customer)
            liked = True  # Set liked status to True
            
        # Return updated like status and count
        return JsonResponse({
            'success': True,
            'liked': liked,  # Indicates if the post is liked or not
            'like_count': post.likes.count()  # Current like count of the post
        }, status=200)
    
    except Exception as e:
        # Handle any exceptions and return an error response
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_POST  # Ensure this view only handles POST requests
def create_comment(request, post_id):
    try:
        # Retrieve the post or return a 404 if not found
        post = get_object_or_404(Post, id=post_id)
        text = request.POST.get('text', '').strip()  # Get the comment text, stripping whitespace
        
        # Ensure the comment is not empty
        if not text:
            return JsonResponse({'error': 'Comment cannot be empty'}, status=400)

        # Verify the user has a customer profile
        if not hasattr(request.user, 'customer'):
            return JsonResponse({'error': 'User profile incomplete'}, status=403)
            
        # Create a new comment associated with the post and user
        comment = Comment.objects.create(
            post=post,
            user=request.user.customer,
            text=text
        )
        
        # Return a success response with comment details
        return JsonResponse({
            'success': True,
            'comment_id': comment.id,
            'user_name': request.user.customer.f_name,
            'user_image': request.user.customer.image.url if request.user.customer.image else '',  # Profile image URL
            'text': comment.text,
            'is_owner': True,  # Indicate that the user is the owner of the comment
            'created_at': comment.created_at.strftime('%b. %d, %Y, %I:%M %p')  # Format created date
        })
        
    except Exception as e:
        # Handle any exceptions and return a server error response
        return JsonResponse({
            'error': 'Server error',
            'detail': str(e)  # Return exception detail for debugging
        }, status=500)

@login_required
@require_POST
def delete_post(request, post_id):
    try:
        post = get_object_or_404(Post, id=post_id)
        user = request.user.customer
        community = post.community

        is_moderator = community.communitymember_set.filter(
            customer=user, 
            role='moderator'
        ).exists()
        
        allowed = (
            user == post.author or
            user == community.created_by or
            is_moderator
        )
        
        if not allowed:
            return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)
            
        post.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_POST
def delete_comment(request, comment_id):
    try:
        comment = get_object_or_404(Comment, id=comment_id)
        user = request.user.customer
        community = comment.post.community

        is_moderator = community.communitymember_set.filter(
            customer=user, 
            role='moderator'
        ).exists()
        
        allowed = (
            user == comment.user or
            user == comment.post.author or
            user == community.created_by or
            is_moderator
        )
        
        if not allowed:
            return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)
            
        comment.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
# ======================
# User Account Views
# ======================

@login_required
def account(request):
    customer = request.user.customer
    
    # Get download history
    download_history = DownloadHistory.objects.filter(
        user=customer, 
        visible=True
    ).select_related('game').order_by('-downloaded_at')[:20]
    
    # Get IDs of games the user has purchased
    purchased_game_ids = OrderItem.objects.filter(
        order__customer=customer,
        order__payment_status='completed'
    ).values_list('game__id', flat=True).distinct()
    
    context = {
        'download_history': download_history,
        'purchased_game_ids': set(purchased_game_ids),
    }
    return render(request, 'account.html', context)

# Allow the user to edit their profile information.
@login_required
def edit_profile(request):
    if request.method == 'POST':
        # Bind the user edit form with the posted data and the current user instance
        form = UserEditForm(request.POST, instance=request.user)
        if form.is_valid():  # Validate the form data
            user = form.save()  # Save the updated user information
            customer = request.user.customer  # Get the customer's instance
            customer.f_name = user.first_name  # Update the first name
            customer.l_name = user.last_name  # Update the last name
            customer.email = user.email  # Update the email
            customer.save()  # Save the customer instance
            messages.success(request, 'Profile updated successfully')  # Success message
            return redirect('account')  # Redirect to the account page
    else:
        # If not a POST request, instantiate the form with the current user data
        form = UserEditForm(instance=request.user)
    
    # Render the edit profile page with the form
    return render(request, 'edit_profile.html', {'form': form})

# Verify the user's password for security purposes.
@require_POST  # Ensure this view only handles POST requests
@login_required
def verify_password(request):
    try:
        data = json.loads(request.body)  # Parse the JSON body of the request
        password = data.get('password')  # Extract the password
    except json.JSONDecodeError:
        return JsonResponse({'valid': False})  # Return invalid status if JSON parsing fails
    
    # Authenticate the user with the given password
    user = authenticate(username=request.user.username, password=password)
    # Return JSON response indicating if the password is valid
    return JsonResponse({'valid': user is not None})


from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password

def change_password(request):
    if request.method == 'POST':
        # Step 1: Verify old password and send OTP
        if 'old_password' in request.POST:
            # Manual password validation
            old_password = request.POST.get('old_password')
            user = request.user
            
            if not user.check_password(old_password):
                return JsonResponse({'errors': {'old_password': ['Incorrect current password']}}, status=400)

            # Generate and store OTP
            otp = str(random.randint(100000, 999999))
            request.session['password_data'] = {
                'otp': otp,
                'otp_created': timezone.now().isoformat(),
                'user_id': user.id
            }
            
            # Send OTP email
            send_mail(
                'Password Change Verification',
                f'Your OTP is: {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return JsonResponse({'status': 'otp_sent'})

        # Step 2: Verify OTP and set new password
        elif 'otp' in request.POST:
            session_data = request.session.get('password_data', {})
            
            # Validate session data
            if not session_data or session_data.get('user_id') != request.user.id:
                return JsonResponse({'error': 'Invalid session'}, status=400)

            # Check OTP expiration (15 minutes)
            otp_time = timezone.datetime.fromisoformat(session_data['otp_created'])
            if (timezone.now() - otp_time).total_seconds() > 900:
                return JsonResponse({'error': 'OTP expired'}, status=400)

            # Verify OTP match
            if request.POST['otp'] != session_data['otp']:
                return JsonResponse({'error': 'Invalid OTP'}, status=400)

            # Validate new passwords
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')
            
            if new_password1 != new_password2:
                return JsonResponse({'error': 'Passwords do not match'}, status=400)

            try:
                validate_password(new_password1, user=request.user)
            except ValidationError as e:
                return JsonResponse({'error': e.messages}, status=400)

            # Update password
            request.user.set_password(new_password1)
            request.user.save()
            update_session_auth_hash(request, request.user)
            
            # Clear session data
            del request.session['password_data']
            
            return JsonResponse({'status': 'success'})

    return render(request, 'change_password.html')

# Upload a new profile image for the user.
@login_required
def upload_profile_image(request):
    if request.method == 'POST' and 'image' in request.FILES:  # Check for image file in the request
        try:
            customer = request.user.customer  # Get the current user's customer instance
            customer.image = request.FILES['image']  # Set the new profile image
            customer.save()  # Save the updated customer instance
            messages.success(request, 'Profile image updated successfully')  # Success message
        except Exception as e:
            messages.error(request, f'Error updating profile image: {str(e)}')  # Error message on exception
    
    # Redirect to the account page after upload
    return redirect('account')

@login_required
@transaction.atomic
def delete_account(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user = request.user
        
        if not user.check_password(password):
            messages.error(request, "Invalid password. Account deletion failed")
            return redirect('account')
        
        try:
            # Delete all related objects explicitly to ensure full cleanup
            customer = user.customer
            
            # Delete developer-related data if exists
            Developer.objects.filter(user=customer).delete()
            
            # Delete download history
            DownloadHistory.objects.filter(user=customer).delete()
            
            # Delete orders and related items
            orders = Order.objects.filter(customer=customer)
            for order in orders:
                OrderItem.objects.filter(order=order).delete()
            orders.delete()
            
            # Delete customer profile
            customer.delete()
            
            # Delete the user account
            user.delete()
            
            # Logout the user
            logout(request)
            
            messages.success(request, "Your account and all associated data have been permanently deleted")
            return redirect('home')
        
        except Exception as e:
            transaction.set_rollback(True)
            messages.error(request, f"Account deletion failed: {str(e)}")
            return redirect('account')
    
    return redirect('account')

@login_required
@require_POST
def delete_selected_downloads(request):
    try:
        data = json.loads(request.body)
        download_ids = data.get('download_ids', [])
        DownloadHistory.objects.filter(
            id__in=download_ids,
            user=request.user.customer
        ).update(visible=False)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def clear_all_downloads(request):
    try:
        DownloadHistory.objects.filter(
            user=request.user.customer
        ).update(visible=False)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# ======================
# Admin Views
# ======================

# Render the admin dashboard with user and community information.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)  # Ensure that only staff or superusers can access this view
def admin_dashboard(request):
    # Retrieve all customers with related communities and games for efficient querying
    users = Customer.objects.all().prefetch_related('created_communities', 'joined_communities', 'developer__game_set')
    # Get the most recent pending game submissions, limited to 5
    submissions = GameSubmission.objects.filter(status='pending').order_by('-submitted_at')[:5]
    
    # Prepare context for rendering the admin dashboard
    context = {
        'users': users,
        'communities': Community.objects.all(),  # Retrieve all communities for the dashboard
        'submissions': submissions  # Include pending submissions in the context
    }
    # Render the admin dashboard template with the provided context
    return render(request, 'admin.html', context)





@login_required
@user_passes_test(lambda u: u.is_staff)  # Ensure that only staff can access this view
@require_POST  # Ensure this view only handles POST requests
def delete_submission(request, submission_id):
    # Retrieve the game submission or return a 404 if not found
    submission = get_object_or_404(GameSubmission, id=submission_id)
    submission.delete()  # Delete the submission from the database
    messages.success(request, "Submission deleted successfully.")  # Success message
    return redirect('admin_dashboard')  # Redirect to the admin dashboard

# Delete a user from the system by admin.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)  # Ensure that only staff or superusers can access this view
def delete_user(request, user_id):
    try:
        # Retrieve the Customer object by user ID or raise a 404 if not found
        customer = Customer.objects.get(id=user_id)
        
        # Delete the associated User object
        user = customer.user  # Get related User instance
        user.delete()  # Cascades delete the Customer if models are set up properly
        
        messages.success(request, "User deleted successfully.")  # Success message
    except Customer.DoesNotExist:
        messages.error(request, "User not found.")  # Error message if user does not exist
    
    return redirect('admin_panel')  # Redirect to the admin panel

# Admin functionality to delete a community.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)  # Ensure that only staff or superusers can access this view
@require_POST  # Ensure this view only handles POST requests
def admin_delete_community(request, community_id):
    try:
        # Retrieve the community or return a 404 if not found
        community = get_object_or_404(Community, id=community_id)
        community.delete()  # Delete the community from the database
        messages.success(request, "Community deleted successfully.")  # Success message
        return redirect('admin_panel')  # Redirect to the admin panel
    except Exception as e:
        # Handle unexpected errors and return an error message
        messages.error(request, f"Error deleting community: {str(e)}")
        return redirect('admin_panel')  # Redirect to the admin panel

# ======================
# Game Detail Views
# ======================

# Render the details of a specific game.

def game_details(request, game_id):
    # Retrieve the game object, including related submission and developer/user information
    game = get_object_or_404(
        Game.objects.select_related('submission', 'developer__user')  # Optimize query for related fields
                   .prefetch_related('categories'),  # Prefetch categories related to the game
        id=game_id  # Get the game by its ID
    )
    # Render the game details page with the retrieved game object
    return render(request, 'game_details.html', {'game': game})

from django.db.models import Case, When, F, DecimalField

# views.py
from django.db.models import Case, When, F, DecimalField, Q
from django.shortcuts import render

def game_list(request):
    # Determine which template to use
    template_name = 'game_list.html' if request.path == '/games/' else 'home.html'
    
    # Common logic for both pages
    games = Game.objects.all().prefetch_related('categories')
    categories = Category.objects.all().order_by('name')
    
    # Get filters/sorting from request
    search_query = request.GET.get('q', '')
    selected_category_ids = [int(id) for id in request.GET.getlist('category') if id.isdigit()]
    sort_by = request.GET.get('sort', '')

    # Filtering logic
    if search_query:
        games = games.filter(Q(name__icontains=search_query) | Q(description__icontains=search_query))
    
    if selected_category_ids:
        games = games.filter(categories__id__in=selected_category_ids).distinct()

    # Sorting logic
    games = games.annotate(
        current_price=Case(
            When(is_on_sale=True, then=F('sale_price')),
            default=F('price'),
            output_field=DecimalField(max_digits=10, decimal_places=2),
        )
    )
    sort_map = {
        'price_asc': 'current_price',
        'price_desc': '-current_price',
        'name_asc': 'name',
        'name_desc': '-name'
    }
    if sort_by in sort_map:
        games = games.order_by(sort_map[sort_by])

    context = {
        'games': games,
        'categories': categories,
        'selected_category_ids': selected_category_ids,
        'current_sort': sort_by,
        'search_query': search_query
    }
    return render(request, template_name, context)

@login_required
def developer_dashboard(request):
    try:
        customer = request.user.customer  # Retrieve the customer's profile from the user
        developer = customer.developer  # Get the developer instance associated with the customer

        # Get all game submissions made by the developer
        submissions = GameSubmission.objects.filter(developer=developer)  
        # Render the developer dashboard with the list of submissions
        return render(request, 'developer_dashboard.html', {'submissions': submissions})

    except Customer.DoesNotExist:
        # Handle the case where the customer profile is missing
        messages.error(request, "You need a customer profile to access the developer dashboard.")
        return redirect('home')  # Redirect to home page

    except Developer.DoesNotExist:
        # Handle the case where the user is not an approved developer
        messages.error(request, "You are not an approved developer.")
        return redirect('home')  # Redirect to home page

@login_required
@transaction.atomic
def upload_game(request):
    try:
        customer = request.user.customer
        developer = Developer.objects.get(user=customer)
        categories = Category.objects.all()

        if request.method == 'POST':
            form_data = request.POST.copy()
            try:
                # Validate price format
                try:
                    price = Decimal(form_data['price'])
                    if price < Decimal('0.00'):
                        raise ValueError("Price cannot be negative")
                except (InvalidOperation, ValueError) as e:
                    messages.error(request, f"Invalid price format: {str(e)}")
                    return render(request, 'upload_game.html', {
                        'categories': categories,
                        'form_data': form_data
                    })

                # Validate required files
                if 'game_file' not in request.FILES:
                    messages.error(request, "Game file is required")
                    return render(request, 'upload_game.html', {
                        'categories': categories,
                        'form_data': form_data
                    })

                # Validate screenshots
                screenshots = request.FILES.getlist('screenshots')
                if len(screenshots) < 1:
                    messages.error(request, "At least one screenshot is required")
                    return render(request, 'upload_game.html', {
                        'categories': categories,
                        'form_data': form_data
                    })

                # Validate file types
                valid_image_types = ['image/jpeg', 'image/png', 'image/gif']
                for screenshot in screenshots:
                    if screenshot.content_type not in valid_image_types:
                        messages.error(request, "Only JPG, PNG, and GIF images are allowed for screenshots")
                        return render(request, 'upload_game.html', {
                            'categories': categories,
                            'form_data': form_data
                        })

                # Create submission
                submission = GameSubmission(
                    developer=developer,
                    title=form_data['title'],
                    description=form_data['description'],
                    price=price,
                    version=form_data['version'],
                    min_os=form_data['min_os'],
                    min_processor=form_data['min_processor'],
                    min_ram=form_data['min_ram'],
                    min_gpu=form_data['min_gpu'],
                    min_directx=form_data['min_directx'],
                    rec_os=form_data['rec_os'],
                    rec_processor=form_data['rec_processor'],
                    rec_ram=form_data['rec_ram'],
                    rec_gpu=form_data['rec_gpu'],
                    rec_directx=form_data['rec_directx'],
                    game_file=request.FILES['game_file'],
                    thumbnail=request.FILES['thumbnail'],
                    trailer=request.FILES.get('trailer'),
                    community_name=form_data.get('community_name', '').strip(),
                    community_description='',
                )
                submission.save()

                # Handle categories
                category_ids = form_data.getlist('categories')
                submission.categories.set(category_ids)

                # Handle screenshots
                for file in screenshots:
                    GameScreenshot.objects.create(
                        game_submission=submission, 
                        image=file
                    )

                messages.success(request, 'Game submitted for review!')
                return redirect('developer_dashboard')

            except KeyError as e:
                messages.error(request, f"Missing required field: {str(e)}")
                return render(request, 'upload_game.html', {
                    'categories': categories,
                    'form_data': form_data
                })
                
            except Exception as e:
                messages.error(request, f'Submission error: {str(e)}')
                return render(request, 'upload_game.html', {
                    'categories': categories,
                    'form_data': form_data
                })

        return render(request, 'upload_game.html', {
            'categories': categories
        })

    except (Customer.DoesNotExist, Developer.DoesNotExist):
        messages.error(request, 'Developer account required for game submissions')
        return redirect('home')


@login_required
def delete_submission(request, submission_id):
    try:
        # Retrieve the developer associated with the current user
        developer = request.user.customer.developer
        
        # Retrieve the submission or return a 404 if not found, ensuring it's associated with the developer
        submission = get_object_or_404(
            GameSubmission,
            id=submission_id,
            developer=developer  # Ensure the submission belongs to the logged-in developer
        )
        
        if request.method == 'POST':  # Check for POST request to confirm deletion
            submission.delete()  # Delete the submission
            
            messages.success(request, "Submission and associated game permanently deleted")  # Success message
            return redirect('developer_dashboard')  # Redirect to the developer dashboard

        return redirect('developer_dashboard')  # Redirect if not a POST request

    except Exception as e:
        # Handle any exceptions that occur during deletion
        messages.error(request, f"Deletion failed: {str(e)}")  # Error message
        return redirect('developer_dashboard')  # Redirect to the developer dashboard
    
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)  # Ensure only staff or superusers can access this view
def review_submissions(request):
    # Get all pending submissions and optimize with prefetching categories
    submissions = GameSubmission.objects.filter(status='pending').prefetch_related('categories')
    # Render the submission review page with the list of submissions
    return render(request, 'admin/review_submissions.html', {'submissions': submissions})
    
    
# views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.db import transaction
from decimal import Decimal, InvalidOperation

from .models import (
    GameSubmission,
    Game,
    Community,
)
# (import Category or other models here if your templates need them)


@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def review_submissions(request):
    """
    List all pending game submissions for staff to review.
    """
    submissions = (
        GameSubmission.objects
        .filter(status='pending')
        .prefetch_related('categories')
    )
    return render(request, 'admin/review_submissions.html', {
        'submissions': submissions,
    })


@login_required
@user_passes_test(lambda u: u.is_staff)
@transaction.atomic
def review_submission(request, submission_id):
    """
    Review (approve/reject) a single submission.
    On approval, publish a Game and create its Community.
    """
    submission = get_object_or_404(
        GameSubmission.objects
            .select_related('developer__user')
            .prefetch_related('categories', 'gamescreenshot_set'),
        id=submission_id
    )

    if request.method == 'POST':
        # Must confirm action in the form
        if request.POST.get('confirmed') != 'true':
            messages.error(request, "Action not confirmed.")
            return redirect('review_submission', submission_id=submission_id)

        action = request.POST.get('action')
        notes = request.POST.get('notes', '')
        dev_notes = request.POST.get('developer_notes', '')

        try:
            if action == 'approve':
                if submission.status != 'pending':
                    messages.error(request, "Only pending submissions can be approved.")
                    return redirect('review_submission', submission_id=submission_id)

                # Create or update the Game record
                game, created = Game.objects.update_or_create(
                    submission=submission,
                    defaults={
                        'name':        submission.title,
                        'description': submission.description,
                        'developer':   submission.developer,
                        'price':       submission.price,
                        'image':       submission.thumbnail,
                        'approved':    True,
                        'sale_price':  submission.price * (1 - submission.discount_percentage / 100),
                        'is_on_sale':  submission.sale_enabled,
                    }
                )
                game.categories.set(submission.categories.all())

                # Mark submission approved
                submission.status = 'approved'
                messages.success(request, 'Game approved and published!')

                community_title = (
                    submission.community_name.strip()
                    if submission.community_name else
                    game.name
                )

                # Only create if it doesn't already exist
                if not hasattr(game, 'official_community'):
                    comm = Community.objects.create(
                        name=community_title,
                        description='',                    
                        created_by=submission.developer.user,
                        game=game,
                        is_public=True,
                    )
                 
                    comm.admins.add(submission.developer.user)
                    comm.members.add(submission.developer.user)
              
            elif action == 'reject':
                if submission.status != 'pending':
                    messages.error(request, "Only pending submissions can be rejected.")
                    return redirect('review_submission', submission_id=submission_id)

                submission.status = 'rejected'
                messages.warning(request, 'Submission rejected.')

            else:
                messages.error(request, "Unknown action.")
                return redirect('review_submission', submission_id=submission_id)

            # Save admin & developer notes and final submission state
            submission.admin_notes = notes
            submission.developer_notes = dev_notes
            submission.save()

            return redirect('review_submissions')

        except Exception as e:
            messages.error(request, f'Error during review: {e}')
            return redirect('review_submissions')

    # GET: show the review form
    return render(request, 'admin/review_submission.html', {
        'submission': submission,
        'categories': submission.categories.all(),
    })



def edit_submission(request, submission_id):
    try:
        customer = request.user.customer
        submission = get_object_or_404(GameSubmission, id=submission_id, developer=customer.developer)
        
        if request.method == 'POST':
            try:
                # Update price
                submission.price = Decimal(request.POST.get('price', submission.price))
                
                # Determine if sale is enabled
                submission.sale_enabled = 'enable_discount' in request.POST
                submission.sale_type = request.POST.get('sale_type', '')
                
                # Calculate discount and sale price (for validation, but don't save to submission)
                discount = Decimal('0')
                if submission.sale_enabled:
                    if submission.sale_type == 'summer':
                        discount = Decimal('0.20')
                    elif submission.sale_type == 'spring':
                        discount = Decimal('0.15')
                    elif submission.sale_type == 'winter':
                        discount = Decimal('0.25')
                    elif submission.sale_type == 'custom':
                        discount = Decimal(request.POST.get('discount_percentage', '0')) / Decimal('100')

                submission.discount_percentage = discount * 100  # Save discount percentage
                
                # Remove line setting submission.sale_price
                
                # Update game file
                if 'game_file' in request.FILES:
                    submission.game_file = request.FILES['game_file']
                
                # Developer notes
                submission.developer_notes = request.POST.get('developer_notes', '')
                
                if submission.status == 'approved':
                    submission.status = 'pending'
                    messages.info(request, "Resubmitted for approval after edits.")
                
                submission.save()
                messages.success(request, "Submission updated successfully!")
                return redirect('developer_dashboard')
            
            except (InvalidOperation, ValidationError) as e:
                messages.error(request, f"Error updating submission: {str(e)}")
        
        return render(request, 'edit_submission.html', {'submission': submission})
    
    except (Customer.DoesNotExist, AttributeError):
        messages.error(request, "Authorization failed")
        return redirect('home')


@login_required
def delete_submission(request, submission_id):
    try:
        customer = request.user.customer
        developer = customer.developer
        submission = get_object_or_404(GameSubmission, id=submission_id, developer=developer)
        
        if request.method == 'POST':
            submission.delete()
            messages.success(request, "Submission deleted successfully")
            return redirect('developer_dashboard')
        
        return redirect('developer_dashboard')

    except (Customer.DoesNotExist, Developer.DoesNotExist):
        messages.error(request, "Authorization failed")
        return redirect('home')
    
# ======================
# order Views
# ======================

@login_required
def cart_view(request):
    customer = request.user.customer
    cart, created = Cart.objects.get_or_create(customer=customer)
    context = {
        'cart': cart,
        'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY  # Add this line
    }
    return render(request, 'cart.html', context)


@login_required
def add_to_cart(request, game_id):
    game = get_object_or_404(Game, id=game_id)
    customer = request.user.customer
    
    cart, created = Cart.objects.get_or_create(customer=customer)
    
    cart_item, created = CartItem.objects.get_or_create(
        cart=cart,
        game=game,
        defaults={'quantity': 1}
    )
    
    if not created:
        cart_item.quantity += 1
        cart_item.save()
        messages.info(request, f'"{game.name}" quantity updated in cart!')
    else:
        messages.success(request, f'"{game.name}" added to cart successfully!')
    
    return redirect(request.META.get('HTTP_REFERER', reverse('game_details', kwargs={'game_id': game.id})))

@receiver([post_save, post_delete], sender=CartItem)
def clear_cart_cache(sender, instance, **kwargs):
    user = instance.cart.customer.user
    cache.delete(f'cart_count_{user.id}')

@login_required
def download_game(request, game_id):
    try:
        game = Game.objects.get(
            id=game_id,
            price=0,
            cart_items__cart__customer=request.user.customer
        )
        
        if game.submission and game.submission.game_file:
            # Record download history
            DownloadHistory.objects.create(
                user=request.user.customer,
                game=game,
                download_type='single'
            )
            
            # Increment download count
            game.submission.download_count += 1
            game.submission.save(update_fields=['download_count'])
            
            # Determine the filename to use: original if available, else stored name
            filename = game.submission.original_filename or os.path.basename(game.submission.game_file.name)
            
            return FileResponse(
                game.submission.game_file.open(),
                filename=filename,
                as_attachment=True
            )
    except Game.DoesNotExist:
        pass
    return HttpResponse("File not available", status=404)

@login_required
def download_free_games(request):
    game_ids = request.GET.get('game_ids', '').split(',')
    games = Game.objects.filter(
        id__in=game_ids,
        price=0,
        cart_items__cart__customer=request.user.customer 
    ).prefetch_related('submission')

    # Create in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for game in games:
            if game.submission and game.submission.game_file:
                file_path = game.submission.game_file.path
                if os.path.exists(file_path):
                    # Use the original filename if available, else the stored file name
                    arcname = game.submission.original_filename or os.path.basename(file_path)
                    zipf.write(file_path, arcname)
                    
                    # Record batch download history
                    DownloadHistory.objects.create(
                        user=request.user.customer,
                        game=game,
                        download_type='batch'
                    )
                    
                    # Increment download count
                    game.submission.download_count += 1
                    game.submission.save(update_fields=['download_count'])

    zip_buffer.seek(0)
    response = HttpResponse(zip_buffer.read(), content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="free_games.zip"'
    return response


@require_POST
@login_required
def delete_selected_items(request):
    try:
        data = json.loads(request.body)
        item_ids = data.get('item_ids', [])
        CartItem.objects.filter(
            id__in=item_ids,
            cart__customer=request.user.customer
        ).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@require_POST
@login_required
def remove_from_cart(request, item_id):
    try:
        cart_item = CartItem.objects.select_related('cart').get(
            id=item_id,
            cart__customer=request.user.customer
        )
        cart_item.delete()
        return JsonResponse({'success': True})
    except CartItem.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Item not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
# ======================
# Miscellaneous Views
# ======================

# Render the about us page.
def aboutus(request):
    return render(request, 'aboutus.html', {})


def privacy_policy(request):
    policy = PrivacyPolicy.get_latest_policy()
    return render(request, 'privacy_policy.html', {'policy': policy})

@staff_member_required
def update_privacy_policy(request):
    latest_policy = PrivacyPolicy.get_latest_policy()
    
    if request.method == 'POST':
        form = PrivacyPolicyForm(request.POST)
        if form.is_valid():
            # Create new version instead of updating existing
            new_policy = form.save(commit=False)
            new_policy.effective_date = time.timezone.now()
            new_policy.save()
            messages.success(request, 'Privacy policy updated successfully')
            return redirect('privacy_policy')
    else:
        form = PrivacyPolicyForm(instance=latest_policy)

    return render(request, 'admin/update_privacy_policy.html', {
        'form': form,
        'title': 'Update Privacy Policy'
    })


from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import json
import requests
import logging

logger = logging.getLogger(__name__)

@login_required
def create_khalti_checkout(request):
    if request.method == 'POST':
        try:
            customer = request.user.customer
            data = json.loads(request.body)
            game_ids = data.get('game_ids', [])
            
            # Get cart items with quantity validation
            items = CartItem.objects.filter(
                cart=customer.cart,
                game__id__in=game_ids
            ).select_related('game')
            
            if not items.exists():
                return JsonResponse({'error': 'No items in cart'}, status=400)

            # Calculate total amounts
            total_decimal = sum(
                (item.game.sale_price if item.game.is_on_sale else item.game.price) * item.quantity
                for item in items
            )
            total_paisa = int(total_decimal * 100)  # Convert to paisa for Khalti

            if total_paisa < 1000:  # Khalti minimum amount (10 NPR)
                return JsonResponse({'error': 'Minimum payment amount is NPR 10'}, status=400)

            # Create order record
            order = Order.objects.create(
                customer=customer,
                total_amount=total_decimal,
                payment_status='pending'
            )

            # Create order items with quantities
            order_items = [
                OrderItem(
                    order=order,
                    game=item.game,
                    quantity=item.quantity,
                    price=item.game.sale_price if item.game.is_on_sale else item.game.price
                ) for item in items
            ]
            OrderItem.objects.bulk_create(order_items)
            
            # Add games to M2M relationship
            order.games.add(*[item.game for item in items])

            # Initiate Khalti payment
            return_url = f"{settings.SITE_URL}/khalti/callback/"
            response = initiate_khalti_payment(
                order_id=order.id,
                amount=total_paisa,
                return_url=return_url
            )

            if 'pidx' in response:
                order.khalti_pidx = response['pidx']
                order.save()
                return JsonResponse({'payment_url': response['payment_url']})

            logger.error(f'Khalti initiation failed: {response}')
            return JsonResponse({
                'error': 'Payment initialization failed',
                'detail': response.get('detail', 'Unknown error')
            }, status=400)

        except Exception as e:
            logger.exception("Payment processing error")
            return JsonResponse({'error': str(e)}, status=500)

def initiate_khalti_payment(order_id, amount, return_url):
    """Handle Khalti payment initiation"""
    url = "https://a.khalti.com/api/v2/epayment/initiate/"
    headers = {
        "Authorization": f"Key {settings.KHALTI_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "return_url": return_url,
        "website_url": settings.SITE_URL,
        "amount": amount,
        "purchase_order_id": str(order_id),
        "purchase_order_name": f"GamePurchase_{order_id}",
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Khalti API Error: {str(e)}")
        return {'error': 'Payment gateway communication failed'}

@csrf_exempt
def khalti_callback(request):
    """Handle Khalti payment callback"""
    pidx = request.GET.get('pidx')
    if not pidx:
        return redirect('payment-failed')

    try:
        # Verify payment with Khalti API
        verify_url = "https://a.khalti.com/api/v2/epayment/lookup/"
        headers = {"Authorization": f"Key {settings.KHALTI_SECRET_KEY}"}
        response = requests.post(verify_url, json={"pidx": pidx}, headers=headers)
        response.raise_for_status()
        response_data = response.json()

        order = Order.objects.get(khalti_pidx=pidx)
        
        if response_data.get('status') == 'Completed':
            # Validate amount match
            if (order.total_amount * 100) != response_data.get('total_amount', 0):
                logger.error(f"Amount mismatch for order {order.id}")
                order.payment_status = 'failed'
                order.save()
                return redirect('payment-failed')

            # Update order status
            order.payment_status = 'completed'
            order.khalti_transaction_id = response_data.get('transaction_id')
            order.save()

            # Clear purchased cart items
            CartItem.objects.filter(
                cart=order.customer.cart,
                game__in=order.games.all()
            ).delete()

            return redirect('payment-success')

        # Handle failed statuses
        order.payment_status = 'failed'
        order.failure_reason = response_data.get('status', 'Unknown')
        order.save()
        return redirect('payment-failed')

    except Order.DoesNotExist:
        logger.error(f"Order not found for pidx: {pidx}")
        return redirect('payment-failed')
    except Exception as e:
        logger.exception("Callback processing error")
        return redirect('payment-failed')

# ======================
# Payment Status Views
# ======================
def payment_success(request):
    try:
        order = Order.objects.filter(
            customer=request.user.customer,
            payment_status='completed'
        ).prefetch_related('games').latest('created_at')
        
        return render(request, 'payments/success.html', {
            'order': order,
            'games': order.games.all()
        })
    except Order.DoesNotExist:
        return redirect('payment-failed')

def payment_failed(request):
    return render(request, 'payments/failed.html')

# ======================
# Download Management
# ======================

@login_required
def download_purchased_game(request, game_id):
    try:
        customer = request.user.customer
        game = get_object_or_404(Game, id=game_id)
        
        # Verify purchase through both OrderItems and M2M relationship
        purchased = Order.objects.filter(
            customer=customer,
            payment_status='completed',
            games=game
        ).exists()

        if not purchased:
            return HttpResponse("You don't own this game or payment wasn't completed", status=403)

        # Check file availability
        if not game.submission or not game.submission.game_file:
            logger.error(f"Game file missing for {game.name} (ID: {game_id})")
            return HttpResponse("Game file not available", status=404)

        # Record download history
        DownloadHistory.objects.create(
            user=customer,
            game=game,
            download_type='single'
        )

        # Update download count
        game.submission.download_count += 1
        game.submission.save()

        # Serve the file with proper headers
        response = FileResponse(
            game.submission.game_file.open(),
            filename=game.submission.original_filename or game.submission.game_file.name,
            as_attachment=True
        )
        
        # Add security headers
        response['Content-Security-Policy'] = "default-src 'self'"
        response['X-Content-Type-Options'] = "nosniff"
        
        return response

    except Exception as e:
        logger.error(f"Download error: {str(e)}", exc_info=True)
        return HttpResponse("Error downloading file", status=500)