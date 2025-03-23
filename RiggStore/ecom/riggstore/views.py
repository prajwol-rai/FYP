from decimal import Decimal, InvalidOperation
from io import BytesIO
from venv import logger
import zipfile
from django.forms import ValidationError
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.core.mail import send_mail
import json

from .models import Category, CommunityMember, Game, Customer, Developer, Community, Post, Comment, GameSubmission, GameScreenshot
from .forms import (
    CustomPasswordChangeForm,
    SignUpForm,
    UserEditForm,
    CommunityForm,
    PostForm,
    GameUploadForm
)

# ======================
# Authentication Views
# ======================


def home(request):
    games = Game.objects.filter(approved=True)
    return render(request, 'home.html', {'games': games})

from django.contrib.auth import login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from django.db import IntegrityError
from .forms import SignUpForm  # Ensure you have your form imported
from .models import User, Customer, Developer  # Ensure the models are imported

from django.db import IntegrityError
from django.contrib.auth import login, authenticate
from django.core.mail import send_mail

def signup_user(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            try:
                # Create User
                user = User.objects.create_user(
                    username=form.cleaned_data['username'],
                    password=form.cleaned_data['password1'],
                    first_name=form.cleaned_data['first_name'],
                    last_name=form.cleaned_data['last_name'],
                    email=form.cleaned_data['email']
                )

                # Create Customer
                customer, created = Customer.objects.get_or_create(
                    user=user,
                    defaults={
                        'f_name': form.cleaned_data['first_name'],
                        'l_name': form.cleaned_data['last_name'],
                        'email': form.cleaned_data['email'],
                        'phone': form.cleaned_data['phone']
                    }
                )

                # Create Developer if needed
                if form.cleaned_data['account_type'] == 'developer':
                    Developer.objects.get_or_create(
                        user=customer,  # Use customer instance here
                        defaults={'company_name': '', 'approved': False}
                    )

                # Send welcome email
                send_mail(
                    "Welcome to RiggStore!",
                    f"Hello {user.first_name},\n\nAccount created as {form.cleaned_data['account_type']}!",
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False
                )

                login(request, user)
                messages.success(request, "Account Created Successfully")
                return redirect('home')

            except IntegrityError as e:
                messages.error(request, "Account creation failed. Please try different credentials.")
            except Exception as e:
                messages.error(request, f"Error: {str(e)}")
            return render(request, 'signup.html', {'form': form})
        else:
            return render(request, 'signup.html', {'form': form})
    
    return render(request, 'signup.html', {'form': SignUpForm()})

# Handle user login, authenticate and redirect appropriately.
def login_user(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            request.session.set_expiry(1209600)  # 2 weeks
            if user.is_staff or user.is_superuser:
                messages.success(request, "Admin logged in successfully")
                return redirect('admin_panel')
            messages.success(request, "Logged In Successfully")
            return redirect(request.POST.get('next', 'account'))
        messages.error(request, "Invalid username or password")
    return render(request, 'login.html', {})

# Log out the user and redirect to the home page.
def logout_user(request):
    logout(request)
    messages.success(request, "Logged Out")
    return redirect('home')

# ======================
# Community Views
# ======================
# In your view function
@login_required
def community(request):
    joined_communities = []
    discover_communities = Community.objects.all().order_by('-created_at')
    
    if request.user.is_authenticated:
        customer, created = Customer.objects.get_or_create(
            user=request.user,
            defaults={
                'f_name': request.user.first_name,
                'l_name': request.user.last_name,
                'email': request.user.email,
            }
        )
        
        joined_communities = customer.joined_communities.all().order_by('-created_at')
        discover_communities = Community.objects.exclude(
            id__in=joined_communities.values_list('id', flat=True)
        ).order_by('-created_at')
    
    context = {
        'joined_communities': joined_communities,
        'discover_communities': discover_communities,
        'community_form': CommunityForm()
    }
    return render(request, 'community.html', context)


@login_required
@require_POST
def create_community(request):
    try:
        form = CommunityForm(request.POST)
        if form.is_valid():
            community = form.save(commit=False)
            community.created_by = request.user.customer
            community.save()
            # Add creator as admin and member
            community.add_admin(request.user.customer)
            community.members.add(request.user.customer)  # Add this line
            return JsonResponse({
                'success': True,
                'community_name': community.name,
                'community_id': community.id
            }, status=201)
        return JsonResponse({
            'success': False,
            'errors': form.errors.get_json_data()
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': [str(e)]}
        }, status=500)
    
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Community
from .forms import CommunityForm

@login_required
def edit_community(request, community_id):
    community = get_object_or_404(Community, id=community_id)
    # Only allow the creator to edit the community
    if request.user.customer != community.created_by:
        messages.error(request, "You are not authorized to edit this community.")
        return redirect('community_detail', community_id=community.id)

    if request.method == 'POST':
        form = CommunityForm(request.POST, instance=community)
        if form.is_valid():
            form.save()
            messages.success(request, "Community updated successfully!")
            return redirect('community_detail', community_id=community.id)
    else:
        form = CommunityForm(instance=community)
    
    return render(request, 'edit_community.html', {'form': form, 'community': community})

# Render the details of a specific community and its posts.
def community_detail(request, community_id):
    community_obj = get_object_or_404(Community, id=community_id)
    context = {
        'community_obj': community_obj,
        'posts': Post.objects.filter(community=community_obj).order_by('-created_at'),
        'post_form': PostForm(),
        'other_communities': Community.objects.exclude(id=community_obj.id).order_by('-created_at')[:5]
    }
    return render(request, 'community_detail.html', context)

@login_required
@require_POST
def join_community(request, community_id):
    community = get_object_or_404(Community, id=community_id)
    customer = request.user.customer
    
    if community.members.filter(id=customer.id).exists():
        community.members.remove(customer)
        joined = False
    else:
        community.members.add(customer)
        joined = True
    
    return JsonResponse({
        'success': True,
        'joined': joined,
        'member_count': community.members.count()
    })

@login_required
def community_members(request, community_id):
    community = get_object_or_404(Community, id=community_id)
    
    # Check if the user is a member of the community
    user_membership = community.members.filter(user=request.user).first()
    
    is_admin = False
    if user_membership:
        is_admin = community.admins.filter(id=user_membership.id).exists()

    # Get all admins
    admins = community.admins.all()
    
    # Get regular members (excluding admins)
    regular_members = community.members.exclude(id__in=admins.values('id'))

    # If the viewer is an admin, show all members
    if is_admin:
        regular_members = community.members.all()

    # Get moderators, assuming you have a way to identify them
    moderators = community.members.filter(communitymember__role='moderator')

    context = {
        'community': community,
        'admins': admins,
        'moderators': moderators,
        'regular_members': regular_members,
        'regular_members_count': regular_members.count(),
        'is_admin': is_admin,
    }
    return render(request, 'community_members.html', context)

@login_required
def promote_to_moderator(request, community_id, user_id):
    community = get_object_or_404(Community, id=community_id)
    user = get_object_or_404(User, id=user_id)
    customer = user.customer

    if request.user.customer in community.admins.all():
        # Get or create CommunityMember entry
        member_entry, created = CommunityMember.objects.get_or_create(
            community=community,
            customer=customer,
            defaults={'role': 'moderator'}
        )
        if not created:
            member_entry.role = 'moderator'
            member_entry.save()
    return redirect('community_members', community_id=community.id)

@login_required
def demote_to_member(request, community_id, user_id):
    community = get_object_or_404(Community, id=community_id)
    user = get_object_or_404(User, id=user_id)
    customer = user.customer

    if request.user.customer in community.admins.all():
        try:
            member_entry = CommunityMember.objects.get(
                community=community,
                customer=customer
            )
            member_entry.role = 'member'
            member_entry.save()
        except CommunityMember.DoesNotExist:
            pass
    return redirect('community_members', community_id=community.id)

@login_required
def kick_member(request, community_id, user_id):
    community = get_object_or_404(Community, id=community_id)
    user = get_object_or_404(User, id=user_id)
    customer = user.customer

    if customer == community.created_by:
        messages.error(request, "You cannot kick the community creator.")
        return redirect('community_members', community_id=community.id)

    if request.user.customer in community.admins.all():
        # Remove from both members and CommunityMember entries
        community.members.remove(customer)
        CommunityMember.objects.filter(
            community=community,
            customer=customer
        ).delete()
    return redirect('community_members', community_id=community.id)


# Delete a community if the user is the creator.
@login_required
@require_POST
def delete_community(request, community_id):
    try:
        community = get_object_or_404(Community, id=community_id)
        
        if request.user.customer != community.created_by:
            return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)
        
        community.delete()
        return JsonResponse({
            'success': True,
            'message': 'Community deleted successfully',
            'redirect_url': reverse('community')
        }, status=200)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# ======================
# Post & Comment Views
# ======================

# Create a new post in a specific community.
@login_required
@require_POST
def create_post(request, community_id):
    try:
        community_obj = get_object_or_404(Community, id=community_id)
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.community = community_obj
            post.author = request.user.customer
            post.save()
            return JsonResponse({
                'success': True,
                'post_id': post.id,
                'content': post.content,
                'author': post.author.f_name,
                'created_at': post.created_at.strftime('%b %d, %Y %H:%M')
            }, status=201)
        return JsonResponse({
            'success': False,
            'errors': form.errors.as_json()
        }, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# Like or unlike a post and return the updated like count.
@login_required
@require_POST
def like_post(request, post_id):
    try:
        post = get_object_or_404(Post, id=post_id)
        customer = request.user.customer
        
        if post.likes.filter(id=customer.id).exists():
            post.likes.remove(customer)
            liked = False
        else:
            post.likes.add(customer)
            liked = True
            
        return JsonResponse({
            'success': True,
            'liked': liked,
            'like_count': post.likes.count()
        }, status=200)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# Create a comment on a post.
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST

@login_required
@require_POST
def create_comment(request, post_id):
    try:
        post = get_object_or_404(Post, id=post_id)
        text = request.POST.get('text', '').strip()
        
        if not text:
            return JsonResponse({'error': 'Comment cannot be empty'}, status=400)

        # Verify user has a customer profile
        if not hasattr(request.user, 'customer'):
            return JsonResponse({'error': 'User profile incomplete'}, status=403)
            
        comment = Comment.objects.create(
            post=post,
            user=request.user.customer,
            text=text
        )
        
        return JsonResponse({
            'success': True,
            'comment_id': comment.id,
            'user_name': request.user.customer.f_name,
            'user_image': request.user.customer.image.url if request.user.customer.image else '',
            'text': comment.text,
            'is_owner': True,
            'created_at': comment.created_at.strftime('%b. %d, %Y, %I:%M %p')
        })
        
    except Exception as e:
        # Log the error here (consider adding logging)
        return JsonResponse({
            'error': 'Server error',
            'detail': str(e)
        }, status=500)

# Delete a post if the user is the author.

# views.py
@login_required
@require_POST
def delete_post(request, post_id):
    try:
        post = get_object_or_404(Post, id=post_id)
        user = request.user.customer
        community = post.community

        # Check if the user is the post author, community owner, or a moderator
        is_moderator = community.communitymember_set.filter(customer=user, role='moderator').exists()
        allowed = (
            user == post.author or  # Post author
            user == community.created_by or  # Community owner
            is_moderator  # Moderator check
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

        # Check if the user is the comment author, post author, community owner, or a moderator
        is_moderator = community.communitymember_set.filter(customer=user, role='moderator').exists()
        allowed = (
            user == comment.user or  # Comment author
            user == comment.post.author or  # Post author
            user == community.created_by or  # Community owner
            is_moderator  # Moderator check
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

# Render the user's account page with their details and download history.
@login_required
def account(request):
    return render(request, 'account.html', {
        'user': request.user,
        'wallet_balance': 100.50,
        'download_history': [
            {'file_name': 'God of War', 'download_date': '2025-02-10'},
            {'file_name': 'CS2', 'download_date': '2025-02-08'},
            {'file_name': 'Dota 2', 'download_date': '2025-02-05'},
            {'file_name': 'Tekken 8', 'download_date': '2025-02-05'},
            {'file_name': 'Valorent', 'download_date': '2025-02-05'},
        ]
    })

# Allow the user to edit their profile information.
@login_required
def edit_profile(request):
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=request.user)
        if form.is_valid():
            user = form.save()
            customer = request.user.customer
            customer.f_name = user.first_name
            customer.l_name = user.last_name
            customer.email = user.email
            customer.save()
            messages.success(request, 'Profile updated successfully')
            return redirect('account')
    else:
        form = UserEditForm(instance=request.user)
    return render(request, 'edit_profile.html', {'form': form})

# Verify the user's password for security purposes.
@require_POST
@login_required
def verify_password(request):
    try:
        data = json.loads(request.body)
        password = data.get('password')
    except json.JSONDecodeError:
        return JsonResponse({'valid': False})
    
    user = authenticate(username=request.user.username, password=password)
    return JsonResponse({'valid': user is not None})

# Allow the user to change their password.
@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            messages.success(request, 'Password changed successfully')
            return redirect('account')
    return render(request, 'change_password.html', {'form': CustomPasswordChangeForm(user=request.user)})

# Upload a new profile image for the user.
@login_required
def upload_profile_image(request):
    if request.method == 'POST' and 'image' in request.FILES:
        try:
            customer = request.user.customer
            customer.image = request.FILES['image']
            customer.save()
            messages.success(request, 'Profile image updated successfully')
        except Exception as e:
            messages.error(request, f'Error updating profile image: {str(e)}')
    return redirect('account')

# ======================
# Admin Views
# ======================

# Render the admin dashboard with user and community information.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_dashboard(request):
    users = Customer.objects.all().prefetch_related('created_communities', 'joined_communities', 'developer__game_set')
    submissions = GameSubmission.objects.filter(status='pending').order_by('-submitted_at')[:5]
    
    context = {
        'users': users,
        'communities': Community.objects.all(),
        'submissions': submissions
    }
    return render(request, 'admin.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
@require_POST
def delete_submission(request, submission_id):
    submission = get_object_or_404(GameSubmission, id=submission_id)
    submission.delete()
    messages.success(request, "Submission deleted successfully.")
    return redirect('admin_dashboard')

# Delete a user from the system by admin.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def delete_user(request, user_id):
    try:
        # Get the Customer object
        customer = Customer.objects.get(id=user_id)
        
        # Delete the associated User
        user = customer.user
        user.delete()  # This will cascade delete the Customer if models are set up properly
        
        messages.success(request, "User deleted successfully.")
    except Customer.DoesNotExist:
        messages.error(request, "User not found.")
    return redirect('admin_panel')

# Admin functionality to delete a community.
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
@require_POST
def admin_delete_community(request, community_id):
    try:
        community = get_object_or_404(Community, id=community_id)
        community.delete()
        messages.success(request, "Community deleted successfully.")
        return redirect('admin_panel')
    except Exception as e:
        messages.error(request, f"Error deleting community: {str(e)}")
        return redirect('admin_panel')

# ======================
# Game Detail Views
# ======================

# Render the details of a specific game.

def game_details(request, game_id):
    game = get_object_or_404(
        Game.objects.select_related('submission', 'developer__user')
                   .prefetch_related('categories'),
        id=game_id
    )
    return render(request, 'game_details.html', {'game': game})

from django.db.models import Q

def game_list(request):
    games = Game.objects.all().prefetch_related('categories')  # Optimize query
    categories = Category.objects.all().order_by('name') 

    # Search functionality
    search_query = request.GET.get('q', '')
    if search_query:
        games = games.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Category filter
    selected_categories = request.GET.getlist('category')
    if selected_categories:
        games = games.filter(categories__name__in=selected_categories).distinct()
    
    # Sorting
    sort_map = {
        'price_asc': 'price',
        'price_desc': '-price',
        'name_asc': 'name',
        'name_desc': '-name'
    }
    sort_by = request.GET.get('sort', '')
    if sort_by in sort_map:
        games = games.order_by(sort_map[sort_by])
    
    context = {
        'games': games,
        'categories': categories,
        'selected_categories': selected_categories,
        'current_sort': sort_by,
        'search_query': search_query
    }
    return render(request, 'game_list.html', context)

@login_required
def developer_dashboard(request):
    try:
        customer = request.user.customer 
        developer = customer.developer  

        submissions = GameSubmission.objects.filter(developer=developer) 
        return render(request, 'developer_dashboard.html', {'submissions': submissions})

    except Customer.DoesNotExist:
        messages.error(request, "You need a customer profile to access the developer dashboard.")
        return redirect('home')

    except Developer.DoesNotExist:
        messages.error(request, "You are not an approved developer.")
        return redirect('home')

# Add to imports

from django.db import transaction
from django.core.files.uploadedfile import InMemoryUploadedFile
from decimal import Decimal, InvalidOperation

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

# views.py
@login_required
def delete_submission(request, submission_id):
    try:
        developer = request.user.customer.developer
        submission = get_object_or_404(
            GameSubmission,
            id=submission_id,
            developer=developer
        )
        
        if request.method == 'POST':
            # This single delete call will cascade to:
            # 1. Delete Game via CASCADE
            # 2. Delete Game image via Game.delete()
            # 3. Delete submission files via GameSubmission.delete()
            submission.delete()
            
            messages.success(request, "Submission and associated game permanently deleted")
            return redirect('developer_dashboard')

        return redirect('developer_dashboard')

    except Exception as e:
        messages.error(request, f"Deletion failed: {str(e)}")
        return redirect('developer_dashboard')
    
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def review_submissions(request):
    submissions = GameSubmission.objects.filter(status='pending').prefetch_related('categories')
    return render(request, 'admin/review_submissions.html', {'submissions': submissions})
@login_required
@user_passes_test(lambda u: u.is_staff)
def review_submission(request, submission_id):
    submission = get_object_or_404(
        GameSubmission.objects.select_related('developer__user')
                              .prefetch_related('categories', 'gamescreenshot_set'),
        id=submission_id
    )

    if request.method == 'POST':
        confirmed = request.POST.get('confirmed', 'false')
        if confirmed != 'true':
            messages.error(request, "Action not confirmed.")
            return redirect('review_submission', submission_id=submission_id)

        action = request.POST.get('action')
        notes = request.POST.get('notes', '')

        try:
            if action == 'approve':
                if submission.status != 'pending':
                    messages.error(request, "Only pending submissions can be approved.")
                    return redirect('review_submission', submission_id=submission_id)

                game, created = Game.objects.update_or_create(
                    submission=submission,
                    defaults={
                        'name': submission.title,
                        'description': submission.description,
                        'developer': submission.developer,
                        'price': submission.price,
                        'image': submission.thumbnail,
                        'approved': True,
                        'sale_price': Decimal('0.00'),
                        'is_on_sale': False
                    }
                )
                game.categories.set(submission.categories.all())
                submission.status = 'approved'
                messages.success(request, 'Game approved and published!')
            elif action == 'reject':
                if submission.status != 'pending':
                    messages.error(request, "Only pending submissions can be rejected.")
                    return redirect('review_submission', submission_id=submission_id)

                submission.status = 'rejected'
                messages.warning(request, 'Submission rejected.')

            submission.admin_notes = notes
            submission.save()
            return redirect('review_submissions')

        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('review_submissions')

    # Ensure the path to the template is correct
    return render(request, 'admin/review_submission.html', {
        'submission': submission,
        'categories': submission.categories.all()
    })

from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from decimal import Decimal

@login_required
def edit_submission(request, submission_id):
    try:
        customer = request.user.customer
        developer = customer.developer
        submission = get_object_or_404(GameSubmission, id=submission_id, developer=developer)
        categories = Category.objects.all()

        if request.method == 'POST':
            try:
                # Update text fields
                submission.title = request.POST['title']
                submission.description = request.POST['description']
                submission.price = Decimal(request.POST['price'])
                submission.version = request.POST['version']
                
                # Update system requirements
                submission.min_os = request.POST['min_os']
                submission.min_processor = request.POST['min_processor']
                submission.min_ram = request.POST['min_ram']
                submission.min_gpu = request.POST['min_gpu']
                submission.min_directx = request.POST['min_directx']
                submission.rec_os = request.POST['rec_os']
                submission.rec_processor = request.POST['rec_processor']
                submission.rec_ram = request.POST['rec_ram']
                submission.rec_gpu = request.POST['rec_gpu']
                submission.rec_directx = request.POST['rec_directx']

                # Handle file updates
                if 'thumbnail' in request.FILES:
                    submission.thumbnail = request.FILES['thumbnail']
                if 'game_file' in request.FILES:
                    submission.game_file = request.FILES['game_file']
                if 'trailer' in request.FILES:
                    submission.trailer = request.FILES['trailer']

                # Update categories
                category_ids = request.POST.getlist('categories')
                submission.categories.set(category_ids)

                # Handle status changes
                if submission.status == 'approved':
                    submission.status = 'pending'
                    messages.info(request, "Resubmitted for approval after edits")

                # Handle screenshots
                if 'screenshots' in request.FILES:
                    submission.gamescreenshot_set.all().delete()
                    for file in request.FILES.getlist('screenshots'):
                        GameScreenshot.objects.create(game_submission=submission, image=file)

                submission.save()
                messages.success(request, "Submission updated successfully!")
                return redirect('developer_dashboard')

            except Exception as e:
                messages.error(request, f"Error updating submission: {str(e)}")
                return render(request, 'edit_submission.html', {
                    'submission': submission,
                    'categories': categories
                })

        return render(request, 'edit_submission.html', {
            'submission': submission,
            'categories': categories
        })

    except (Customer.DoesNotExist, Developer.DoesNotExist):
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
from .models import Game, Cart, CartItem
@login_required
def cart_view(request):
    customer = request.user.customer
    cart, created = Cart.objects.get_or_create(customer=customer)
    return render(request, 'cart.html', {'cart': cart})

from django.core.cache import cache

@login_required
def add_to_cart(request, game_id):
    game = get_object_or_404(Game, id=game_id)
    customer = request.user.customer

    cart, created = Cart.objects.get_or_create(customer=customer)
    cart_item, created = CartItem.objects.get_or_create(cart=cart, game=game)
    
    if not created:
        cart_item.quantity += 1
        cart_item.save()
    
    # Clear cache for cart count
    cache.delete(f'cart_count_{request.user.id}')
    
    return redirect('cart_view')

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver([post_save, post_delete], sender=CartItem)
def clear_cart_cache(sender, instance, **kwargs):
    user = instance.cart.customer.user
    cache.delete(f'cart_count_{user.id}')

from django.http import FileResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Game
import os
from django.utils.text import slugify

@login_required
@require_POST
def download_free_games(request):
    game_ids = request.POST.getlist('game_ids')
    
    # Validate games exist and are free
    games = Game.objects.filter(
        id__in=game_ids,
        price=0,
        cartitem__cart__customer=request.user.customer
    ).distinct()

    if not games.exists():
        return HttpResponse("No valid free games selected", status=400)

    # Create in-memory ZIP file
    zip_buffer = BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for game in games:
            if game.game_file and os.path.exists(game.game_file.path):
                # Get safe filename
                base_name = slugify(game.name) + os.path.splitext(game.game_file.name)[1]
                zipf.write(game.game_file.path, arcname=base_name)
    
    # Prepare response
    zip_buffer.seek(0)
    response = FileResponse(zip_buffer, content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="free_games.zip"'
    response['Content-Length'] = zip_buffer.getbuffer().nbytes
    
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