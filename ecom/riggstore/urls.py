from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.home, name='home'),  # Home page
    path('login/', views.login_user, name='login'),  # User login
    path('logout/', views.logout_user, name='logout'),  # User logout
    path('signup/', views.signup_user, name='signup'),  # User signup
    
    # Community
    path('community/', views.community, name='community'),  # Community overview
    path('community/create/', views.create_community, name='create_community'),  # Create a new community
    path('community/<int:community_id>/', views.community_detail, name='community_detail'),  # Community detail view
    path('community/<int:community_id>/post/create/', views.create_post, name='create_post'),  # Create a post in a community
    path('community/<int:community_id>/delete/', views.delete_community, name='delete_community'),  # Delete a community
    path('community/<int:community_id>/members/', views.community_members, name='community_members'),  # View community members
    path('community/<int:community_id>/promote/<int:user_id>/', views.promote_to_moderator, name='promote_to_moderator'),  # Promote user to moderator
    path('community/<int:community_id>/demote/<int:user_id>/', views.demote_to_member, name='demote_to_member'),  # Demote user to member
    path('community/<int:community_id>/kick/<int:user_id>/', views.kick_member, name='kick_member'),  # Kick a member from the community
    path('community/<int:community_id>/edit/', views.edit_community, name='edit_community'),  # Edit community settings

    # Posts & Interactions
    path('post/<int:post_id>/like/', views.like_post, name='like_post'),  # Like a post
    path('post/<int:post_id>/comment/', views.create_comment, name='create_comment'),  # Comment on a post
    path('post/<int:post_id>/delete/', views.delete_post, name='delete_post'),  # Delete a post
    path('comment/<int:comment_id>/delete/', views.delete_comment, name='delete_comment'),  # Delete a comment
    path('community/<int:community_id>/join/', views.join_community, name='join_community'),  # Join a community
    
    # User Account
    path('account/', views.account, name='account'),  # User account overview
    path('edit-profile/', views.edit_profile, name='edit_profile'),  # Edit user profile
    path('change-password/', views.change_password, name='change_password'),  # Change user password
    path('upload-profile-image/', views.upload_profile_image, name='upload_profile_image'),  # Upload profile image
    path('verify-password/', views.verify_password, name='verify_password'),  # Verify user password
    
    # Admin
    path('admin-panel/', views.admin_dashboard, name='admin_panel'),  # Admin dashboard
    path('admin-panel/delete-user/<int:user_id>/', views.delete_user, name='delete_user'),  # Delete a user
    path('admin-panel/delete-community/<int:community_id>/', views.admin_delete_community, name='admin_delete_community'),  # Admin delete community

    # Game Management
    path('game/<int:game_id>/', views.game_detail, name='game_details'),  # Game detail page
    path('upload-game/', views.upload_game, name='upload_game'),  # Upload game
    path('developer/dashboard/', views.developer_dashboard, name='developer_dashboard'),  # Developer dashboard

    # Review Submissions
    path('review-submissions/', views.review_submissions, name='review_submissions'),  # Review all submissions
    path('review-submission/<int:submission_id>/', views.review_submission, name='review_submission'),  # Review a specific submission
    path('delete-submission/<int:submission_id>/', views.delete_submission, name='delete_submission'),  # Delete a submission
    
    # Miscellaneous
    path('aboutus/', views.aboutus, name='aboutus'),  # About us page
]