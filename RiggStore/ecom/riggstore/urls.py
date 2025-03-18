from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.home, name='home'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('signup/', views.signup_user, name='signup'),
    
    # Community
    path('community/', views.community, name='community'),
    path('community/create/', views.create_community, name='create_community'),
    path('community/<int:community_id>/', views.community_detail, name='community_detail'),
    path('community/<int:community_id>/post/create/', views.create_post, name='create_post'),
    path('community/<int:community_id>/delete/', views.delete_community, name='delete_community'),
    path('community/<int:community_id>/members/', views.community_members, name='community_members'),
    path('community/<int:community_id>/promote/<int:user_id>/', views.promote_to_moderator, name='promote_to_moderator'),
    path('community/<int:community_id>/demote/<int:user_id>/', views.demote_to_member, name='demote_to_member'),
    path('community/<int:community_id>/kick/<int:user_id>/', views.kick_member, name='kick_member'),
    path('community/<int:community_id>/edit/', views.edit_community, name='edit_community'),

    # Posts & Interactions
    path('post/<int:post_id>/like/', views.like_post, name='like_post'),
    path('post/<int:post_id>/comment/', views.create_comment, name='create_comment'),
    path('post/<int:post_id>/delete/', views.delete_post, name='delete_post'),
    path('comment/<int:comment_id>/delete/', views.delete_comment, name='delete_comment'),
    path('community/<int:community_id>/join/', views.join_community, name='join_community'),
    
    # User Account
    path('account/', views.account, name='account'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
    path('change-password/', views.change_password, name='change_password'),
    path('upload-profile-image/', views.upload_profile_image, name='upload_profile_image'),
    path('verify-password/', views.verify_password, name='verify_password'),
    
    # Admin
    path('admin-panel/', views.admin_dashboard, name='admin_panel'),
    path('admin-panel/delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('admin-panel/delete-community/<int:community_id>/', views.admin_delete_community, name='admin_delete_community'),
    path('delete-submission/<int:submission_id>/', views.delete_submission, name='delete_submission'),

    # Game Management
    path('game/<int:game_id>/', views.game_details, name='game_details'),
    path('upload-game/', views.upload_game, name='upload_game'),
    path('review-submissions/', views.review_submissions, name='review_submissions'),
    path('review-submission/<int:submission_id>/', views.review_submission, name='review_submission'),
    path('developer/dashboard/', views.developer_dashboard, name='developer_dashboard'),
    path('edit-submission/<int:submission_id>/', views.edit_submission, name='edit_submission'),
    path('games/', views.game_list, name='game_list'),
    
    # Miscellaneous
    path('aboutus/', views.aboutus, name='aboutus'),
]