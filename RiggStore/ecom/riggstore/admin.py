from django.contrib import admin
from .models import Category, Customer, Community, Developer, Game, Order, Post,Comment
# Register your models here.
admin.site.register(Category)
admin.site.register(Customer)
admin.site.register(Community)
admin.site.register(Developer)
admin.site.register(Game)
admin.site.register(Order)
admin.site.register(Post)

admin.site.register(Comment)

# riggstore/admin.py
from django.contrib import admin
from .models import GameSubmission, GameScreenshot

@admin.register(GameSubmission)
class GameSubmissionAdmin(admin.ModelAdmin):
    list_display = ('title', 'developer', 'status', 'submitted_at')
    list_filter = ('status',)

@admin.register(GameScreenshot)
class GameScreenshotAdmin(admin.ModelAdmin):
    list_display = ('game_submission', 'image')  # Corrected field name

