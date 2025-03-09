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

from django.contrib import admin
from .models import GameSubmission, GameScreenshot

@admin.register(GameSubmission)
class GameSubmissionAdmin(admin.ModelAdmin):
    list_display = ('title', 'developer', 'status', 'submitted_at')
    list_filter = ('status',)
    search_fields = ('title', 'developer__user__username')

@admin.register(GameScreenshot)
class GameScreenshotAdmin(admin.ModelAdmin):
    list_display = ('submission', 'image_preview')  # Changed from 'game' to 'submission'
    readonly_fields = ('image_preview',)
    
    def image_preview(self, obj):
        return obj.image.url if obj.image else 'No image'
    image_preview.short_description = 'Preview'