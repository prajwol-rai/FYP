from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

# ======================
# Core Models
# ======================

class Category(models.Model):
    name = models.CharField(max_length=50)

    class Meta:
        verbose_name_plural = 'categories'

    def __str__(self):
        return self.name

# ======================
# User Related Models
# ======================

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer', null=True, blank=True)
    f_name = models.CharField(max_length=50)
    l_name = models.CharField(max_length=50)
    email = models.EmailField(max_length=100)
    phone = models.CharField(max_length=15, blank=True, null=True)
    image = models.ImageField(upload_to='profile_pics', default='default.jpg')

    class Meta:
        ordering = ['l_name', 'f_name']

    def __str__(self):
        return f'{self.f_name} {self.l_name}'

class Developer(models.Model):
    user = models.OneToOneField(Customer, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=100, blank=True, null=True)
    approved = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user} - {self.company_name}'

# ======================
# Product Models
# ======================

class Game(models.Model):

    submission = models.OneToOneField(  # Add this field
        'GameSubmission',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='published_game'
    )
    name = models.CharField(max_length=100)
    categories = models.ManyToManyField(Category)  
    price = models.DecimalField(default=0, decimal_places=2, max_digits=6)
    sale_price = models.DecimalField(default=0, decimal_places=2, max_digits=6)
    description = models.CharField(max_length=250, blank=True)
    image = models.ImageField(upload_to='uploads/game/')
    is_on_sale = models.BooleanField(default=False)
    developer = models.ForeignKey(Developer, on_delete=models.CASCADE)
    approved = models.BooleanField(default=False)

    def delete(self, *args, **kwargs):
        """Delete game and its files"""
        self.image.delete(save=False)
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.name

class Order(models.Model):
    product = models.ForeignKey(Game, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    address = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    date = models.DateField(auto_now_add=True)
    status = models.BooleanField(default=False)

    def __str__(self):
        return f'Order #{self.id} - {self.product.name}'

# ======================
# Community Models
# ======================

class Community(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    members = models.ManyToManyField(Customer, related_name='joined_communities', blank=True)
    rules = models.TextField(blank=True)
    is_public = models.BooleanField(default=True)
    created_by = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='created_communities')
    admins = models.ManyToManyField(Customer, related_name='administered_communities', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = 'communities'
    
    def add_admin(self, customer):
        """Add a user to community admins"""
        self.admins.add(customer)
        self.save()

    def __str__(self):
        return self.name

class CommunityMember(models.Model):
    community = models.ForeignKey(Community, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[('member', 'Member'), ('moderator', 'Moderator')], default='member')

    def __str__(self):
        return f'{self.customer} in {self.community}'

class Post(models.Model):
    community = models.ForeignKey(Community, on_delete=models.CASCADE)
    author = models.ForeignKey(Customer, on_delete=models.CASCADE)
    content = models.TextField()
    image = models.ImageField(upload_to='post_images/', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    likes = models.ManyToManyField(Customer, related_name='liked_posts', blank=True)

    def __str__(self):
        return f'Post by {self.author} in {self.community}'

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment by {self.user} on {self.post}'

# ======================
# Game Upload
# ======================

from django.db import models

class GameSubmission(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )

    developer = models.ForeignKey('Developer', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    categories = models.ManyToManyField(Category)
    description = models.TextField()
    price = models.DecimalField(default=0, decimal_places=2, max_digits=6)  

    game_file = models.FileField(upload_to='uploads/games/')
    thumbnail = models.ImageField(upload_to='uploads/thumbnails/')
    trailer = models.FileField(upload_to='uploads/trailers/', null=True, blank=True)

    version = models.CharField(max_length=20)

    # System Requirements
    min_os = models.CharField(max_length=50)
    min_processor = models.CharField(max_length=50)
    min_ram = models.CharField(max_length=50)
    min_gpu = models.CharField(max_length=50)
    min_directx = models.CharField(max_length=50)

    rec_os = models.CharField(max_length=50)
    rec_processor = models.CharField(max_length=50)
    rec_ram = models.CharField(max_length=50)
    rec_gpu = models.CharField(max_length=50)
    rec_directx = models.CharField(max_length=50)

    submitted_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    admin_notes = models.TextField(blank=True)

    file_size = models.PositiveIntegerField(null=True, blank=True)  # Automatically stored

    def delete(self, *args, **kwargs):
        """Handle file deletions while letting Django manage DB relations"""
        # Delete associated files
        self.game_file.delete(save=False)
        self.thumbnail.delete(save=False)
        if self.trailer:
            self.trailer.delete(save=False)
            
        # Delete screenshots and their files
        for screenshot in self.gamescreenshot_set.all():
            screenshot.image.delete(save=False)
            screenshot.delete()
            
        super().delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        if self.game_file:
            self.file_size = self.game_file.size
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class GameScreenshot(models.Model):
    game_submission = models.ForeignKey(
        GameSubmission, 
        on_delete=models.CASCADE,
        null=True,  # Allows existing records to be updated
        blank=True  
        
    )
    image = models.ImageField(upload_to='screenshots/')

    def delete(self, *args, **kwargs):
        self.image.delete(save=False)
        super().delete(*args, **kwargs)

    def __str__(self):
        return f"Screenshot for {self.game_submission.title if self.game_submission else 'Unassigned'}"


# ======================
# Signals
# ======================

@receiver(post_save, sender=User)
def create_customer(sender, instance, created, **kwargs):
    if created:
        Customer.objects.create(
            user=instance,
            f_name=instance.first_name,
            l_name=instance.last_name,
            email=instance.email
        )