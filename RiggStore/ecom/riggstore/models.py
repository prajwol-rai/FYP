from decimal import Decimal
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.shortcuts import get_object_or_404
from django.utils import timezone
import random

from django.db.models import Q

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

class EmailVerification(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    form_data = models.JSONField()  # To store form data temporarily

    def is_valid(self):
        return (timezone.now() - self.created_at).seconds < 300 and not self.is_verified

    @classmethod
    def create_verification(cls, email, form_data):
        # Delete any existing entries for this email OR username
        cls.objects.filter(
            Q(email=email) | 
            Q(form_data__username=form_data['username'])
        ).delete()
        
        return cls.objects.create(
            email=email,
            otp=str(random.randint(100000, 999999)),
            form_data=form_data
        )

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer', null=True, blank=True)
    f_name = models.CharField(max_length=50)
    l_name = models.CharField(max_length=50)
    email = models.EmailField()
    phone = models.CharField(max_length=15, null=True, blank=True,)
    image = models.ImageField(upload_to='profile_pics', default='default.jpg')

    class Meta:
        ordering = ['l_name', 'f_name']

    def __str__(self):
        return f'{self.f_name} {self.l_name}'

class Developer(models.Model):
    user = models.OneToOneField(Customer, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=100, blank=True, null=True)
    approved = models.BooleanField(default=False)
    # Add these new fields
    khalti_merchant_id = models.CharField(max_length=100, blank=True)
    bank_account_number = models.CharField(max_length=50, blank=True)
    payout_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=70.00
    )

# ======================
# Product Models
# ======================

class Game(models.Model):

    submission = models.OneToOneField( 
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
    
    def get_download_url(self):
        if self.submission:
            return self.submission.game_file.url
        return None
    
    def delete(self, *args, **kwargs):
        """Delete game and its files"""
        self.image.delete(save=False)
        super().delete(*args, **kwargs)

    def __str__(self):
        return self.name

class Order(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='orders')
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)
    purchase_order_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    payment_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ],
        default='pending'
    )
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if self.payment_status == 'completed' and not self.commissions.exists():
            Commission.objects.create(
                order=self,
                platform_fee=self.total_amount * Decimal('0.30'),  # Use Decimal
                developer_payout=self.total_amount * Decimal('0.70')  # Use Decimal
            )
        super().save(*args, **kwargs)
    
    games = models.ManyToManyField(Game, through='OrderItem')
    def get_purchased_games(self):
        return self.games.all()

class PaymentDetail(models.Model):
    order = models.OneToOneField(Order, on_delete=models.CASCADE, related_name='payment_details')
    stripe_session_id = models.CharField(max_length=100)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3)
    payment_method = models.CharField(max_length=50)
    receipt_url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment for Order {self.order.id}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE)
    game = models.ForeignKey(Game, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

class Commission(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='commissions')
    platform_fee = models.DecimalField(max_digits=10, decimal_places=2)
    developer_payout = models.DecimalField(max_digits=10, decimal_places=2)
    payout_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('paid', 'Paid'),
            ('failed', 'Failed')
        ],
        default='pending'
    )
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
    download_count = models.PositiveIntegerField(default=0) 

    def delete(self, *args, **kwargs):
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

class Cart(models.Model):
    customer = models.OneToOneField(Customer, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def total_items(self):
        from django.db.models import Sum
        return self.items.aggregate(total=Sum('quantity'))['total'] or 0

    def total_price(self):
        return sum(item.total_price() for item in self.items.all())

    def __str__(self):
        return f"Cart of {self.customer}"
    
class CartItem(models.Model):
    cart = models.ForeignKey(Cart, related_name='items', on_delete=models.CASCADE)
    game = models.ForeignKey(Game, related_name='cart_items', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('cart', 'game')


class DownloadHistory(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='downloads')
    game = models.ForeignKey(Game, on_delete=models.CASCADE)
    downloaded_at = models.DateTimeField(auto_now_add=True)
    download_type = models.CharField(max_length=10, choices=[('single', 'Single'), ('batch', 'Batch')])
    visible = models.BooleanField(default=True)
    class Meta:
        ordering = ['-downloaded_at']
        verbose_name_plural = 'Download Histories'

    def __str__(self):
        return f"{self.user} downloaded {self.game} at {self.downloaded_at}"
    

class PrivacyPolicy(models.Model):
    content = models.TextField()
    effective_date = models.DateTimeField(default=timezone.now)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Privacy Policy"
        ordering = ['-effective_date']

    def __str__(self):
        return f"Privacy Policy ({self.effective_date.strftime('%Y-%m-%d')})"

    @classmethod
    def get_latest_policy(cls):
        return cls.objects.order_by('-effective_date').first()
    

