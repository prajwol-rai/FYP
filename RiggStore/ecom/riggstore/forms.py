from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from django import forms
from django.contrib.auth.models import User
from .models import Customer, Community, Post, GameSubmission, PrivacyPolicy  # Updated imports

# Choices for account types during signup
ACCOUNT_TYPE_CHOICES = [
    ('buyer', 'Buyer'),
    ('developer', 'Game Developer'),
]

# Form for user signup, extending the default UserCreationForm.
ACCOUNT_TYPE_CHOICES = [
    ('buyer', 'Buyer'),
    ('developer', 'Game Developer'),
]

# Form for user signup, extending the default UserCreationForm.
class SignUpForm(UserCreationForm):
    email = forms.EmailField(
        label="",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Email Address'})
    )
    first_name = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    account_type = forms.ChoiceField(
        choices=ACCOUNT_TYPE_CHOICES,
        widget=forms.RadioSelect,
        label="I am a:"
    )
    phone = forms.CharField(
        label="",
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Phone Number'})
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'account_type', 'phone', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Update the attributes for the username field
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'User Name'
        })
        self.fields['username'].label = ''
        self.fields['username'].help_text = 'Required. 150 characters or fewer. Letters, digits, and @/./+/-/_ only.'

        # Update attributes for password fields
        for password_field in ['password1', 'password2']:
            self.fields[password_field].widget.attrs.update({
                'class': 'form-control',
                'placeholder': 'Password' if password_field == 'password1' else 'Confirm Password'
            })
            self.fields[password_field].label = ''

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists!")
        return username

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        
        # Sanitize phone number
        cleaned_phone = ''.join(filter(str.isdigit, phone))
        
        # Validate length
        if len(cleaned_phone) != 10:
            raise forms.ValidationError("Phone number must be 10 digits")
        
        # Check uniqueness in Customer model
        if Customer.objects.filter(phone=cleaned_phone).exists():
            raise forms.ValidationError("This phone number is already registered")
        
        return cleaned_phone

    def clean_email(self):
        email = self.cleaned_data.get('email').lower()
        
        # Check both User and Customer tables
        if User.objects.filter(email=email).exists() or \
           Customer.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already registered")
        
        # Keep your existing email validations
        if len(email) > 100:
            raise forms.ValidationError("Email must be under 100 characters")
            
        if not email.endswith('@gmail.com'):
            raise forms.ValidationError("Only Gmail addresses allowed")
        
        return email
    
# Form for editing user details, extending the default UserChangeForm.
class UserEditForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the password field from the form
        self.fields.pop('password')

# Custom form for changing user passwords.
class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Update all fields to have a specific class
        for field in self.fields:
            self.fields[field].widget.attrs.update({'class': 'form-control'})

# Form for updating user profile information (using Customer model).
class ProfileForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['image']

# Form for creating or editing a community.
class CommunityForm(forms.ModelForm):
    class Meta:
        model = Community
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Community Name'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Description'}),
        }

# Form for creating or editing a post within a community.
class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['content', 'image']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'image': forms.FileInput(attrs={'class': 'form-control'})
        }

from django.forms.widgets import ClearableFileInput

# Custom widget to support multiple file selection for game uploads.
class MultiFileInput(ClearableFileInput):
    allow_multiple_selected = True

# Form for uploading a game submission.
class GameUploadForm(forms.ModelForm):
    # Use the custom widget for screenshots field
    screenshots = forms.FileField(
        widget=MultiFileInput(attrs={'multiple': True}),
        required=False
    )
    
    class Meta:
        model = GameSubmission
        fields = [
            'title', 'description', 'game_file', 'thumbnail', 'trailer', 'version',
            'min_os', 'min_processor', 'min_ram', 'min_gpu', 'min_directx',
            'rec_os', 'rec_processor', 'rec_ram', 'rec_gpu', 'rec_directx'
        ]
    widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
        }
    
class PrivacyPolicyForm(forms.ModelForm):
    class Meta:
        model = PrivacyPolicy
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'rich-text-editor'}),
        }