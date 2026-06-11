"""
Authentication forms with full validation and security measures.
"""
import re
from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.exceptions import ValidationError
from .models import CustomUser, OTPVerification

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']


class RegistrationForm(UserCreationForm):
    """User registration form with comprehensive validation."""
    first_name = forms.CharField(
        max_length=50, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        max_length=50, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    username = forms.CharField(
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email Address'})
    )
    phone = forms.CharField(
        max_length=20, required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Phone (Optional)'})
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password (min. 8 chars, mixed case, number)',
            'id': 'id_password1',
        })
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password',
        })
    )
    security_question = forms.ChoiceField(
        choices=[('', '-- Select a Security Question --')] + list(CustomUser.SECURITY_QUESTIONS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    security_answer = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Your answer (used for medium-risk login verification)',
        })
    )

    class Meta:
        model = CustomUser
        fields = [
            'first_name', 'last_name', 'username', 'email', 'phone',
            'password1', 'password2', 'security_question', 'security_answer'
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        if CustomUser.objects.filter(username__iexact=username).exists():
            raise ValidationError("This username is already taken.")
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            raise ValidationError(
                "Username may only contain letters, numbers, underscores, hyphens, and dots."
            )
        return username

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        if phone and not re.match(r'^\+?[\d\s\-()]{7,20}$', phone):
            raise ValidationError("Enter a valid phone number.")
        return phone

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email'].lower()
        if self.cleaned_data.get('security_question'):
            user.security_question = self.cleaned_data['security_question']
            user.security_answer = self.cleaned_data.get('security_answer', '').strip().lower()
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    """Custom login form."""
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username or Email',
            'autofocus': True,
            'autocomplete': 'username',
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password',
            'autocomplete': 'current-password',
        })
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'password']


class OTPForm(forms.Form):
    """OTP verification form — validates 6-digit numeric code."""
    otp_code = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control otp-input text-center',
            'placeholder': '000000',
            'maxlength': '6',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'autocomplete': 'one-time-code',
        }),
        label='Enter OTP Code',
    )

    def clean_otp_code(self):
        code = self.cleaned_data.get('otp_code', '')
        if not code.isdigit():
            raise ValidationError("OTP must contain only digits.")
        if len(code) != 6:
            raise ValidationError("OTP must be exactly 6 digits.")
        return code


class ForgotPasswordForm(forms.Form):
    """Forgot password — email input."""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Registered Email Address',
        })
    )


class ResetPasswordForm(forms.Form):
    """Password reset form with strength validation."""
    new_password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New Password',
            'id': 'id_new_password',
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm New Password',
        })
    )

    def clean_new_password(self):
        password = self.cleaned_data.get('new_password', '')
        errors = []
        if len(password) < 8:
            errors.append("at least 8 characters")
        if not re.search(r'[A-Z]', password):
            errors.append("an uppercase letter")
        if not re.search(r'[a-z]', password):
            errors.append("a lowercase letter")
        if not re.search(r'\d', password):
            errors.append("a number")
        if errors:
            raise ValidationError(f"Password must contain: {', '.join(errors)}.")
        return password

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('new_password')
        p2 = cleaned_data.get('confirm_password')
        if p1 and p2 and p1 != p2:
            raise ValidationError("Passwords do not match.")
        return cleaned_data


class ProfileUpdateForm(forms.ModelForm):
    """User profile update form with MIME validation for images."""

    class Meta:
        model = CustomUser
        fields = [
            'first_name', 'last_name', 'email', 'phone',
            'profile_picture', 'security_question', 'security_answer',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'profile_picture': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
            'security_question': forms.Select(attrs={'class': 'form-select'}),
            'security_answer': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def clean_profile_picture(self):
        picture = self.cleaned_data.get('profile_picture')
        if picture:
            # Validate file size (max 5MB)
            if picture.size > 5 * 1024 * 1024:
                raise ValidationError("Profile picture must be smaller than 5MB.")
            # Validate MIME type by reading magic bytes
            picture.seek(0)
            header = picture.read(12)
            picture.seek(0)
            if not (
                header[:3] == b'\xff\xd8\xff' or   # JPEG
                header[:8] == b'\x89PNG\r\n\x1a\n' or  # PNG
                header[:6] in (b'GIF87a', b'GIF89a') or  # GIF
                header[:4] == b'RIFF' and header[8:12] == b'WEBP'  # WEBP
            ):
                raise ValidationError(
                    "Invalid image format. Please upload a JPEG, PNG, GIF, or WebP file."
                )
        return picture


class SecurityQuestionForm(forms.Form):
    """Security question answer form for medium-risk MFA."""
    answer = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Your answer',
            'autocomplete': 'off',
        }),
        label='Your Answer',
    )
