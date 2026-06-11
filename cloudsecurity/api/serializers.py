"""
DRF Serializers for CloudSec REST API.
"""
from django.contrib.auth import authenticate
from rest_framework import serializers
from authentication.models import CustomUser, LoginHistory, OTPVerification
from encryption.models import EncryptedFile
from audit.models import AuditLog, SecurityEvent


class UserSerializer(serializers.ModelSerializer):
    risk_label = serializers.SerializerMethodField()
    files_count = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'status', 'phone', 'email_verified',
            'two_factor_enabled', 'failed_login_count',
            'cumulative_risk_score', 'total_logins',
            'created_at', 'risk_label', 'files_count',
        ]
        read_only_fields = ['id', 'created_at', 'risk_label', 'files_count']

    def get_risk_label(self, obj):
        return obj.get_risk_label()

    def get_files_count(self, obj):
        return obj.files.filter(is_deleted=False).count()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        # Try username or email
        user = None
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            try:
                user = CustomUser.objects.get(email=username)
            except CustomUser.DoesNotExist:
                pass

        if user and user.is_locked():
            raise serializers.ValidationError('Account is temporarily locked.')

        if user and user.check_password(password):
            if user.status == 'suspended':
                raise serializers.ValidationError('Account is suspended.')
            if not user.email_verified:
                raise serializers.ValidationError('Email not verified.')
            data['user'] = user
            return data

        raise serializers.ValidationError('Invalid credentials.')


class OTPVerifySerializer(serializers.Serializer):
    otp_code = serializers.CharField(min_length=6, max_length=6)
    purpose = serializers.ChoiceField(
        choices=['login', 'email', 'password_reset', 'risk_auth'],
        default='login'
    )

    def validate_otp_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError('OTP must contain only digits.')
        return value


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'confirm_password',
                  'first_name', 'last_name', 'phone']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})
        return data

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError('Email already registered.')
        return value.lower()

    def validate_username(self, value):
        if CustomUser.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError('Username already taken.')
        return value

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        user = CustomUser(**validated_data)
        user.set_password(password)
        user.status = 'active'
        user.role = 'user'
        user.email_verified = False
        user.save()
        return user


class EncryptedFileSerializer(serializers.ModelSerializer):
    size_display = serializers.SerializerMethodField()
    strength_percent = serializers.SerializerMethodField()
    owner = serializers.StringRelatedField(source='user')

    class Meta:
        model = EncryptedFile
        fields = [
            'id', 'original_filename', 'encryption_type', 'status',
            'original_size', 'size_display', 'file_hash', 'sensitivity_level',
            'risk_score_at_upload', 'access_count', 'last_accessed',
            'encryption_time', 'decryption_time', 'uploaded_at', 'encrypted_at',
            'strength_percent', 'owner',
        ]
        read_only_fields = ['id', 'uploaded_at', 'encrypted_at', 'file_hash',
                            'size_display', 'strength_percent', 'owner']

    def get_size_display(self, obj):
        return obj.get_size_display()

    def get_strength_percent(self, obj):
        return obj.get_strength_percent()


class AuditLogSerializer(serializers.ModelSerializer):
    user_display = serializers.StringRelatedField(source='user')
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'user_display', 'action', 'action_display',
            'severity', 'severity_display', 'description',
            'ip_address', 'timestamp',
        ]


class SecurityEventSerializer(serializers.ModelSerializer):
    user_display = serializers.StringRelatedField(source='user')
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'user_display', 'event_type', 'event_type_display',
            'description', 'ip_address', 'risk_score', 'is_resolved',
            'detected_at', 'resolved_at',
        ]


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = [
            'id', 'login_time', 'ip_address', 'device_type', 'browser',
            'was_successful', 'risk_score', 'risk_level', 'is_suspicious',
            'session_duration', 'mfa_level_used',
        ]


class RiskScoreSerializer(serializers.Serializer):
    risk_score = serializers.FloatField()
    risk_level = serializers.CharField()
    is_suspicious = serializers.BooleanField()
    probability_scores = serializers.DictField()
    features_used = serializers.DictField()


class DashboardStatsSerializer(serializers.Serializer):
    total_users = serializers.IntegerField()
    active_users = serializers.IntegerField()
    total_files = serializers.IntegerField()
    encrypted_files = serializers.IntegerField()
    total_logins_7d = serializers.IntegerField()
    suspicious_logins_7d = serializers.IntegerField()
    high_risk_events = serializers.IntegerField()
    unresolved_security_events = serializers.IntegerField()
