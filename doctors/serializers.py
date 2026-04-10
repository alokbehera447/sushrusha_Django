from rest_framework import serializers
from django.utils import timezone
import pytz
from authentication.models import User
from .models import (
    DoctorProfile, DoctorEducation, DoctorExperience, 
    DoctorDocument, DoctorSchedule, DoctorReview, DoctorSlot
)
from eclinic.models import Clinic
from utils.signed_urls import get_signed_media_url
from .models import DoctorStatus


class DoctorProfileSerializer(serializers.ModelSerializer):
    """Serializer for doctor profile"""
    user_name = serializers.CharField(source='user.name', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    user_phone = serializers.CharField(source='user.phone', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    experience_years = serializers.ReadOnlyField()
    meeting_link = serializers.SerializerMethodField(read_only=True)
    profile_picture = serializers.SerializerMethodField()
    signature_url = serializers.SerializerMethodField()
    signature = serializers.FileField(read_only=True)
    # Note: Using 'rating' field from model instead of 'average_rating'
    
    class Meta:
        model = DoctorProfile
        fields = [
            'id', 'user', 'user_name', 'user_phone', 'user_email',
            'profile_picture', 'signature_url', 'signature',
            'license_number', 'qualification', 'specialization', 'sub_specialization',
            'experience_years', 'consultation_fee', 'online_consultation_fee',
            'languages_spoken', 'bio', 'achievements',
            'is_verified', 'consultation_duration',
            'is_online_consultation_available', 'is_active',
            'rating', 'total_reviews', 'clinic_name', 'clinic_address',
            'is_accepting_patients', 'date_of_birth', 'date_of_anniversary',
            'created_at', 'updated_at', 'meeting_link'
        ]
        read_only_fields = ['id', 'user', 'is_verified', 'rating', 'total_reviews', 'created_at', 'updated_at']

    def get_meeting_link(self, obj):
        return obj.meeting_link
    
    def get_profile_picture(self, obj):
        """Generate signed URL for profile picture"""
        if obj.user.profile_picture:
            return get_signed_media_url(str(obj.user.profile_picture))
        return None
    
    def get_signature_url(self, obj):
        """Generate signed URL for signature"""
        if obj.signature:
            return get_signed_media_url(str(obj.signature))
        return None


class DoctorProfileCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating doctor profile"""
    
    class Meta:
        model = DoctorProfile
        fields = [
            'license_number', 'qualification', 'specialization', 'sub_specialization',
            'consultation_fee', 'online_consultation_fee', 'languages_spoken',
            'bio', 'achievements', 'consultation_duration',
            'is_online_consultation_available', 'clinic_name', 'clinic_address',
            'date_of_birth', 'date_of_anniversary', 'signature'
        ]
    
    def create(self, validated_data):
        """Create doctor profile for authenticated user"""
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)
    
    def validate_consultation_duration(self, value):
        """Validate consultation duration is between 5 and 15 minutes"""
        if value is not None:
            if value < 5 or value > 15:
                raise serializers.ValidationError("Consultation duration must be between 5 and 15 minutes.")
        return value


class DoctorProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating doctor profile"""
    
    # Add signature_url field for response
    signature_url = serializers.SerializerMethodField()
    
    # Make fields optional for updates
    license_number = serializers.CharField(required=False, allow_blank=True)
    qualification = serializers.CharField(required=False, allow_blank=True)
    specialization = serializers.ChoiceField(choices=DoctorProfile.SPECIALTIES, required=False, allow_blank=True)
    sub_specialization = serializers.CharField(required=False, allow_blank=True)
    consultation_fee = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    online_consultation_fee = serializers.DecimalField(max_digits=10, decimal_places=2, required=False, allow_null=True)
    languages_spoken = serializers.JSONField(required=False)
    bio = serializers.CharField(required=False, allow_blank=True)
    achievements = serializers.CharField(required=False, allow_blank=True)
    consultation_duration = serializers.IntegerField(required=False)
    is_online_consultation_available = serializers.BooleanField(required=False)
    clinic_name = serializers.CharField(required=False, allow_blank=True)
    clinic_address = serializers.CharField(required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    date_of_anniversary = serializers.DateField(required=False, allow_null=True)
    signature = serializers.FileField(required=False, allow_null=True)
    
    class Meta:
        model = DoctorProfile
        fields = [
            'license_number', 'qualification', 'specialization', 'sub_specialization',
            'consultation_fee', 'online_consultation_fee', 'languages_spoken',
            'bio', 'achievements', 'consultation_duration',
            'is_online_consultation_available', 'clinic_name', 'clinic_address',
            'date_of_birth', 'date_of_anniversary', 'signature', 'signature_url'
        ]
    
    def validate_license_number(self, value):
        """Validate license number uniqueness"""
        if not value or value.strip() == '':
            return value  # Allow empty/blank values for updates
            
        # Check if context has request
        if 'request' not in self.context:
            return value  # Skip validation if no request context
            
        user = self.context['request'].user
        # Check if license number already exists for another doctor
        if DoctorProfile.objects.filter(license_number=value).exclude(user=user).exists():
            raise serializers.ValidationError("A doctor with this license number already exists.")
        return value
    
    def validate_specialization(self, value):
        """Validate specialization choice"""
        if not value or value.strip() == '':
            return value  # Allow empty/blank values for updates
        return value
    
    def validate_consultation_duration(self, value):
        """Validate consultation duration is between 5 and 15 minutes"""
        if value is not None:
            if value < 5 or value > 15:
                raise serializers.ValidationError("Consultation duration must be between 5 and 15 minutes.")
        return value
    
    def get_signature_url(self, obj):
        """Generate signed URL for signature"""
        if obj.signature:
            return get_signed_media_url(str(obj.signature))
        return None


class DoctorEducationSerializer(serializers.ModelSerializer):
    """Serializer for doctor education"""
    
    class Meta:
        model = DoctorEducation
        fields = [
            'id', 'doctor', 'degree', 'institution', 'year_of_completion',
            'grade_or_percentage', 'certificate', 'is_verified', 'created_at'
        ]
        read_only_fields = ['id', 'is_verified', 'created_at']


class DoctorExperienceSerializer(serializers.ModelSerializer):
    """Serializer for doctor experience"""
    
    class Meta:
        model = DoctorExperience
        fields = [
            'id', 'doctor', 'organization', 'position',
            'start_date', 'end_date', 'is_current', 'description',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DoctorDocumentSerializer(serializers.ModelSerializer):
    """Serializer for doctor documents"""
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    verified_by_name = serializers.CharField(source='verified_by.name', read_only=True)
    
    class Meta:
        model = DoctorDocument
        fields = [
            'id', 'doctor', 'doctor_name', 'document_type', 'title', 'description',
            'file', 'is_verified', 'verified_by', 'verified_by_name', 'verified_at',
            'verification_notes', 'uploaded_at', 'updated_at'
        ]
        read_only_fields = ['id', 'is_verified', 'verified_by', 'verified_at', 'uploaded_at', 'updated_at']


class DoctorScheduleSerializer(serializers.ModelSerializer):
    """Serializer for doctor schedule"""
    
    class Meta:
        model = DoctorSchedule
        fields = [
            'id', 'doctor', 'day_of_week', 'start_time', 'end_time',
            'is_available', 'break_start_time', 'break_end_time',
            'break_reason', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DoctorReviewSerializer(serializers.ModelSerializer):
    """Serializer for doctor reviews"""
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    
    class Meta:
        model = DoctorReview
        fields = [
            'id', 'doctor', 'patient', 'patient_name', 'consultation',
            'rating', 'communication_rating', 'treatment_rating',
            'punctuality_rating', 'review_text', 'is_anonymous',
            'is_approved', 'created_at'
        ]
        read_only_fields = ['id', 'patient', 'is_approved', 'created_at']


class DoctorListSerializer(serializers.ModelSerializer):
    """Serializer for doctor list view (now includes all fields for superadmin dashboard)"""
    user_name = serializers.CharField(source='user.name', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    user_phone = serializers.CharField(source='user.phone', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    experience_years = serializers.ReadOnlyField()
    profile_picture = serializers.SerializerMethodField()
    
    class Meta:
        model = DoctorProfile
        fields = [
            'id', 'user', 'user_name', 'user_phone', 'user_email',
            'profile_picture',
            'license_number', 'qualification', 'specialization', 'sub_specialization',
            'experience_years', 'consultation_fee', 'online_consultation_fee',
            'languages_spoken', 'bio', 'achievements',
            'is_verified', 'consultation_duration',
            'is_online_consultation_available', 'is_active',
            'rating', 'total_reviews', 'clinic_name', 'clinic_address',
            'is_accepting_patients', 'date_of_birth', 'date_of_anniversary',
            'created_at', 'updated_at'
        ]
    
    def get_profile_picture(self, obj):
        """Generate signed URL for profile picture"""
        if obj.user.profile_picture:
            return get_signed_media_url(str(obj.user.profile_picture))
        return None


class PublicDoctorListSerializer(serializers.ModelSerializer):
    """Serializer for public doctor listing (no sensitive information)"""
    name = serializers.CharField(source='user.name', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    experience_years = serializers.ReadOnlyField()
    profile_picture = serializers.SerializerMethodField()
    consultation_types = serializers.SerializerMethodField()
    
    class Meta:
        model = DoctorProfile
        fields = [
            'id', 'name', 'user_id', 'profile_picture', 'specialization', 'sub_specialization',
            'experience_years', 'consultation_fee', 'online_consultation_fee',
            'languages_spoken', 'bio', 'rating', 'total_reviews', 
            'clinic_name', 'clinic_address', 'consultation_types',
            'is_online_consultation_available', 'consultation_duration'
        ]
    
    def get_profile_picture(self, obj):
        """Generate signed URL for profile picture"""
        if obj.user.profile_picture:
            return get_signed_media_url(str(obj.user.profile_picture))
        return None
    
    def get_consultation_types(self, obj):
        """Get available consultation types"""
        types = []
        if obj.clinic_address:  # Has physical clinic
            types.append('in-person')
        if obj.is_online_consultation_available:
            types.append('video')
        return types


class DoctorSearchSerializer(serializers.Serializer):
    """Serializer for doctor search"""
    query = serializers.CharField(max_length=200, required=False)
    specialization = serializers.CharField(max_length=100, required=False)
    sub_specialization = serializers.CharField(max_length=100, required=False)
    min_experience = serializers.IntegerField(min_value=0, required=False)
    max_experience = serializers.IntegerField(min_value=0, required=False)
    min_fee = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=0, required=False)
    max_fee = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=0, required=False)
    languages = serializers.ListField(child=serializers.CharField(), required=False)
    consultation_type = serializers.ChoiceField(
        choices=[('in_person', 'In Person'), ('online', 'Online'), ('both', 'Both')],
        required=False
    )
    rating_min = serializers.DecimalField(max_digits=3, decimal_places=1, min_value=0, max_value=5, required=False)
    is_verified = serializers.BooleanField(required=False)
    # Note: emergency_available field removed as it doesn't exist in the model
    city = serializers.CharField(max_length=100, required=False)
    state = serializers.CharField(max_length=100, required=False)
    
    def validate(self, attrs):
        """Validate search parameters"""
        min_exp = attrs.get('min_experience')
        max_exp = attrs.get('max_experience')
        min_fee = attrs.get('min_fee')
        max_fee = attrs.get('max_fee')
        
        if min_exp and max_exp and min_exp > max_exp:
            raise serializers.ValidationError('min_experience cannot be greater than max_experience')
        
        if min_fee and max_fee and min_fee > max_fee:
            raise serializers.ValidationError('min_fee cannot be greater than max_fee')
        
        return attrs


class DoctorStatsSerializer(serializers.Serializer):
    """Serializer for doctor statistics"""
    total_doctors = serializers.IntegerField()
    active_doctors = serializers.IntegerField()
    new_this_month = serializers.IntegerField()
    avg_rating = serializers.DecimalField(max_digits=3, decimal_places=1)
    verified_doctors = serializers.IntegerField()
    specialization_distribution = serializers.DictField()
    experience_distribution = serializers.DictField()
    average_consultation_fee = serializers.DecimalField(max_digits=10, decimal_places=2)
    top_rated_doctors = serializers.ListField()
    consultation_stats = serializers.DictField()


class DoctorScheduleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating doctor schedule"""
    
    class Meta:
        model = DoctorSchedule
        fields = [
            'day_of_week', 'start_time', 'end_time', 'is_available',
            'break_start_time', 'break_end_time', 'break_reason'
        ]
    
    def create(self, validated_data):
        """Create schedule for doctor"""
        doctor_id = self.context['view'].kwargs.get('doctor_id')
        doctor = User.objects.get(id=doctor_id)
        validated_data['doctor'] = doctor
        return super().create(validated_data)


class DoctorSlotSerializer(serializers.ModelSerializer):
    """Serializer for doctor slots (multiple slots per day)"""
    doctor = serializers.PrimaryKeyRelatedField(read_only=True)
    clinic = serializers.PrimaryKeyRelatedField(
        queryset=Clinic.objects.all(), 
        required=False, 
        allow_null=True
    )
    clinic_name = serializers.CharField(source='clinic.name', read_only=True)
    
    class Meta:
        model = DoctorSlot
        fields = [
            'id', 'doctor', 'clinic', 'clinic_name', 'date', 'start_time', 'end_time', 
            'is_available', 'is_booked', 'booked_consultation', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'doctor', 'created_at', 'updated_at']

    def validate(self, data):
        """Custom validation to handle clinic field and check for duplicates"""
        doctor_id = self.context['view'].kwargs.get('doctor_id')
        
        # Handle 'current' doctor_id for self-reference
        if doctor_id == 'current':
            doctor_id = self.context['request'].user.id
        
        # If clinic is not provided, set it to None for global availability
        if 'clinic' not in data:
            data['clinic'] = None
        
        # Check for existing slots with the same doctor, date, start_time, end_time, and clinic
        existing_slot = DoctorSlot.objects.filter(
            doctor_id=doctor_id,
            clinic=data['clinic'],
            date=data['date'],
            start_time=data['start_time'],
            end_time=data['end_time']
        ).first()
        
        if existing_slot:
            raise serializers.ValidationError(
                f"A slot already exists for this doctor on {data['date']} from {data['start_time']} to {data['end_time']}"
            )
        
        return data

    def create(self, validated_data):
        doctor_id = self.context['view'].kwargs.get('doctor_id')
        
        # Handle 'current' doctor_id for self-reference
        if doctor_id == 'current':
            doctor_id = self.context['request'].user.id
        
        try:
            doctor = User.objects.get(id=doctor_id)
        except User.DoesNotExist:
            raise serializers.ValidationError(f"Doctor with ID {doctor_id} does not exist")
        
        validated_data['doctor'] = doctor
        
        # If clinic is not provided, we'll set it to None for global availability
        # The model allows null=True, blank=True for clinic field
        if 'clinic' not in validated_data:
            validated_data['clinic'] = None
        
        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        ist = pytz.timezone('Asia/Kolkata')
        for field in ['created_at', 'updated_at']:
            if data.get(field):
                dt = getattr(instance, field)
                if timezone.is_aware(dt):
                    data[field] = dt.astimezone(ist).isoformat()
        return data


class DoctorSlotGenerationSerializer(serializers.Serializer):
    """Serializer for generating slots from doctor availability"""
    clinic = serializers.PrimaryKeyRelatedField(queryset=Clinic.objects.all())
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    
    def validate(self, data):
        clinic = data['clinic']
        date = data['date']
        start_time = data['start_time']
        end_time = data['end_time']
        
        # Check if clinic has consultation duration set
        if not clinic.consultation_duration:
            raise serializers.ValidationError("Clinic consultation duration is not set")
        
        # Validate time range
        if start_time >= end_time:
            raise serializers.ValidationError("Start time must be before end time")
        
        # Check if date is not in the past
        from datetime import date as date_today
        if date < date_today():
            raise serializers.ValidationError("Cannot create slots for past dates")
        
        return data
    
    def create(self, validated_data):
        doctor_id = self.context['view'].kwargs.get('doctor_id')
        
        # Handle 'current' doctor_id for self-reference
        if doctor_id == 'current':
            doctor_id = self.context['request'].user.id
        
        try:
            doctor = User.objects.get(id=doctor_id)
        except User.DoesNotExist:
            raise serializers.ValidationError(f"Doctor with ID {doctor_id} does not exist")
        
        # Generate slots using the model method
        slots = DoctorSlot.generate_slots_for_availability(
            doctor=doctor,
            clinic=validated_data['clinic'],
            date=validated_data['date'],
            start_time=validated_data['start_time'],
            end_time=validated_data['end_time']
        )
        
        return slots


class DoctorStatusSerializer(serializers.ModelSerializer):
    """Serializer for Doctor Status"""
    
    doctor_name = serializers.CharField(source='doctor.user.name', read_only=True)
    doctor_email = serializers.CharField(source='doctor.user.email', read_only=True)
    doctor_specialization = serializers.CharField(source='doctor.specialization', read_only=True)
    doctor_profile_picture = serializers.CharField(source='doctor.user.profile_picture', read_only=True)
    status_display = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    last_activity_formatted = serializers.SerializerMethodField()
    last_login_formatted = serializers.SerializerMethodField()
    current_consultation_info = serializers.SerializerMethodField()
    
    class Meta:
        model = DoctorStatus
        fields = [
            'id', 'doctor', 'doctor_name', 'doctor_email', 'doctor_specialization', 
            'doctor_profile_picture', 'is_online', 'is_logged_in', 'is_available',
            'current_status', 'status_display', 'is_active', 'last_activity',
            'last_activity_formatted', 'last_login', 'last_login_formatted',
            'current_consultation', 'current_consultation_info', 'status_updated_at',
            'status_note', 'auto_away_threshold'
        ]
        read_only_fields = ['id', 'doctor', 'last_activity', 'last_login', 'status_updated_at']
    
    def get_last_activity_formatted(self, obj):
        """Format last activity time"""
        if obj.last_activity:
            now = timezone.now()
            diff = now - obj.last_activity
            
            if diff.days > 0:
                return f"{diff.days} day(s) ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour(s) ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute(s) ago"
            else:
                return "Just now"
        return "Never"
    
    def get_last_login_formatted(self, obj):
        """Format last login time"""
        if obj.last_login:
            now = timezone.now()
            diff = now - obj.last_login
            
            if diff.days > 0:
                return f"{diff.days} day(s) ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour(s) ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute(s) ago"
            else:
                return "Just now"
        return "Never"
    
    def get_current_consultation_info(self, obj):
        """Get current consultation information"""
        if obj.current_consultation:
            return {
                'id': obj.current_consultation.id,
                'patient_name': obj.current_consultation.patient.name if obj.current_consultation.patient else 'Unknown',
                'start_time': obj.current_consultation.start_time,
                'status': obj.current_consultation.status
            }
        return None


class DoctorStatusUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating doctor status"""
    
    class Meta:
        model = DoctorStatus
        fields = ['current_status', 'status_note', 'is_available']
    
    def validate_current_status(self, value):
        """Validate status change"""
        user = self.context['request'].user
        if not hasattr(user, 'doctor'):
            raise serializers.ValidationError("Only doctors can update their status")
        return value


class DoctorStatusListSerializer(serializers.ModelSerializer):
    """Serializer for listing doctor statuses with summary info"""
    
    doctor_name = serializers.CharField(source='doctor.user.name', read_only=True)
    doctor_specialization = serializers.CharField(source='doctor.specialization', read_only=True)
    doctor_profile_picture = serializers.CharField(source='doctor.user.profile_picture', read_only=True)
    status_display = serializers.CharField(read_only=True)
    last_activity_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = DoctorStatus
        fields = [
            'id', 'doctor', 'doctor_name', 'doctor_specialization', 
            'doctor_profile_picture', 'is_online', 'is_available',
            'current_status', 'status_display', 'last_activity_formatted'
        ]
    
    def get_last_activity_formatted(self, obj):
        """Format last activity time"""
        if obj.last_activity:
            now = timezone.now()
            diff = now - obj.last_activity
            
            if diff.days > 0:
                return f"{diff.days}d ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours}h ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes}m ago"
            else:
                return "Now"
        return "Never"

