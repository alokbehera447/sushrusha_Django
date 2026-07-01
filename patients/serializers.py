from rest_framework import serializers
from django.utils import timezone
from authentication.models import User
from .models import PatientProfile, MedicalRecord, PatientDocument, PatientNote


class PatientProfileSerializer(serializers.ModelSerializer):
    """Serializer for patient profile detail - now works with User objects"""
    user_name = serializers.CharField(source='name', read_only=True)
    user_phone = serializers.CharField(source='phone', read_only=True)
    user_email = serializers.CharField(source='email', read_only=True)
    date_of_birth = serializers.DateField(read_only=True)
    gender = serializers.CharField(read_only=True)
    age = serializers.SerializerMethodField()
    
    # PatientProfile fields (may be None if profile doesn't exist)
    profile_id = serializers.SerializerMethodField()
    blood_group = serializers.SerializerMethodField()
    allergies = serializers.SerializerMethodField()
    chronic_conditions = serializers.SerializerMethodField()
    current_medications = serializers.SerializerMethodField()
    insurance_provider = serializers.SerializerMethodField()
    insurance_policy_number = serializers.SerializerMethodField()
    insurance_expiry = serializers.SerializerMethodField()
    preferred_language = serializers.SerializerMethodField()
    profile_is_active = serializers.SerializerMethodField()
    profile_created_at = serializers.SerializerMethodField()
    profile_updated_at = serializers.SerializerMethodField()
    has_profile = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'user_name', 'user_phone', 'user_email',
            'date_of_birth', 'gender', 'age',
            'street', 'city', 'state', 'pincode', 'country',
            'emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship',
            'medical_history', 'is_active', 'is_verified',
            'profile_id', 'blood_group', 'allergies', 'chronic_conditions', 'current_medications',
            'insurance_provider', 'insurance_policy_number', 'insurance_expiry',
            'preferred_language', 'profile_is_active', 'profile_created_at', 'profile_updated_at',
            'has_profile'
        ]
        read_only_fields = ['id']
    
    def get_age(self, obj):
        """Calculate age from date of birth"""
        if obj.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - obj.date_of_birth.year - ((today.month, today.day) < (obj.date_of_birth.month, obj.date_of_birth.day))
        return None
    
    def get_has_profile(self, obj):
        """Check if user has a PatientProfile"""
        return hasattr(obj, 'patient_profile') and obj.patient_profile is not None
    
    def get_profile_id(self, obj):
        """Get PatientProfile ID if exists"""
        return obj.patient_profile.id if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_blood_group(self, obj):
        """Get blood group from profile if exists"""
        return obj.patient_profile.blood_group if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_allergies(self, obj):
        """Get allergies from profile if exists"""
        return obj.patient_profile.allergies if hasattr(obj, 'patient_profile') and obj.patient_profile else ''
    
    def get_chronic_conditions(self, obj):
        """Get chronic conditions from profile if exists"""
        return obj.patient_profile.chronic_conditions if hasattr(obj, 'patient_profile') and obj.patient_profile else []
    
    def get_current_medications(self, obj):
        """Get current medications from profile if exists"""
        return obj.patient_profile.current_medications if hasattr(obj, 'patient_profile') and obj.patient_profile else []
    
    def get_insurance_provider(self, obj):
        """Get insurance provider from profile if exists"""
        return obj.patient_profile.insurance_provider if hasattr(obj, 'patient_profile') and obj.patient_profile else ''
    
    def get_insurance_policy_number(self, obj):
        """Get insurance policy number from profile if exists"""
        return obj.patient_profile.insurance_policy_number if hasattr(obj, 'patient_profile') and obj.patient_profile else ''
    
    def get_insurance_expiry(self, obj):
        """Get insurance expiry from profile if exists"""
        return obj.patient_profile.insurance_expiry if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_preferred_language(self, obj):
        """Get preferred language from profile if exists"""
        return obj.patient_profile.preferred_language if hasattr(obj, 'patient_profile') and obj.patient_profile else 'english'
    
    def get_profile_is_active(self, obj):
        """Get profile is_active status if exists"""
        return obj.patient_profile.is_active if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_profile_created_at(self, obj):
        """Get profile created_at if exists"""
        return obj.patient_profile.created_at if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_profile_updated_at(self, obj):
        """Get profile updated_at if exists"""
        return obj.patient_profile.updated_at if hasattr(obj, 'patient_profile') and obj.patient_profile else None


class PatientProfileCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating patient profile"""
    
    class Meta:
        model = PatientProfile
        fields = [
            'blood_group',
            'allergies', 'chronic_conditions', 'current_medications',
            'insurance_provider', 'insurance_policy_number', 'insurance_expiry',
            'preferred_language'
        ]
    
    def create(self, validated_data):
        """Create patient profile for authenticated user"""
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)


class MedicalRecordSerializer(serializers.ModelSerializer):
    """Serializer for medical records"""
    recorded_by_name = serializers.CharField(source='recorded_by.name', read_only=True)
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    document_url = serializers.SerializerMethodField()
    
    class Meta:
        model = MedicalRecord
        fields = [
            'id', 'patient', 'patient_name', 'record_type',
            'title', 'description', 'date_recorded', 'document', 'document_url',
            'recorded_by', 'recorded_by_name', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'patient', 'recorded_by', 'created_at', 'updated_at']
    
    def get_document_url(self, obj):
        """Get signed URL for document if it exists"""
        if obj.document:
            try:
                from utils.signed_urls import get_signed_media_url
                return get_signed_media_url(obj.document.name)
            except Exception:
                return obj.document.url if hasattr(obj.document, 'url') else None
        return None


class MedicalRecordCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating medical records"""
    description = serializers.CharField(required=False, allow_blank=True, default='')
    
    class Meta:
        model = MedicalRecord
        fields = [
            'record_type', 'title', 'description', 'date_recorded', 'document'
        ]
    
    def validate_document(self, value):
        """Validate uploaded document"""
        if value:
            # Check file size (max 100MB)
            max_size = 100 * 1024 * 1024  # 100MB
            if value.size > max_size:
                raise serializers.ValidationError("File size must be less than 100MB")
            
            # Check file type
            allowed_types = [
                'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
                'application/pdf', 'application/msword', 
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain'
            ]
            if value.content_type not in allowed_types:
                raise serializers.ValidationError(
                    "Only JPEG, PNG, GIF, PDF, DOC, DOCX, and TXT files are allowed"
                )
        
        return value
    
    def create(self, validated_data):
        """Create medical record for patient"""
        patient_id = self.context['view'].kwargs.get('patient_id')
        doctor = self.context['request'].user
        
        validated_data['patient_id'] = patient_id
        validated_data['recorded_by'] = doctor
        return super().create(validated_data)


class BulkMedicalRecordCreateSerializer(serializers.Serializer):
    """Serializer for creating multiple medical records at once"""
    record_type = serializers.ChoiceField(choices=MedicalRecord.RECORD_TYPES)
    title = serializers.CharField(max_length=200)
    date_recorded = serializers.DateField()
    documents = serializers.ListField(
        child=serializers.FileField(),
        required=True,
        min_length=1
    )
    
    def validate_documents(self, value):
        """Validate all uploaded documents"""
        allowed_types = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
            'application/pdf', 'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ]
        
        max_size = 100 * 1024 * 1024  # 100MB
        for doc in value:
            if doc.size > max_size:
                raise serializers.ValidationError(f"File '{doc.name}' exceeds 100MB limit")
            if doc.content_type not in allowed_types:
                raise serializers.ValidationError(
                    f"File '{doc.name}' has invalid type. Only JPEG, PNG, GIF, PDF, DOC, DOCX, and TXT files are allowed"
                )
        
        return value


class PatientDocumentSerializer(serializers.ModelSerializer):
    """Serializer for patient documents"""
    verified_by_name = serializers.CharField(source='verified_by.name', read_only=True)
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = PatientDocument
        fields = [
            'id', 'patient', 'patient_name', 'document_type', 'title', 'description',
            'file', 'file_url',
            'is_verified', 'verified_by', 'verified_by_name', 'verified_at',
            'uploaded_at', 'updated_at'
        ]
        read_only_fields = ['id', 'patient', 'verified_by', 'verified_at', 'uploaded_at', 'updated_at']
    
    def get_file_url(self, obj):
        """Get signed URL for file if it exists"""
        if obj.file:
            try:
                from utils.signed_urls import get_signed_media_url
                return get_signed_media_url(obj.file.name)
            except Exception:
                return obj.file.url if hasattr(obj.file, 'url') else None
        return None


class PatientDocumentUploadSerializer(serializers.ModelSerializer):
    """Serializer for uploading patient documents"""
    
    class Meta:
        model = PatientDocument
        fields = [
            'document_type', 'title', 'description', 'file'
        ]
    
    def validate_file(self, value):
        """Validate uploaded file"""
        if value:
            # Check file size (max 100MB)
            max_size = 100 * 1024 * 1024  # 100MB
            if value.size > max_size:
                raise serializers.ValidationError("File size must be less than 100MB")
            
            # Check file type
            allowed_types = [
                'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
                'application/pdf', 'application/msword', 
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain'
            ]
            if value.content_type not in allowed_types:
                raise serializers.ValidationError(
                    "Only JPEG, PNG, GIF, PDF, DOC, DOCX, and TXT files are allowed"
                )
        
        return value
    
    def create(self, validated_data):
        """Create patient document"""
        patient_id = self.context['view'].kwargs.get('patient_id')
        
        validated_data['patient_id'] = patient_id
        
        return super().create(validated_data)


class PatientNoteSerializer(serializers.ModelSerializer):
    """Serializer for patient notes"""
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    
    class Meta:
        model = PatientNote
        fields = [
            'id', 'patient', 'note',
            'is_private', 'created_by', 'created_by_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_by', 'created_at', 'updated_at']


class PatientNoteCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating patient notes"""
    
    class Meta:
        model = PatientNote
        fields = ['note', 'is_private']
    
    def create(self, validated_data):
        """Create patient note"""
        patient_id = self.context['view'].kwargs.get('patient_id')
        created_by = self.context['request'].user
        
        validated_data['patient_id'] = patient_id
        validated_data['created_by'] = created_by
        return super().create(validated_data)


class PatientListSerializer(serializers.ModelSerializer):
    """Serializer for patient list view - now works with User objects and includes profile data if available"""
    user_name = serializers.CharField(source='name', read_only=True)
    user_phone = serializers.CharField(source='phone', read_only=True)
    user_email = serializers.CharField(source='email', read_only=True)
    date_of_birth = serializers.DateField(read_only=True)
    gender = serializers.CharField(read_only=True)
    age = serializers.SerializerMethodField()
    total_consultations = serializers.SerializerMethodField()
    last_consultation_date = serializers.SerializerMethodField()
    
    # PatientProfile fields (may be None if profile doesn't exist)
    profile_id = serializers.SerializerMethodField()
    blood_group = serializers.SerializerMethodField()
    allergies = serializers.SerializerMethodField()
    chronic_conditions = serializers.SerializerMethodField()
    current_medications = serializers.SerializerMethodField()
    preferred_language = serializers.SerializerMethodField()
    profile_is_active = serializers.SerializerMethodField()
    profile_created_at = serializers.SerializerMethodField()
    profile_updated_at = serializers.SerializerMethodField()
    has_profile = serializers.SerializerMethodField()
    
    # Clinic information
    clinics = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'user_name', 'user_phone', 'user_email',
            'date_of_birth', 'gender', 'age',
            'street', 'city', 'state', 'pincode', 'country',
            'emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship',
            'medical_history', 'is_active', 'is_verified',
            'profile_id', 'blood_group', 'allergies', 'chronic_conditions', 'current_medications',
            'preferred_language', 'profile_is_active', 'profile_created_at', 'profile_updated_at',
            'total_consultations', 'last_consultation_date', 'has_profile', 'clinics'
        ]
    
    def get_age(self, obj):
        """Calculate age from date of birth"""
        if obj.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - obj.date_of_birth.year - ((today.month, today.day) < (obj.date_of_birth.month, obj.date_of_birth.day))
        return None
    
    def get_has_profile(self, obj):
        """Check if user has a PatientProfile"""
        return hasattr(obj, 'patient_profile') and obj.patient_profile is not None
    
    def get_profile_id(self, obj):
        """Get PatientProfile ID if exists"""
        return obj.patient_profile.id if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_blood_group(self, obj):
        """Get blood group from profile if exists"""
        return obj.patient_profile.blood_group if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_allergies(self, obj):
        """Get allergies from profile if exists"""
        return obj.patient_profile.allergies if hasattr(obj, 'patient_profile') and obj.patient_profile else ''
    
    def get_chronic_conditions(self, obj):
        """Get chronic conditions from profile if exists"""
        return obj.patient_profile.chronic_conditions if hasattr(obj, 'patient_profile') and obj.patient_profile else []
    
    def get_current_medications(self, obj):
        """Get current medications from profile if exists"""
        return obj.patient_profile.current_medications if hasattr(obj, 'patient_profile') and obj.patient_profile else []
    
    def get_preferred_language(self, obj):
        """Get preferred language from profile if exists"""
        return obj.patient_profile.preferred_language if hasattr(obj, 'patient_profile') and obj.patient_profile else 'english'
    
    def get_profile_is_active(self, obj):
        """Get profile is_active status if exists"""
        return obj.patient_profile.is_active if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_profile_created_at(self, obj):
        """Get profile created_at if exists"""
        return obj.patient_profile.created_at if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_profile_updated_at(self, obj):
        """Get profile updated_at if exists"""
        return obj.patient_profile.updated_at if hasattr(obj, 'patient_profile') and obj.patient_profile else None
    
    def get_total_consultations(self, obj):
        """Get total number of consultations"""
        return obj.patient_consultations.count()
    
    def get_last_consultation_date(self, obj):
        """Get last consultation date"""
        last_consultation = obj.patient_consultations.order_by('-created_at').first()
        if last_consultation:
            return last_consultation.created_at
        return None
    
    def get_clinics(self, obj):
        """Get list of clinics this patient is registered to"""
        from eclinic.models import ClinicPatient
        clinic_patients = ClinicPatient.objects.filter(
            patient=obj,
            is_active=True
        ).select_related('clinic')
        
        return [
            {
                'clinic_id': cp.clinic.id,
                'clinic_name': cp.clinic.name,
                'registered_at': cp.registered_at,
                'registration_source': cp.registration_source
            }
            for cp in clinic_patients
        ]


class PatientSearchSerializer(serializers.Serializer):
    """Serializer for patient search"""
    query = serializers.CharField(max_length=200, required=False)
    gender = serializers.ChoiceField(
        choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')],
        required=False
    )
    blood_group = serializers.ChoiceField(
        choices=[
            ('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'),
            ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')
        ],
        required=False
    )
    age_min = serializers.IntegerField(min_value=0, max_value=150, required=False)
    age_max = serializers.IntegerField(min_value=0, max_value=150, required=False)
    city = serializers.CharField(max_length=100, required=False)
    state = serializers.CharField(max_length=100, required=False)
    
    def validate(self, attrs):
        """Validate search parameters"""
        min_age = attrs.get('age_min')
        max_age = attrs.get('age_max')
        if min_age and max_age and min_age > max_age:
            raise serializers.ValidationError('age_min cannot be greater than age_max')
        return attrs


class PatientStatsSerializer(serializers.Serializer):
    """Serializer for patient statistics"""
    total_patients = serializers.IntegerField()
    new_patients_this_month = serializers.IntegerField()
    active_patients = serializers.IntegerField()
    gender_distribution = serializers.DictField()
    age_distribution = serializers.DictField()
    blood_group_distribution = serializers.DictField()
    top_cities = serializers.ListField()
    consultation_stats = serializers.DictField()

