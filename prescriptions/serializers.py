from rest_framework import serializers
from .models import Prescription, PrescriptionMedication, PrescriptionVitalSigns, PrescriptionPDF, InvestigationCategory, InvestigationTest, PrescriptionInvestigation

# Simple User Serializer for prescription system
class UserSerializer(serializers.Serializer):
    """Simple user serializer for prescription system"""
    id = serializers.CharField()  # Changed from IntegerField to CharField to match User model
    name = serializers.CharField()
    phone = serializers.CharField()
    email = serializers.EmailField(required=False, allow_blank=True)
    role = serializers.CharField()
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    gender = serializers.CharField(required=False, allow_blank=True)

class PrescriptionVitalSignsSerializer(serializers.ModelSerializer):
    """Serializer for prescription vital signs"""
    
    class Meta:
        model = PrescriptionVitalSigns
        fields = [
            'id', 'pulse', 'blood_pressure_systolic', 'blood_pressure_diastolic',
            'temperature', 'weight', 'height', 'respiratory_rate', 'oxygen_saturation',
            'blood_sugar_fasting', 'blood_sugar_postprandial', 'hba1c', 'notes',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

class PrescriptionMedicationSerializer(serializers.ModelSerializer):
    """Serializer for prescription medications"""
    
    dosage_display = serializers.SerializerMethodField()
    timing_display = serializers.SerializerMethodField()
    frequency_display = serializers.SerializerMethodField()
    
    class Meta:
        model = PrescriptionMedication
        fields = [
            'id', 'medicine_name', 'composition', 'dosage_form',
            'morning_dose', 'afternoon_dose', 'evening_dose',
            'dosage_display', 'frequency', 'frequency_display',
            'timing', 'timing_display', 'custom_timing',
            'duration_days', 'duration_weeks', 'duration_months', 'is_continuous',
            'quantity', 'special_instructions', 'notes', 'order',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_dosage_display(self, obj):
        """Format dosage as M-A-N format (e.g., 1-0-1)"""
        return f"{obj.morning_dose}-{obj.afternoon_dose}-{obj.evening_dose}"
    
    def get_timing_display(self, obj):
        """Get human-readable timing"""
        timing_map = dict(PrescriptionMedication.TIMING_CHOICES)
        return timing_map.get(obj.timing, obj.timing)
    
    def get_frequency_display(self, obj):
        """Get human-readable frequency"""
        frequency_map = dict(PrescriptionMedication.FREQUENCY_CHOICES)
        return frequency_map.get(obj.frequency, obj.frequency)

class InvestigationCategorySerializer(serializers.ModelSerializer):
    """Serializer for investigation categories"""
    
    class Meta:
        model = InvestigationCategory
        fields = '__all__'


class InvestigationTestSerializer(serializers.ModelSerializer):
    """Serializer for investigation tests"""
    
    category = InvestigationCategorySerializer(read_only=True)
    category_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = InvestigationTest
        fields = '__all__'


class PrescriptionInvestigationSerializer(serializers.ModelSerializer):
    """Serializer for prescription investigations"""
    
    test = InvestigationTestSerializer(read_only=True)
    test_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = PrescriptionInvestigation
        fields = '__all__'


class PrescriptionInvestigationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating prescription investigations"""
    
    class Meta:
        model = PrescriptionInvestigation
        fields = ['test_id', 'priority', 'special_instructions', 'notes', 'order']


class InvestigationListResponseSerializer(serializers.Serializer):
    """Response serializer for investigation list"""
    categories = InvestigationCategorySerializer(many=True)
    tests = InvestigationTestSerializer(many=True)


class PrescriptionSerializer(serializers.ModelSerializer):
    """Enhanced prescription serializer"""
    
    doctor = UserSerializer(read_only=True)
    patient = UserSerializer(read_only=True)
    consultation_id = serializers.CharField(source='consultation.id', read_only=True)
    consultation_date = serializers.DateField(source='consultation.scheduled_date', read_only=True)
    consultation_time = serializers.TimeField(source='consultation.scheduled_time', read_only=True)
    medications = PrescriptionMedicationSerializer(many=True, read_only=True)
    vital_signs = PrescriptionVitalSignsSerializer(read_only=True)
    investigations = PrescriptionInvestigationSerializer(many=True, read_only=True)
    
    # Computed fields
    patient_age = serializers.SerializerMethodField()
    patient_gender = serializers.SerializerMethodField()
    blood_pressure_display = serializers.SerializerMethodField()
    
    class Meta:
        model = Prescription
        fields = [
            'id', 'consultation_id', 'consultation_date', 'consultation_time', 'doctor', 'patient', 'patient_age', 'patient_gender',
            'issued_date', 'issued_time',
            'pulse', 'blood_pressure_systolic', 'blood_pressure_diastolic', 'blood_pressure_display',
            'temperature', 'weight', 'height',
            'primary_diagnosis', 'patient_previous_history', 'clinical_classification',
            'general_instructions', 'fluid_intake', 'diet_instructions', 'lifestyle_advice',
            'next_visit', 'follow_up_notes',
            'is_draft', 'is_finalized',
            'medications', 'vital_signs', 'investigations',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'issued_date', 'issued_time', 'created_at', 'updated_at']
    
    def get_patient_age(self, obj):
        """Calculate patient age"""
        if obj.patient.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - obj.patient.date_of_birth.year - (
                (today.month, today.day) < (obj.patient.date_of_birth.month, obj.patient.date_of_birth.day)
            )
        return None
    
    def get_patient_gender(self, obj):
        """Get patient gender"""
        return obj.patient.gender if hasattr(obj.patient, 'gender') else None
    
    def get_blood_pressure_display(self, obj):
        """Format blood pressure display"""
        if obj.blood_pressure_systolic and obj.blood_pressure_diastolic:
            return f"{obj.blood_pressure_systolic}/{obj.blood_pressure_diastolic} mmHg"
        return None

class PrescriptionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating prescriptions"""
    
    medications = PrescriptionMedicationSerializer(many=True, required=False)
    vital_signs = PrescriptionVitalSignsSerializer(required=False)
    
    class Meta:
        model = Prescription
        fields = [
            'consultation', 'patient',
            'pulse', 'blood_pressure_systolic', 'blood_pressure_diastolic',
            'temperature', 'weight', 'height',
            'primary_diagnosis', 'patient_previous_history', 'clinical_classification',
            'general_instructions', 'fluid_intake', 'diet_instructions', 'lifestyle_advice',
            'next_visit', 'follow_up_notes',
            'medications', 'vital_signs'
        ]
    
    def create(self, validated_data):
        medications_data = validated_data.pop('medications', [])
        vital_signs_data = validated_data.pop('vital_signs', None)
        
        # Set doctor from request user, but allow override (e.g. superadmin writing on behalf of doctor)
        override_doctor = self.context.get('override_doctor')
        validated_data['doctor'] = override_doctor if override_doctor else self.context['request'].user
        
        # Create prescription
        prescription = Prescription.objects.create(**validated_data)
        
        # Create medications
        for i, medication_data in enumerate(medications_data):
            medication_data['order'] = i + 1
            PrescriptionMedication.objects.create(prescription=prescription, **medication_data)
        
        # Create vital signs if provided
        if vital_signs_data:
            PrescriptionVitalSigns.objects.create(prescription=prescription, **vital_signs_data)
        
        return prescription

class PrescriptionUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating prescriptions"""
    
    medications = PrescriptionMedicationSerializer(many=True, required=False)
    vital_signs = PrescriptionVitalSignsSerializer(required=False)
    
    class Meta:
        model = Prescription
        fields = [
            'pulse', 'blood_pressure_systolic', 'blood_pressure_diastolic',
            'temperature', 'weight', 'height',
            'primary_diagnosis', 'patient_previous_history', 'clinical_classification',
            'general_instructions', 'fluid_intake', 'diet_instructions', 'lifestyle_advice',
            'next_visit', 'follow_up_notes',
            'is_draft', 'is_finalized',
            'medications', 'vital_signs'
        ]
    
    def update(self, instance, validated_data):
        medications_data = validated_data.pop('medications', None)
        vital_signs_data = validated_data.pop('vital_signs', None)
        
        # Update prescription
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update medications if provided
        if medications_data is not None:
            # Delete existing medications
            instance.medications.all().delete()
            
            # Create new medications
            for i, medication_data in enumerate(medications_data):
                medication_data['order'] = i + 1
                PrescriptionMedication.objects.create(prescription=instance, **medication_data)
        
        # Update vital signs if provided
        if vital_signs_data is not None:
            vital_signs, created = PrescriptionVitalSigns.objects.get_or_create(
                prescription=instance,
                defaults=vital_signs_data
            )
            if not created:
                for attr, value in vital_signs_data.items():
                    setattr(vital_signs, attr, value)
                vital_signs.save()
        
        return instance




class PrescriptionListSerializer(serializers.ModelSerializer):
    """Serializer for listing prescriptions"""
    
    doctor = UserSerializer(read_only=True)
    patient = UserSerializer(read_only=True)
    medication_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Prescription
        fields = [
            'id', 'consultation', 'doctor', 'patient', 'issued_date', 'issued_time',
            'primary_diagnosis', 'is_draft', 'is_finalized', 'medication_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'issued_date', 'issued_time', 'created_at', 'updated_at']
    
    def get_medication_count(self, obj):
        """Get count of medications"""
        return obj.medications.count()

class PrescriptionDetailSerializer(PrescriptionSerializer):
    """Detailed prescription serializer with all related data"""
    
    # These are computed fields, not model fields
    consultation_details = serializers.SerializerMethodField()
    patient_history = serializers.SerializerMethodField()
    current_pdf = serializers.SerializerMethodField()
    
    class Meta(PrescriptionSerializer.Meta):
        fields = PrescriptionSerializer.Meta.fields + [
            'consultation_details', 'patient_history', 'current_pdf'
        ]
    
    def get_consultation_details(self, obj):
        """Get consultation details"""
        if obj.consultation:
            return {
                'id': obj.consultation.id,
                'scheduled_date': obj.consultation.scheduled_date,
                'scheduled_time': obj.consultation.scheduled_time,
                'status': obj.consultation.status,
                'consultation_type': obj.consultation.consultation_type,
                'chief_complaint': obj.consultation.chief_complaint,
            }
        return None
    
    def get_patient_history(self, obj):
        """Get patient history (last 5 prescriptions)"""
        patient_prescriptions = Prescription.objects.filter(
            patient=obj.patient
        ).exclude(id=obj.id).order_by('-created_at')[:5]
        
        return PrescriptionListSerializer(
            patient_prescriptions, many=True
        ).data
    
    def get_current_pdf(self, obj):
        """Get current PDF version for finalized prescriptions"""
        if obj.is_finalized:
            current_pdf = obj.pdf_versions.filter(is_current=True).first()
            if current_pdf:
                return PrescriptionPDFSerializer(
                    current_pdf, 
                    context=self.context
                ).data
        return None


class PrescriptionPDFSerializer(serializers.ModelSerializer):
    """Serializer for prescription PDF versions"""
    
    generated_by = UserSerializer(read_only=True)
    file_url = serializers.SerializerMethodField()
    prescription_info = serializers.SerializerMethodField()
    
    class Meta:
        model = PrescriptionPDF
        fields = [
            'id', 'version_number', 'is_current', 'generated_at', 'generated_by',
            'file_url', 'file_size', 'checksum', 'prescription_info'
        ]
        read_only_fields = ['id', 'version_number', 'generated_at', 'file_size', 'checksum']
    
    def get_file_url(self, obj):
        """Get PDF file URL with signed URL"""
        if obj.pdf_file:
            try:
                from utils.signed_urls import generate_signed_url
                from django.conf import settings
                
                # Generate signed URL for the PDF file
                file_key = str(obj.pdf_file)
                aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                if not file_key.startswith(f"{aws_location}/"):
                    file_key = f"{aws_location}/{file_key}"
                
                signed_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                return signed_url
                
            except Exception as e:
                print(f"Error generating signed URL for PDF {obj.id}: {e}")
                # Fallback to direct URL
                request = self.context.get('request')
                if request:
                    return request.build_absolute_uri(obj.pdf_file.url)
                return obj.pdf_file.url
        return None
    
    def get_prescription_info(self, obj):
        """Get basic prescription information"""
        return {
            'id': obj.prescription.id,
            'patient_name': obj.prescription.patient.name,
            'doctor_name': obj.prescription.doctor.name,
            'issued_date': obj.prescription.issued_date,
            'primary_diagnosis': obj.prescription.primary_diagnosis
        }


class PrescriptionWithPDFSerializer(PrescriptionDetailSerializer):
    """Prescription serializer with PDF version information"""
    
    pdf_versions = serializers.SerializerMethodField()
    current_pdf = serializers.SerializerMethodField()
    
    class Meta(PrescriptionDetailSerializer.Meta):
        fields = PrescriptionDetailSerializer.Meta.fields + [
            'pdf_versions', 'current_pdf'
        ]
    
    def get_pdf_versions(self, obj):
        """Get all PDF versions for this prescription"""
        pdf_versions = obj.pdf_versions.order_by('-version_number')
        return PrescriptionPDFSerializer(
            pdf_versions, 
            many=True, 
            context=self.context
        ).data
    
    def get_current_pdf(self, obj):
        """Get current PDF version"""
        current_pdf = obj.pdf_versions.filter(is_current=True).first()
        if current_pdf:
            return PrescriptionPDFSerializer(
                current_pdf, 
                context=self.context
            ).data
        return None


class InvestigationCategorySerializer(serializers.ModelSerializer):
    """Serializer for investigation categories"""
    
    class Meta:
        model = InvestigationCategory
        fields = '__all__'


class InvestigationTestSerializer(serializers.ModelSerializer):
    """Serializer for investigation tests"""
    
    category = InvestigationCategorySerializer(read_only=True)
    category_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = InvestigationTest
        fields = '__all__'


class PrescriptionInvestigationSerializer(serializers.ModelSerializer):
    """Serializer for prescription investigations"""
    
    test = InvestigationTestSerializer(read_only=True)
    test_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = PrescriptionInvestigation
        fields = '__all__'


class PrescriptionInvestigationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating prescription investigations"""
    
    class Meta:
        model = PrescriptionInvestigation
        fields = ['test_id', 'priority', 'special_instructions', 'notes', 'order']


class InvestigationListResponseSerializer(serializers.Serializer):
    """Response serializer for investigation list"""
    categories = InvestigationCategorySerializer(many=True)
    tests = InvestigationTestSerializer(many=True)



