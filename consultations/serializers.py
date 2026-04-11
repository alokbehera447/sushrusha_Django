from rest_framework import serializers
from django.utils import timezone
from authentication.models import User
from patients.models import PatientProfile
from doctors.models import DoctorProfile
from .models import (
    Consultation, ConsultationSymptom, ConsultationDiagnosis,
    ConsultationVitalSigns, ConsultationAttachment, ConsultationNote,
    ConsultationReschedule, ConsultationReceipt
)

class ConsultationSerializer(serializers.ModelSerializer):
    """Serializer for consultation"""
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    doctor_meeting_link = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Consultation
        fields = [
            'id', 'patient', 'doctor', 'patient_name', 'doctor_name',
            'consultation_type', 'scheduled_date', 'scheduled_time', 'duration',
            'status', 'doctor_notes', 'patient_notes', 'payment_status', 
            'consultation_fee', 'is_paid', 'payment_method', 'created_at', 'updated_at',
            'doctor_meeting_link', 'booked_slot', 'checked_in_at', 'checked_in_by',
            'ready_for_consultation_at', 'ready_marked_by', 'is_checked_in',
            'is_ready_for_consultation'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_checked_in', 'is_ready_for_consultation']

    def get_doctor_meeting_link(self, obj):
        if hasattr(obj, 'doctor') and hasattr(obj.doctor, 'doctor_profile') and hasattr(obj.doctor.doctor_profile, 'meeting_link'):
            return obj.doctor.doctor_profile.meeting_link
        return None


class ConsultationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation"""
    slot_id = serializers.IntegerField(write_only=True, help_text="ID of the doctor slot to book")
    
    class Meta:
        model = Consultation
        fields = [
            'patient', 'doctor', 'consultation_type', 'scheduled_date',
            'scheduled_time', 'duration', 'chief_complaint', 'symptoms',
            'consultation_fee', 'slot_id'
        ]
    
    def create(self, validated_data):
        """Create consultation and book the slot"""
        slot_id = validated_data.pop('slot_id')
        
        # Get the slot and validate it's available
        from doctors.models import DoctorSlot
        try:
            slot = DoctorSlot.objects.get(id=slot_id)
        except DoctorSlot.DoesNotExist:
            raise serializers.ValidationError("Invalid slot ID")
        
        if not slot.is_available or slot.is_booked:
            raise serializers.ValidationError("This slot is not available for booking")
        
        # Set consultation data from slot
        validated_data['scheduled_date'] = slot.date
        validated_data['scheduled_time'] = slot.start_time
        
        # Handle clinic and duration - use fallback if clinic is None
        if slot.clinic:
            validated_data['duration'] = slot.clinic.consultation_duration
            validated_data['clinic'] = slot.clinic
        else:
            # Fallback: use duration from request data or default to 30 minutes
            if 'duration' not in validated_data or not validated_data['duration']:
                validated_data['duration'] = 30  # Default 30 minutes
            validated_data['clinic'] = None
        validated_data['status'] = 'scheduled'
        validated_data['payment_status'] = 'pending'
        
        # Create the consultation
        consultation = super().create(validated_data)
        
        # Book the slot
        slot.is_booked = True
        slot.booked_consultation = consultation
        slot.save()
        
        # Send WhatsApp notification to doctor
        try:
            from .services import WhatsAppNotificationService
            whatsapp_service = WhatsAppNotificationService()
            
            # Send notification to doctor
            doctor_notification_sent = whatsapp_service.send_doctor_appointment_notification(consultation)
            if doctor_notification_sent:
                print(f"✅ WhatsApp notification sent to doctor: {consultation.doctor.name}")
            else:
                print(f"❌ Failed to send WhatsApp notification to doctor: {consultation.doctor.name}")
            
            # Send notification to patient
            patient_notification_sent = whatsapp_service.send_patient_appointment_confirmation(consultation)
            if patient_notification_sent:
                print(f"✅ WhatsApp notification sent to patient: {consultation.patient.name}")
            else:
                print(f"❌ Failed to send WhatsApp notification to patient: {consultation.patient.name}")
                
        except Exception as e:
            print(f"❌ Error in WhatsApp notification service: {str(e)}")
            # Don't fail the consultation creation if notification fails
        
        return consultation

    def validate(self, data):
        slot_id = data.get('slot_id')
        if not slot_id:
            raise serializers.ValidationError("Slot ID is required")
        
        # Validate slot exists and is available
        from doctors.models import DoctorSlot
        try:
            slot = DoctorSlot.objects.get(id=slot_id)
        except DoctorSlot.DoesNotExist:
            raise serializers.ValidationError("Invalid slot ID")
        
        if not slot.is_available or slot.is_booked:
            raise serializers.ValidationError("This slot is not available for booking")
        
        # Validate doctor matches slot
        if data.get('doctor') and data['doctor'] != slot.doctor:
            raise serializers.ValidationError("Doctor does not match the selected slot")
        
        return data


class ConsultationCreateDynamicSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation with dynamic slots (no slot_id required)"""
    clinic_id = serializers.CharField(write_only=True, required=False)
    payment_method = serializers.CharField(write_only=True, required=False)
    payment_status = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = Consultation
        fields = [
            'patient', 'doctor', 'consultation_type', 'scheduled_date',
            'scheduled_time', 'duration', 'chief_complaint', 'symptoms',
            'consultation_fee', 'clinic_id', 'payment_method', 'payment_status'
        ]
    
    def create(self, validated_data):
        """Create consultation without requiring a pre-existing slot"""
        print(f"🔍 ConsultationCreateDynamicSerializer.create called with: {validated_data}")
        
        # Extract clinic_id and set clinic
        clinic_id = validated_data.pop('clinic_id', None)
        if clinic_id:
            from eclinic.models import Clinic
            try:
                clinic = Clinic.objects.get(id=clinic_id)
                validated_data['clinic'] = clinic
                print(f"🔍 Found clinic: {clinic}")
            except Clinic.DoesNotExist:
                print(f"🔍 Clinic not found for ID: {clinic_id}")
                pass  # Continue without clinic if not found
        
        # Handle payment fields
        payment_method = validated_data.pop('payment_method', 'online')
        payment_status = validated_data.pop('payment_status', 'pending')
        
        # Set default values
        validated_data['status'] = 'scheduled'
        validated_data['payment_status'] = payment_status
        validated_data['payment_method'] = payment_method
        validated_data['is_paid'] = payment_status == 'paid'
        
        print(f"🔍 Final validated_data: {validated_data}")
        
        # Create the consultation
        consultation = super().create(validated_data)
        
        # Create corresponding Payment record
        try:
            from payments.models import Payment
            import uuid
            
            # Generate payment ID
            payment_id = f"PAY{uuid.uuid4().hex[:12].upper()}"
            
            # Create payment record
            payment = Payment.objects.create(
                id=payment_id,
                patient=consultation.patient,
                doctor=consultation.doctor,
                consultation=consultation,
                amount=consultation.consultation_fee,
                currency='INR',
                payment_type='consultation',
                description=f"Consultation fee for {consultation.consultation_type}",
                payment_method=payment_method,
                status='completed' if payment_status == 'paid' else 'pending',
                net_amount=consultation.consultation_fee,
                platform_fee=0,
                gateway_fee=0,
                tax_amount=0,
                discount_amount=0,
                processed_at=timezone.now() if payment_status == 'paid' else None,
                completed_at=timezone.now() if payment_status == 'paid' else None,
                receipt_number=f"RCP{payment_id}"
            )
            
            print(f"🔍 Created payment record: {payment}")
            
        except Exception as e:
            print(f"🔍 Error creating payment record: {e}")
            # Don't fail the consultation creation if payment creation fails
        
        print(f"🔍 Created consultation: {consultation}")
        
        # Update or create slot to mark it as booked
        try:
            from doctors.models import DoctorSlot
            from datetime import datetime, timedelta
            
            # Find existing slot for this time period
            consultation_start = datetime.combine(consultation.scheduled_date, consultation.scheduled_time)
            consultation_end = consultation_start + timedelta(minutes=consultation.duration)
            
            # Look for existing slots that overlap with this consultation time
            overlapping_slots = DoctorSlot.objects.filter(
                doctor=consultation.doctor,
                date=consultation.scheduled_date,
                start_time__lt=consultation_end.time(),
                end_time__gt=consultation_start.time(),
                is_available=True,
                is_booked=False
            )
            
            if overlapping_slots.exists():
                # Mark existing slot as booked
                slot = overlapping_slots.first()
                slot.is_booked = True
                slot.booked_consultation = consultation.id
                slot.save()
                print(f"🔍 Marked existing slot {slot.id} as booked for consultation {consultation.id}")
            else:
                # Create a new slot record for this consultation
                new_slot = DoctorSlot.objects.create(
                    doctor=consultation.doctor,
                    clinic=consultation.clinic if hasattr(consultation, 'clinic') and consultation.clinic else None,
                    date=consultation.scheduled_date,
                    start_time=consultation.scheduled_time,
                    end_time=(consultation_start + timedelta(minutes=consultation.duration)).time(),
                    is_available=False,
                    is_booked=True,
                    booked_consultation=consultation.id
                )
                print(f"🔍 Created new slot {new_slot.id} for consultation {consultation.id}")
                
        except Exception as e:
            print(f"🔍 Error updating slot status: {e}")
            # Don't fail the consultation creation if slot update fails
        
        # Send WhatsApp notification to doctor
        try:
            from .services import WhatsAppNotificationService
            whatsapp_service = WhatsAppNotificationService()
            
            # Send notification to doctor
            doctor_notification_sent = whatsapp_service.send_doctor_appointment_notification(consultation)
            if doctor_notification_sent:
                print(f"✅ WhatsApp notification sent to doctor: {consultation.doctor.name}")
            else:
                print(f"❌ Failed to send WhatsApp notification to doctor: {consultation.doctor.name}")
            
            # Send notification to patient
            patient_notification_sent = whatsapp_service.send_patient_appointment_confirmation(consultation)
            if patient_notification_sent:
                print(f"✅ WhatsApp notification sent to patient: {consultation.patient.name}")
            else:
                print(f"❌ Failed to send WhatsApp notification to patient: {consultation.patient.name}")
                
        except Exception as e:
            print(f"❌ Error in WhatsApp notification service: {str(e)}")
            # Don't fail the consultation creation if notification fails
        
        return consultation

    def validate(self, data):
        """Validate consultation data for dynamic slots"""
        print(f"🔍 ConsultationCreateDynamicSerializer.validate called with: {data}")
        
        # Check for overlapping consultations
        from datetime import datetime, timedelta
        from .models import Consultation
        
        scheduled_date = data.get('scheduled_date')
        scheduled_time = data.get('scheduled_time')
        duration = data.get('duration', 30)
        doctor = data.get('doctor')
        
        if scheduled_date and scheduled_time and doctor:
            # Calculate end time
            start_datetime = datetime.combine(scheduled_date, scheduled_time)
            end_datetime = start_datetime + timedelta(minutes=duration)
            
            # Check for overlapping consultations
            overlapping = Consultation.objects.filter(
                doctor=doctor,
                scheduled_date=scheduled_date,
                status__in=['scheduled', 'in_progress']
            ).filter(
                scheduled_time__lt=end_datetime.time(),
                scheduled_time__gte=scheduled_time
            ).exists()
            
            if overlapping:
                raise serializers.ValidationError("This time slot conflicts with an existing consultation")
        
        print(f"🔍 ConsultationCreateDynamicSerializer.validate returning: {data}")
        return data


class ConsultationUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating consultation"""
    
    class Meta:
        model = Consultation
        fields = [
            'consultation_type', 'scheduled_date', 'scheduled_time', 'duration',
            'status', 'doctor_notes', 'patient_notes', 'payment_status',
            'payment_method', 'is_paid'
        ]


class ConsultationSymptomSerializer(serializers.ModelSerializer):
    """Serializer for consultation symptom"""
    
    class Meta:
        model = ConsultationSymptom
        fields = ['id', 'consultation', 'symptom', 'severity', 'notes']
        read_only_fields = ['id']


class ConsultationSymptomCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation symptom"""
    
    class Meta:
        model = ConsultationSymptom
        fields = ['symptom', 'severity', 'notes']
    
    def create(self, validated_data):
        """Create symptom for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        validated_data['consultation_id'] = consultation_id
        return super().create(validated_data)


class ConsultationDiagnosisSerializer(serializers.ModelSerializer):
    """Serializer for consultation diagnosis"""
    
    class Meta:
        model = ConsultationDiagnosis
        fields = ['id', 'consultation', 'diagnosis', 'notes']
        read_only_fields = ['id']


class ConsultationDiagnosisCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation diagnosis"""
    
    class Meta:
        model = ConsultationDiagnosis
        fields = ['diagnosis', 'notes']
    
    def create(self, validated_data):
        """Create diagnosis for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        validated_data['consultation_id'] = consultation_id
        return super().create(validated_data)


class ConsultationVitalSignsSerializer(serializers.ModelSerializer):
    """Serializer for vital signs"""
    
    class Meta:
        model = ConsultationVitalSigns
        fields = [
            'id', 'consultation', 'blood_pressure_systolic', 'blood_pressure_diastolic', 
            'heart_rate', 'temperature', 'respiratory_rate', 'oxygen_saturation',
            'weight', 'height', 'bmi', 'blood_glucose', 'notes', 'recorded_at'
        ]
        read_only_fields = ['id', 'recorded_at']


class ConsultationVitalSignsCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating vital signs"""
    
    class Meta:
        model = ConsultationVitalSigns
        fields = [
            'blood_pressure_systolic', 'blood_pressure_diastolic', 'heart_rate', 'temperature',
            'respiratory_rate', 'oxygen_saturation', 'weight', 'height', 'bmi', 'blood_glucose', 'notes'
        ]
    
    def create(self, validated_data):
        """Create vital signs for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        validated_data['consultation_id'] = consultation_id
        return super().create(validated_data)


class ConsultationAttachmentSerializer(serializers.ModelSerializer):
    """Serializer for consultation attachments"""
    uploaded_by_name = serializers.CharField(source='uploaded_by.name', read_only=True)
    
    class Meta:
        model = ConsultationAttachment
        fields = [
            'id', 'consultation', 'attachment_type', 'title', 'description',
            'file', 'uploaded_by', 'uploaded_by_name', 'uploaded_at'
        ]
        read_only_fields = ['id', 'uploaded_by', 'uploaded_at']


class ConsultationAttachmentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation attachments"""
    
    class Meta:
        model = ConsultationAttachment
        fields = ['attachment_type', 'title', 'description', 'file']
    
    def create(self, validated_data):
        """Create attachment for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        uploaded_by = self.context['request'].user
        
        validated_data['consultation_id'] = consultation_id
        validated_data['uploaded_by'] = uploaded_by
        return super().create(validated_data)


class ConsultationNoteSerializer(serializers.ModelSerializer):
    """Serializer for consultation notes"""
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    
    class Meta:
        model = ConsultationNote
        fields = [
            'id', 'consultation', 'note_type', 'content',
            'created_by', 'created_by_name', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_by', 'created_at', 'updated_at']


class ConsultationNoteCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation notes"""
    
    class Meta:
        model = ConsultationNote
        fields = ['note_type', 'content']
    
    def create(self, validated_data):
        """Create note for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        created_by = self.context['request'].user
        
        validated_data['consultation_id'] = consultation_id
        validated_data['created_by'] = created_by
        return super().create(validated_data)


class ConsultationRescheduleSerializer(serializers.ModelSerializer):
    """Serializer for consultation reschedule"""
    
    class Meta:
        model = ConsultationReschedule
        fields = [
            'id', 'consultation', 'old_date', 'old_time',
            'new_date', 'new_time', 'reason', 'requested_by', 'created_at'
        ]
        read_only_fields = ['id', 'requested_by', 'created_at']


class ConsultationRescheduleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation reschedule"""
    
    class Meta:
        model = ConsultationReschedule
        fields = [
            'new_consultation_date', 'new_start_time',
            'new_end_time', 'reason'
        ]
    
    def create(self, validated_data):
        """Create reschedule for consultation"""
        consultation_id = self.context['view'].kwargs.get('consultation_id')
        rescheduled_by = self.context['request'].user
        
        validated_data['consultation_id'] = consultation_id
        validated_data['rescheduled_by'] = rescheduled_by
        return super().create(validated_data)


class ConsultationListSerializer(serializers.ModelSerializer):
    """Serializer for consultation list view"""
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    clinic_name = serializers.CharField(source='clinic.name', read_only=True)
    clinic_id = serializers.CharField(source='clinic.id', read_only=True)
    doctor_meeting_link = serializers.SerializerMethodField(read_only=True)
    is_overdue = serializers.SerializerMethodField()
    hours_overdue = serializers.SerializerMethodField()
    reschedule_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Consultation
        fields = [
            'id', 'patient', 'doctor', 'clinic', 'patient_name', 'doctor_name', 'clinic_name', 'clinic_id',
            'consultation_type', 'scheduled_date', 'scheduled_time', 'duration',
            'status', 'payment_status', 'consultation_fee', 'is_paid', 'created_at',
            'doctor_meeting_link', 'is_overdue', 'hours_overdue', 'reschedule_status',
            'reschedule_requested', 'reschedule_approved'
        ]
        read_only_fields = ['id', 'created_at']

    def get_doctor_meeting_link(self, obj):
        if hasattr(obj, 'doctor') and hasattr(obj.doctor, 'doctor_profile') and hasattr(obj.doctor.doctor_profile, 'meeting_link'):
            return obj.doctor.doctor_profile.meeting_link
        return None
    
    def get_is_overdue(self, obj):
        """Get whether consultation is overdue"""
        return obj.is_overdue
    
    def get_hours_overdue(self, obj):
        """Get hours overdue"""
        return round(obj.hours_overdue, 1) if obj.hours_overdue else 0
    
    def get_reschedule_status(self, obj):
        """Get reschedule status"""
        if obj.reschedule_approved:
            return 'approved'
        elif obj.reschedule_requested:
            return 'pending_approval'
        elif obj.is_eligible_for_reschedule:
            return 'eligible'
        else:
            return 'not_eligible'


class ConsultationRescheduleRequestSerializer(serializers.Serializer):
    """Serializer for requesting a consultation reschedule"""
    reason = serializers.CharField(max_length=500, required=False, help_text="Reason for reschedule request")
    
    def validate(self, attrs):
        """Validate reschedule request"""
        consultation = self.context.get('consultation')
        if not consultation:
            raise serializers.ValidationError("Consultation is required")
        
        if not consultation.is_eligible_for_reschedule:
            raise serializers.ValidationError("This consultation is not eligible for reschedule")
        
        return attrs


class ConsultationRescheduleApprovalSerializer(serializers.Serializer):
    """Serializer for approving a reschedule request"""
    approve = serializers.BooleanField(help_text="Whether to approve the reschedule request")
    reason = serializers.CharField(max_length=500, required=False, help_text="Additional notes for approval/rejection")


class ConsultationRescheduleApplySerializer(serializers.Serializer):
    """Serializer for applying an approved reschedule"""
    new_date = serializers.DateField(help_text="New consultation date")
    new_time = serializers.TimeField(help_text="New consultation time")
    reason = serializers.CharField(max_length=500, required=False, help_text="Reason for the reschedule")
    
    def validate(self, attrs):
        """Validate reschedule application"""
        consultation = self.context.get('consultation')
        if not consultation:
            raise serializers.ValidationError("Consultation is required")
        
        if not consultation.reschedule_approved:
            raise serializers.ValidationError("Reschedule must be approved before applying")
        
        # Check if new date/time is in the future
        from django.utils import timezone
        new_datetime = timezone.datetime.combine(attrs['new_date'], attrs['new_time'])
        if new_datetime <= timezone.now():
            raise serializers.ValidationError("New consultation time must be in the future")
        
        return attrs


class ConsultationOverdueSerializer(serializers.ModelSerializer):
    """Serializer for overdue consultations with reschedule information"""
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    hours_overdue = serializers.SerializerMethodField()
    is_eligible_for_reschedule = serializers.SerializerMethodField()
    reschedule_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Consultation
        fields = [
            'id', 'patient', 'doctor', 'patient_name', 'doctor_name',
            'scheduled_date', 'scheduled_time', 'duration', 'status',
            'hours_overdue', 'is_eligible_for_reschedule', 'reschedule_status',
            'reschedule_requested', 'reschedule_requested_at', 'reschedule_reason',
            'reschedule_approved', 'reschedule_approved_at', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_hours_overdue(self, obj):
        """Get hours overdue"""
        return round(obj.hours_overdue, 1) if obj.hours_overdue else 0
    
    def get_is_eligible_for_reschedule(self, obj):
        """Get eligibility for reschedule"""
        return obj.is_eligible_for_reschedule
    
    def get_reschedule_status(self, obj):
        """Get reschedule status"""
        if obj.reschedule_approved:
            return 'approved'
        elif obj.reschedule_requested:
            return 'pending_approval'
        elif obj.is_eligible_for_reschedule:
            return 'eligible'
        else:
            return 'not_eligible'


class ConsultationSearchSerializer(serializers.Serializer):
    """Serializer for consultation search"""
    query = serializers.CharField(max_length=200, required=False)
    patient_id = serializers.IntegerField(required=False)
    doctor_id = serializers.IntegerField(required=False)
    consultation_type = serializers.ChoiceField(
        choices=Consultation._meta.get_field('consultation_type').choices,
        required=False
    )
    status = serializers.ChoiceField(
        choices=Consultation._meta.get_field('status').choices,
        required=False
    )
    payment_status = serializers.ChoiceField(
        choices=Consultation._meta.get_field('payment_status').choices,
        required=False
    )
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)
    
    def validate(self, attrs):
        """Validate search parameters"""
        date_from = attrs.get('date_from')
        date_to = attrs.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise serializers.ValidationError('date_from cannot be greater than date_to')
        
        return attrs


class ConsultationStatsSerializer(serializers.Serializer):
    """Serializer for consultation statistics"""
    total_consultations = serializers.IntegerField()
    scheduled_consultations = serializers.IntegerField()
    completed_consultations = serializers.IntegerField()
    cancelled_consultations = serializers.IntegerField()
    total_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)
    consultation_trends = serializers.ListField()
    doctor_consultation_stats = serializers.DictField()


class ConsultationDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for consultation with related data"""
    patient_name = serializers.CharField(source='patient.name', read_only=True)
    patient_phone = serializers.CharField(source='patient.phone', read_only=True)
    patient_email = serializers.CharField(source='patient.email', read_only=True)
    patient_age = serializers.SerializerMethodField(read_only=True)
    patient_gender = serializers.SerializerMethodField(read_only=True)
    
    doctor_name = serializers.CharField(source='doctor.name', read_only=True)
    doctor_phone = serializers.CharField(source='doctor.phone', read_only=True)
    doctor_email = serializers.CharField(source='doctor.email', read_only=True)
    doctor_specialty = serializers.SerializerMethodField(read_only=True)
    doctor_meeting_link = serializers.SerializerMethodField(read_only=True)
    
    recorded_symptoms = ConsultationSymptomSerializer(many=True, read_only=True)
    diagnoses = ConsultationDiagnosisSerializer(many=True, read_only=True)
    vital_signs = serializers.SerializerMethodField(read_only=True)
    attachments = ConsultationAttachmentSerializer(many=True, read_only=True)
    notes = ConsultationNoteSerializer(many=True, read_only=True)
    reschedules = ConsultationRescheduleSerializer(many=True, read_only=True)
    prescription_data = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Consultation
        fields = [
            'id', 'patient', 'doctor', 'patient_name', 'patient_phone', 'patient_email', 'patient_age', 'patient_gender',
            'doctor_name', 'doctor_phone', 'doctor_email', 'doctor_specialty',
            'consultation_type', 'scheduled_date', 'scheduled_time', 'duration',
            'chief_complaint', 'symptoms', 'status',
            'actual_start_time', 'actual_end_time', 'consultation_fee',
            'is_paid', 'payment_method', 'payment_status', 'is_follow_up',
            'parent_consultation', 'follow_up_required', 'follow_up_date',
            'doctor_notes', 'patient_notes', 'prescription_given',
            'cancelled_by', 'cancellation_reason', 'cancelled_at',
            'recorded_symptoms', 'diagnoses', 'vital_signs', 'attachments', 'notes', 'reschedules',
            'prescription_data',
            'created_at', 'updated_at',
            'doctor_meeting_link',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_patient_age(self, obj):
        """Get patient age from date of birth"""
        if obj.patient.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - obj.patient.date_of_birth.year - (
                (today.month, today.day) < (obj.patient.date_of_birth.month, obj.patient.date_of_birth.day)
            )
        return None
    
    def get_patient_gender(self, obj):
        """Get patient gender"""
        if obj.patient.gender:
            return obj.patient.gender
        return None
    
    def get_doctor_specialty(self, obj):
        """Get doctor specialty"""
        if hasattr(obj.doctor, 'doctor_profile') and obj.doctor.doctor_profile.specialization:
            return obj.doctor.doctor_profile.specialization
        return "General Medicine"
    
    def get_doctor_meeting_link(self, obj):
        """Generate meeting link for doctor"""
        if hasattr(obj.doctor, 'doctor_profile') and obj.doctor.doctor_profile.meeting_link:
            return obj.doctor.doctor_profile.meeting_link
        return f"https://meet.google.com/{obj.id}-{obj.doctor.id}"
    
    def get_prescription_data(self, obj):
        """Get prescription data for the consultation"""
        try:
            # Lazy import to avoid circular import
            from prescriptions.models import Prescription
            from prescriptions.serializers import PrescriptionMedicationSerializer
            
            prescription = Prescription.objects.filter(consultation=obj).first()
            if prescription:
                return {
                    'id': prescription.id,
                    'issued_date': prescription.issued_date,
                    'issued_time': prescription.issued_time,
                    'primary_diagnosis': prescription.primary_diagnosis,
                    'patient_previous_history': prescription.patient_previous_history,
                    'general_instructions': prescription.general_instructions,
                    'diet_instructions': prescription.diet_instructions,
                    'lifestyle_advice': prescription.lifestyle_advice,
                    'next_visit': prescription.next_visit,
                    'follow_up_notes': prescription.follow_up_notes,
                    'is_finalized': prescription.is_finalized,
                    'medications': PrescriptionMedicationSerializer(
                        prescription.prescriptionmedication_set.all().order_by('order'), 
                        many=True
                    ).data
                }
            return None
        except Exception as e:
            print(f"Error getting prescription data: {e}")
            return None

    def get_vital_signs(self, obj):
        from .models import ConsultationVitalSigns
        try:
            vital = ConsultationVitalSigns.objects.get(consultation=obj)
            return ConsultationVitalSignsSerializer(vital).data
        except ConsultationVitalSigns.DoesNotExist:
            return None


class ConsultationReceiptSerializer(serializers.ModelSerializer):
    """Serializer for consultation receipts"""
    consultation_id = serializers.CharField(source='consultation.id', read_only=True)
    patient_name = serializers.CharField(source='consultation.patient.name', read_only=True)
    doctor_name = serializers.CharField(source='consultation.doctor.name', read_only=True)
    clinic_name = serializers.CharField(source='consultation.clinic.name', read_only=True)
    issued_by_name = serializers.CharField(source='issued_by.name', read_only=True)
    formatted_amount = serializers.CharField(read_only=True)
    receipt_data = serializers.JSONField(read_only=True)
    
    class Meta:
        model = ConsultationReceipt
        fields = [
            'id', 'receipt_number', 'consultation_id', 'patient_name', 'doctor_name', 
            'clinic_name', 'amount', 'formatted_amount', 'payment_method', 'payment_status',
            'issued_by', 'issued_by_name', 'issued_at', 'receipt_data'
        ]
        read_only_fields = ['id', 'receipt_number', 'issued_at', 'receipt_data']


class ConsultationReceiptCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating consultation receipts"""
    
    class Meta:
        model = ConsultationReceipt
        fields = ['consultation', 'amount', 'payment_method', 'payment_status', 'issued_by']
    
    def create(self, validated_data):
        """Create receipt with auto-generated receipt number"""
        consultation = validated_data['consultation']
        
        # Set receipt content
        validated_data['receipt_content'] = {
            'consultation_id': consultation.id,
            'patient_name': consultation.patient.name,
            'doctor_name': consultation.doctor.name,
            'clinic_name': consultation.clinic.name if consultation.clinic else 'N/A',
            'consultation_date': consultation.scheduled_date.isoformat(),
            'consultation_time': consultation.scheduled_time.isoformat(),
            'consultation_type': consultation.consultation_type,
            'chief_complaint': consultation.chief_complaint,
        }
        
        return super().create(validated_data)


class ConsultationCheckInSerializer(serializers.ModelSerializer):
    """Serializer for checking in a patient"""
    
    class Meta:
        model = Consultation
        fields = ['id', 'status', 'checked_in_at', 'checked_in_by']
        read_only_fields = ['id', 'checked_in_at', 'checked_in_by']


class ConsultationReadySerializer(serializers.ModelSerializer):
    """Serializer for marking patient as ready for consultation"""
    
    class Meta:
        model = Consultation
        fields = ['id', 'status', 'ready_for_consultation_at', 'ready_marked_by']
        read_only_fields = ['id', 'ready_for_consultation_at', 'ready_marked_by']


class ConsultationStartSerializer(serializers.ModelSerializer):
    """Serializer for starting a consultation"""
    
    class Meta:
        model = Consultation
        fields = ['id', 'status', 'actual_start_time']
        read_only_fields = ['id', 'actual_start_time']



