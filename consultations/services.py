import requests
import json
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from django.db.models import Q, Count, Avg, Sum
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import logging
from django.db import transaction
from django.utils import timezone
from datetime import datetime, timedelta

from .models import Consultation, ConsultationNote, ConsultationVitalSigns, ConsultationDiagnosis
from doctors.models import DoctorSlot
from authentication.models import User

logger = logging.getLogger(__name__)

class WhatsAppNotificationService:
    """Service for sending WhatsApp notifications via MSG91 API"""
    
    def __init__(self):
        self.auth_key = "416664AgVFnjJ8nhio65d6fc7bP1"
        self.integrated_number = "917008182954"
        self.template_name = "diracai3"
        self.namespace = "1159b496_e313_4115_ace7_0210e4de2eea"
        self.api_url = "https://api.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/"
    
    def send_doctor_appointment_notification(self, consultation):
        """
        Send WhatsApp notification to doctor about scheduled appointment
        
        Args:
            consultation: Consultation object with all details
        """
        try:
            # Get doctor's phone number
            doctor_phone = consultation.doctor.phone
            if not doctor_phone:
                print(f"❌ No phone number found for doctor: {consultation.doctor.name}")
                return False
            
            # Format phone number with 91 prefix
            if not doctor_phone.startswith('91'):
                doctor_phone = f"91{doctor_phone}"
            
            # Format date and time
            scheduled_date = consultation.scheduled_date.strftime("%d %B, %Y")
            scheduled_time = consultation.scheduled_time.strftime("%I:%M %p")
            
            # Get meeting link
            try:
                meeting_link = consultation.doctor_meeting_link
            except:
                meeting_link = "Meeting link will be shared soon"
            
            # Prepare the API payload
            payload = {
                "integrated_number": self.integrated_number,
                "content_type": "template",
                "payload": {
                    "messaging_product": "whatsapp",
                    "type": "template",
                    "template": {
                        "name": self.template_name,
                        "language": {
                            "code": "en",
                            "policy": "deterministic"
                        },
                        "namespace": self.namespace,
                        "to_and_components": [
                            {
                                "to": [doctor_phone],
                                "components": [
                                    {
                                        "type": "body",
                                        "parameters": [
                                            {
                                                "type": "text",
                                                "text": consultation.doctor.name
                                            },
                                            {
                                                "type": "text",
                                                "text": scheduled_date
                                            },
                                            {
                                                "type": "text",
                                                "text": scheduled_time
                                            },
                                            {
                                                "type": "text",
                                                "text": consultation.patient.name
                                            },
                                            {
                                                "type": "text",
                                                "text": consultation.consultation_type
                                            },
                                            {
                                                "type": "text",
                                                "text": meeting_link
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
            
            # Send the request
            headers = {
                'Content-Type': 'application/json',
                'authkey': self.auth_key
            }
            
            print(f"📱 Sending WhatsApp notification to doctor: {consultation.doctor.name} ({doctor_phone})")
            print(f"📱 Payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            print(f"📱 WhatsApp API Response Status: {response.status_code}")
            print(f"📱 WhatsApp API Response: {response.text}")
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get('status') == 'success':
                    print(f"✅ WhatsApp notification sent successfully to doctor: {consultation.doctor.name}")
                    return True
                else:
                    print(f"❌ WhatsApp API returned error: {response_data}")
                    return False
            else:
                print(f"❌ WhatsApp API request failed with status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending WhatsApp notification: {str(e)}")
            return False
    
    def send_patient_appointment_confirmation(self, consultation):
        """
        Send WhatsApp notification to patient about appointment confirmation
        
        Args:
            consultation: Consultation object with all details
        """
        try:
            # Get patient's phone number
            patient_phone = consultation.patient.phone
            if not patient_phone:
                print(f"❌ No phone number found for patient: {consultation.patient.name}")
                return False
            
            # Format phone number with 91 prefix
            if not patient_phone.startswith('91'):
                patient_phone = f"91{patient_phone}"
            
            # Format date and time
            scheduled_date = consultation.scheduled_date.strftime("%d %B, %Y")
            scheduled_time = consultation.scheduled_time.strftime("%I:%M %p")
            
            # Get meeting link
            try:
                meeting_link = consultation.doctor_meeting_link
            except:
                meeting_link = "Meeting link will be shared soon"
            
            # Prepare the API payload (using same template for now)
            payload = {
                "integrated_number": self.integrated_number,
                "content_type": "template",
                "payload": {
                    "messaging_product": "whatsapp",
                    "type": "template",
                    "template": {
                        "name": self.template_name,
                        "language": {
                            "code": "en",
                            "policy": "deterministic"
                        },
                        "namespace": self.namespace,
                        "to_and_components": [
                            {
                                "to": [patient_phone],
                                "components": [
                                    {
                                        "type": "body",
                                        "parameters": [
                                            {
                                                "type": "text",
                                                "text": consultation.patient.name
                                            },
                                            {
                                                "type": "text",
                                                "text": scheduled_date
                                            },
                                            {
                                                "type": "text",
                                                "text": scheduled_time
                                            },
                                            {
                                                "type": "text",
                                                "text": consultation.doctor.name
                                            },
                                            {
                                                "type": "text",
                                                "text": consultation.consultation_type
                                            },
                                            {
                                                "type": "text",
                                                "text": meeting_link
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
            
            # Send the request
            headers = {
                'Content-Type': 'application/json',
                'authkey': self.auth_key
            }
            
            print(f"📱 Sending WhatsApp notification to patient: {consultation.patient.name} ({patient_phone})")
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            print(f"📱 WhatsApp API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get('status') == 'success':
                    print(f"✅ WhatsApp notification sent successfully to patient: {consultation.patient.name}")
                    return True
                else:
                    print(f"❌ WhatsApp API returned error: {response_data}")
                    return False
            else:
                print(f"❌ WhatsApp API request failed with status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending WhatsApp notification: {str(e)}")
            return False 


class ConsultationService:
    """Service class for consultation business logic"""
    
    @staticmethod
    def create_consultation(
        patient: User,
        doctor: User,
        scheduled_date: datetime.date,
        scheduled_time: datetime.time,
        duration: int = 30,
        consultation_type: str = 'video_call',
        chief_complaint: str = '',
        symptoms: str = '',
        consultation_fee: float = 0.0,
        clinic=None,
        slot=None
    ) -> Consultation:
        """
        Create a new consultation with validation
        """
        # Validate inputs
        if not patient or not doctor:
            raise ValidationError("Patient and doctor are required")
        
        if patient.role != 'patient':
            raise ValidationError("User must be a patient")
        
        if doctor.role != 'doctor':
            raise ValidationError("User must be a doctor")
        
        # Check for scheduling conflicts
        conflict = ConsultationService.check_scheduling_conflict(
            doctor, scheduled_date, scheduled_time, duration
        )
        if conflict:
            raise ValidationError(f"Scheduling conflict: {conflict}")
        
        # Create consultation
        consultation = Consultation.objects.create(
            patient=patient,
            doctor=doctor,
            scheduled_date=scheduled_date,
            scheduled_time=scheduled_time,
            duration=duration,
            consultation_type=consultation_type,
            chief_complaint=chief_complaint,
            symptoms=symptoms,
            consultation_fee=consultation_fee,
            clinic=clinic,
            slot=slot
        )
        
        logger.info(f"Created consultation {consultation.id} for patient {patient.name} with doctor {doctor.name}")
        return consultation
    
    @staticmethod
    def check_scheduling_conflict(
        doctor: User,
        scheduled_date: datetime.date,
        scheduled_time: datetime.time,
        duration: int
    ) -> Optional[str]:
        """
        Check for scheduling conflicts for a doctor
        """
        # Convert to datetime for comparison
        scheduled_datetime = datetime.combine(scheduled_date, scheduled_time)
        end_datetime = scheduled_datetime + timedelta(minutes=duration)
        
        # Check existing consultations
        existing_consultations = Consultation.objects.filter(
            doctor=doctor,
            scheduled_date=scheduled_date,
            status__in=['scheduled', 'in_progress']
        )
        
        for consultation in existing_consultations:
            existing_start = datetime.combine(consultation.scheduled_date, consultation.scheduled_time)
            existing_end = existing_start + timedelta(minutes=consultation.duration)
            
            # Check for overlap
            if (scheduled_datetime < existing_end and end_datetime > existing_start):
                return f"Conflicts with consultation {consultation.id} ({existing_start.time()} - {existing_end.time()})"
        
        return None
    
    @staticmethod
    def get_doctor_consultations(
        doctor: User,
        status: Optional[str] = None,
        date_from: Optional[datetime.date] = None,
        date_to: Optional[datetime.date] = None,
        search: Optional[str] = None
    ) -> List[Consultation]:
        """
        Get consultations for a specific doctor with filtering
        """
        queryset = Consultation.objects.filter(doctor=doctor).select_related(
            'patient', 'clinic'
        ).prefetch_related('recorded_symptoms', 'diagnoses', 'vital_signs')
        
        # Apply filters
        if status:
            queryset = queryset.filter(status=status)
        
        if date_from:
            queryset = queryset.filter(scheduled_date__gte=date_from)
        
        if date_to:
            queryset = queryset.filter(scheduled_date__lte=date_to)
        
        if search:
            queryset = queryset.filter(
                Q(patient__name__icontains=search) |
                Q(patient__phone__icontains=search) |
                Q(chief_complaint__icontains=search) |
                Q(symptoms__icontains=search)
            )
        
        return queryset.order_by('-scheduled_date', '-scheduled_time')
    
    @staticmethod
    def get_patient_consultations(
        patient: User,
        status: Optional[str] = None,
        date_from: Optional[datetime.date] = None,
        date_to: Optional[datetime.date] = None
    ) -> List[Consultation]:
        """
        Get consultations for a specific patient with filtering
        """
        queryset = Consultation.objects.filter(patient=patient).select_related(
            'doctor', 'clinic'
        ).prefetch_related('recorded_symptoms', 'diagnoses', 'vital_signs')
        
        # Apply filters
        if status:
            queryset = queryset.filter(status=status)
        
        if date_from:
            queryset = queryset.filter(scheduled_date__gte=date_from)
        
        if date_to:
            queryset = queryset.filter(scheduled_date__lte=date_to)
        
        return queryset.order_by('-scheduled_date', '-scheduled_time')
    
    @staticmethod
    def start_consultation(consultation: Consultation) -> bool:
        """
        Start a consultation
        """
        if consultation.status != 'scheduled':
            raise ValidationError("Only scheduled consultations can be started")
        
        consultation.status = 'in_progress'
        consultation.actual_start_time = timezone.now()
        consultation.save()
        
        logger.info(f"Started consultation {consultation.id}")
        return True
    
    @staticmethod
    def complete_consultation(consultation: Consultation) -> bool:
        """
        Complete a consultation
        """
        completable_statuses = ['in_progress', 'ongoing', 'ready_for_consultation', 'patient_checked_in', 'scheduled']
        if consultation.status not in completable_statuses:
            raise ValidationError("Only active consultations can be completed")
        
        consultation.status = 'completed'
        consultation.actual_end_time = timezone.now()
        consultation.save()
        
        logger.info(f"Completed consultation {consultation.id}")
        return True
    
    @staticmethod
    def cancel_consultation(
        consultation: Consultation,
        cancelled_by: User,
        reason: str = ''
    ) -> bool:
        """
        Cancel a consultation
        """
        if consultation.status in ['completed', 'cancelled']:
            raise ValidationError("Cannot cancel completed or already cancelled consultations")
        
        consultation.status = 'cancelled'
        consultation.cancelled_by = cancelled_by
        consultation.cancellation_reason = reason
        consultation.cancelled_at = timezone.now()
        consultation.save()
        
        logger.info(f"Cancelled consultation {consultation.id} by {cancelled_by.name}")
        return True
    
    @staticmethod
    def reschedule_consultation(
        consultation: Consultation,
        new_date: datetime.date,
        new_time: datetime.time,
        rescheduled_by: User,
        reason: str = ''
    ) -> bool:
        """
        Reschedule a consultation
        """
        if consultation.status in ['completed', 'cancelled']:
            raise ValidationError("Cannot reschedule completed or cancelled consultations")
        
        # Check for conflicts with new time
        conflict = ConsultationService.check_scheduling_conflict(
            consultation.doctor, new_date, new_time, consultation.duration
        )
        if conflict:
            raise ValidationError(f"Cannot reschedule: {conflict}")
        
        # Store old schedule
        old_date = consultation.scheduled_date
        old_time = consultation.scheduled_time
        
        # Update consultation
        consultation.scheduled_date = new_date
        consultation.scheduled_time = new_time
        consultation.save()
        
        # Create reschedule record
        from .models import ConsultationReschedule
        ConsultationReschedule.objects.create(
            consultation=consultation,
            old_date=old_date,
            old_time=old_time,
            new_date=new_date,
            new_time=new_time,
            reason=reason,
            requested_by=rescheduled_by
        )
        
        logger.info(f"Rescheduled consultation {consultation.id} from {old_date} {old_time} to {new_date} {new_time}")
        return True
    
    @staticmethod
    def get_consultation_statistics(
        doctor: Optional[User] = None,
        date_from: Optional[datetime.date] = None,
        date_to: Optional[datetime.date] = None
    ) -> Dict:
        """
        Get consultation statistics
        """
        queryset = Consultation.objects.all()
        
        if doctor:
            queryset = queryset.filter(doctor=doctor)
        
        if date_from:
            queryset = queryset.filter(scheduled_date__gte=date_from)
        
        if date_to:
            queryset = queryset.filter(scheduled_date__lte=date_to)
        
        stats = {
            'total_consultations': queryset.count(),
            'scheduled': queryset.filter(status='scheduled').count(),
            'in_progress': queryset.filter(status='in_progress').count(),
            'completed': queryset.filter(status='completed').count(),
            'cancelled': queryset.filter(status='cancelled').count(),
            'total_revenue': queryset.filter(is_paid=True).aggregate(
                total=Sum('consultation_fee')
            )['total'] or 0,
            'pending_payments': queryset.filter(payment_status='pending').count(),
            'paid_consultations': queryset.filter(payment_status='paid').count(),
        }
        
        return stats
    
    @staticmethod
    def get_upcoming_consultations(doctor: User, days: int = 7) -> List[Consultation]:
        """
        Get upcoming consultations for a doctor
        """
        today = timezone.now().date()
        end_date = today + timedelta(days=days)
        
        return Consultation.objects.filter(
            doctor=doctor,
            scheduled_date__gte=today,
            scheduled_date__lte=end_date,
            status='scheduled'
        ).order_by('scheduled_date', 'scheduled_time')
    
    @staticmethod
    def get_today_consultations(doctor: User) -> List[Consultation]:
        """
        Get today's consultations for a doctor
        """
        today = timezone.now().date()
        
        return Consultation.objects.filter(
            doctor=doctor,
            scheduled_date=today
        ).order_by('scheduled_time')
    
    @staticmethod
    def add_consultation_note(
        consultation: Consultation,
        note_type: str,
        content: str,
        created_by: User
    ) -> ConsultationNote:
        """
        Add a note to a consultation
        """
        note = ConsultationNote.objects.create(
            consultation=consultation,
            note_type=note_type,
            content=content,
            created_by=created_by
        )
        
        logger.info(f"Added note to consultation {consultation.id}")
        return note
    
    @staticmethod
    def record_vital_signs(
        consultation: Consultation,
        vital_signs_data: Dict,
        recorded_by: User
    ) -> ConsultationVitalSigns:
        """
        Record vital signs for a consultation
        """
        vital_signs, created = ConsultationVitalSigns.objects.get_or_create(
            consultation=consultation,
            defaults={'recorded_by': recorded_by}
        )
        
        # Update vital signs data
        for field, value in vital_signs_data.items():
            if hasattr(vital_signs, field):
                setattr(vital_signs, field, value)
        
        vital_signs.save()
        
        logger.info(f"Recorded vital signs for consultation {consultation.id}")
        return vital_signs
    
    @staticmethod
    def add_diagnosis(
        consultation: Consultation,
        diagnosis: str,
        diagnosis_type: str = 'primary',
        icd_code: str = '',
        notes: str = '',
        confidence_level: str = 'medium'
    ) -> ConsultationDiagnosis:
        """
        Add a diagnosis to a consultation
        """
        diagnosis_obj = ConsultationDiagnosis.objects.create(
            consultation=consultation,
            diagnosis=diagnosis,
            diagnosis_type=diagnosis_type,
            icd_code=icd_code,
            notes=notes,
            confidence_level=confidence_level
        )
        
        logger.info(f"Added diagnosis to consultation {consultation.id}")
        return diagnosis_obj


class ConsultationAnalyticsService:
    """Service class for consultation analytics and reporting"""
    
    @staticmethod
    def get_doctor_performance_metrics(
        doctor: User,
        start_date: datetime.date,
        end_date: datetime.date
    ) -> Dict:
        """
        Get performance metrics for a doctor
        """
        consultations = Consultation.objects.filter(
            doctor=doctor,
            scheduled_date__range=[start_date, end_date]
        )
        
        total_consultations = consultations.count()
        completed_consultations = consultations.filter(status='completed').count()
        cancelled_consultations = consultations.filter(status='cancelled').count()
        
        completion_rate = (completed_consultations / total_consultations * 100) if total_consultations > 0 else 0
        cancellation_rate = (cancelled_consultations / total_consultations * 100) if total_consultations > 0 else 0
        
        total_revenue = consultations.filter(is_paid=True).aggregate(
            total=Sum('consultation_fee')
        )['total'] or 0
        
        avg_consultation_duration = consultations.filter(
            actual_start_time__isnull=False,
            actual_end_time__isnull=False
        ).aggregate(
            avg_duration=Avg('actual_duration')
        )['avg_duration'] or 0
        
        return {
            'total_consultations': total_consultations,
            'completed_consultations': completed_consultations,
            'cancelled_consultations': cancelled_consultations,
            'completion_rate': round(completion_rate, 2),
            'cancellation_rate': round(cancellation_rate, 2),
            'total_revenue': total_revenue,
            'avg_consultation_duration': avg_consultation_duration,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        }
    
    @staticmethod
    def get_consultation_trends(
        doctor: Optional[User] = None,
        days: int = 30
    ) -> List[Dict]:
        """
        Get consultation trends over time
        """
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        queryset = Consultation.objects.filter(
            scheduled_date__range=[start_date, end_date]
        )
        
        if doctor:
            queryset = queryset.filter(doctor=doctor)
        
        # Group by date and status
        trends = queryset.values('scheduled_date', 'status').annotate(
            count=Count('id')
        ).order_by('scheduled_date')
        
        return list(trends)
    
    @staticmethod
    def get_revenue_analytics(
        start_date: datetime.date,
        end_date: datetime.date,
        doctor: Optional[User] = None
    ) -> Dict:
        """
        Get revenue analytics
        """
        queryset = Consultation.objects.filter(
            scheduled_date__range=[start_date, end_date],
            is_paid=True
        )
        
        if doctor:
            queryset = queryset.filter(doctor=doctor)
        
        total_revenue = queryset.aggregate(
            total=Sum('consultation_fee')
        )['total'] or 0
        
        avg_consultation_fee = queryset.aggregate(
            avg=Avg('consultation_fee')
        )['avg'] or 0
        
        revenue_by_status = queryset.values('status').annotate(
            revenue=Sum('consultation_fee')
        )
        
        return {
            'total_revenue': total_revenue,
            'avg_consultation_fee': avg_consultation_fee,
            'revenue_by_status': list(revenue_by_status),
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        } 


class ConsultationAutoCompletionService:
    """Service for automatically completing overdue consultations"""
    
    @staticmethod
    def check_and_complete_overdue_consultations(hours_overdue=1, status_filter='both'):
        """
        Check for overdue consultations and mark them as completed
        
        Args:
            hours_overdue (int): Number of hours after scheduled time to consider overdue
            status_filter (str): Which status to check ('scheduled', 'in_progress', 'both')
        
        Returns:
            dict: Summary of the operation
        """
        try:
            # Calculate the cutoff time
            cutoff_time = timezone.now() - timedelta(hours=hours_overdue)
            
            # Build the query
            status_conditions = []
            if status_filter in ['scheduled', 'both']:
                status_conditions.append('scheduled')
            if status_filter in ['in_progress', 'both']:
                status_conditions.append('in_progress')
            
            if not status_conditions:
                return {
                    'success': False,
                    'error': 'No valid status conditions specified',
                    'updated_count': 0
                }
            
            # Find overdue consultations
            overdue_consultations = Consultation.objects.filter(
                status__in=status_conditions
            ).select_related('patient', 'doctor')
            
            # Filter by scheduled datetime
            overdue_list = []
            for consultation in overdue_consultations:
                # Create scheduled datetime
                scheduled_datetime = datetime.combine(
                    consultation.scheduled_date,
                    consultation.scheduled_time
                )
                
                # Convert to timezone-aware datetime if needed
                if timezone.is_naive(scheduled_datetime):
                    scheduled_datetime = timezone.make_aware(scheduled_datetime)
                
                # Check if consultation is overdue
                if scheduled_datetime < cutoff_time:
                    overdue_list.append({
                        'consultation': consultation,
                        'scheduled_datetime': scheduled_datetime,
                        'hours_overdue': (timezone.now() - scheduled_datetime).total_seconds() / 3600
                    })
            
            if not overdue_list:
                return {
                    'success': True,
                    'message': 'No overdue consultations found',
                    'updated_count': 0,
                    'overdue_consultations': []
                }
            
            # Update consultations
            updated_count = 0
            updated_consultations = []
            
            with transaction.atomic():
                for item in overdue_list:
                    consultation = item['consultation']
                    
                    try:
                        # Update consultation status
                        consultation.status = 'completed'
                        
                        # Set actual end time if not already set
                        if not consultation.actual_end_time:
                            consultation.actual_end_time = timezone.now()
                        
                        consultation.save()
                        updated_count += 1
                        
                        updated_consultations.append({
                            'id': consultation.id,
                            'patient_name': consultation.patient.name,
                            'doctor_name': consultation.doctor.name,
                            'scheduled_date': consultation.scheduled_date,
                            'scheduled_time': consultation.scheduled_time,
                            'hours_overdue': item['hours_overdue']
                        })
                        
                        # Log the action
                        logger.info(
                            f'Auto-completed consultation {consultation.id} '
                            f'(patient: {consultation.patient.name}, doctor: {consultation.doctor.name}) '
                            f'after {item["hours_overdue"]:.1f} hours overdue'
                        )
                        
                    except Exception as e:
                        logger.error(
                            f'Failed to auto-complete consultation {consultation.id}: {str(e)}'
                        )
            
            return {
                'success': True,
                'message': f'Successfully marked {updated_count} consultation(s) as completed',
                'updated_count': updated_count,
                'overdue_consultations': updated_consultations
            }
            
        except Exception as e:
            logger.error(f'Error in check_and_complete_overdue_consultations: {str(e)}')
            return {
                'success': False,
                'error': str(e),
                'updated_count': 0
            }
    
    @staticmethod
    def get_overdue_consultations(hours_overdue=0, status_filter='scheduled'):
        """
        Get list of overdue consultations - scheduled consultations that have passed their scheduled time
        
        Args:
            hours_overdue (int): Additional hours buffer after scheduled time (default 0)
            status_filter (str): Which status to check (default 'scheduled')
        
        Returns:
            list: List of overdue consultation details
        """
        try:
            from django.utils import timezone
            from django.db.models import Q
            
            # Get current time
            now = timezone.now()
            
            # Calculate the cutoff time (scheduled time + buffer)
            cutoff_time = now - timedelta(hours=hours_overdue)
            
            # Find scheduled consultations that have passed their scheduled time
            # Handle timezone properly - convert to local timezone for comparison
            import pytz
            local_tz = pytz.timezone('Asia/Kolkata')  # IST timezone
            local_now = now.astimezone(local_tz)
            
            overdue_consultations = Consultation.objects.filter(
                status='scheduled'  # Only scheduled consultations can be overdue
            ).filter(
                Q(scheduled_date__lt=local_now.date()) |  # Past dates
                Q(scheduled_date=local_now.date(), scheduled_time__lt=local_now.time())  # Today but past time
            ).select_related('patient', 'doctor')
            
            print(f'🔍 ConsultationService.get_overdue_consultations: Found {overdue_consultations.count()} overdue consultations')
            
            # Build the response list
            overdue_list = []
            for consultation in overdue_consultations:
                # Create scheduled datetime
                scheduled_datetime = datetime.combine(
                    consultation.scheduled_date,
                    consultation.scheduled_time
                )
                
                # Convert to timezone-aware datetime if needed
                if timezone.is_naive(scheduled_datetime):
                    scheduled_datetime = timezone.make_aware(scheduled_datetime)
                
                # Check if consultation is overdue
                if scheduled_datetime < cutoff_time:
                    overdue_list.append({
                        'id': consultation.id,
                        'patient_name': consultation.patient.name,
                        'doctor_name': consultation.doctor.name,
                        'scheduled_date': consultation.scheduled_date,
                        'scheduled_time': consultation.scheduled_time,
                        'status': consultation.status,
                        'hours_overdue': (timezone.now() - scheduled_datetime).total_seconds() / 3600
                    })
            
            return overdue_list
            
        except Exception as e:
            logger.error(f'Error in get_overdue_consultations: {str(e)}')
            return [] 