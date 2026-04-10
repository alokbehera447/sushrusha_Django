from rest_framework import status, permissions, filters
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import BasePermission
from django.utils import timezone
from django.db.models import Q, Count, Avg, Sum
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.openapi import OpenApiTypes
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from django_filters.rest_framework import DjangoFilterBackend

from authentication.models import User
from .models import (
    Consultation, ConsultationSymptom, ConsultationDiagnosis, 
    ConsultationVitalSigns, ConsultationAttachment, ConsultationNote,
    ConsultationReschedule, ConsultationReceipt
)
from .serializers import (
    ConsultationSerializer, ConsultationCreateSerializer, ConsultationUpdateSerializer,
    ConsultationListSerializer, ConsultationDetailSerializer, ConsultationSearchSerializer,
    ConsultationStatsSerializer, ConsultationCreateDynamicSerializer,
    ConsultationDiagnosisSerializer, ConsultationDiagnosisCreateSerializer,
    ConsultationVitalSignsSerializer, ConsultationVitalSignsCreateSerializer,
    ConsultationAttachmentSerializer, ConsultationAttachmentCreateSerializer,
    ConsultationNoteSerializer, ConsultationNoteCreateSerializer,
    ConsultationRescheduleSerializer, ConsultationRescheduleCreateSerializer,
    ConsultationReceiptSerializer, ConsultationReceiptCreateSerializer,
    ConsultationCheckInSerializer, ConsultationReadySerializer, ConsultationStartSerializer,
    ConsultationOverdueSerializer
)
from doctors.serializers import DoctorSlotSerializer
from .services import WhatsAppNotificationService, ConsultationService, ConsultationAnalyticsService, ConsultationAutoCompletionService


class ConsultationPagination(PageNumberPagination):
    """Custom pagination for consultation lists"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class IsAdminOrSuperAdmin(BasePermission):
    """Custom permission to allow only admin and superadmin"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['admin', 'superadmin']


class IsAdminWithClinicOrSuperAdmin(BasePermission):
    """Custom permission to allow admin with assigned clinic or superadmin"""
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.role == 'superadmin':
            return True
        
        if request.user.role == 'admin':
            # Check if admin has an assigned clinic
            try:
                return hasattr(request.user, 'administered_clinic') and request.user.administered_clinic is not None
            except:
                return False
        
        return False


class PatientConsultationView(APIView):
    """View for patient to get their consultations"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by consultation status'),
            OpenApiParameter('start_date', OpenApiTypes.DATE, description='Filter consultations from this date (YYYY-MM-DD)'),
            OpenApiParameter('end_date', OpenApiTypes.DATE, description='Filter consultations until this date (YYYY-MM-DD)'),
            OpenApiParameter('ordering', OpenApiTypes.STR, description='Order by field (e.g., -scheduled_date)'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Number of items per page'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="Get consultations for the logged-in patient"
    )
    def get(self, request):
        """Get consultations for the logged-in patient"""
        # Check if user is a patient
        if request.user.role != 'patient':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only patients can access this endpoint'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get consultations for the patient
        queryset = Consultation.objects.filter(patient=request.user).select_related('doctor', 'clinic')
        
        # Apply filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Apply date range filters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        print(f"🔍 Date filtering - Start: {start_date}, End: {end_date}")
        
        if start_date:
            try:
                from datetime import datetime
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                print(f"🔍 Start date object: {start_date_obj}")
                queryset = queryset.filter(scheduled_date__gte=start_date_obj)
                print(f"🔍 After start date filter, queryset count: {queryset.count()}")
            except ValueError:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'INVALID_DATE',
                        'message': 'Invalid start_date format. Use YYYY-MM-DD'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if end_date:
            try:
                from datetime import datetime
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                print(f"🔍 End date object: {end_date_obj}")
                queryset = queryset.filter(scheduled_date__lte=end_date_obj)
                print(f"🔍 After end date filter, queryset count: {queryset.count()}")
            except ValueError:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'INVALID_DATE',
                        'message': 'Invalid end_date format. Use YYYY-MM-DD'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Debug: Print all consultation dates in the queryset
        if start_date or end_date:
            print("🔍 All consultations in filtered queryset:")
            for consultation in queryset:
                print(f"  - {consultation.id}: {consultation.scheduled_date} (Dr. {consultation.doctor.name})")
        
        # Apply ordering
        ordering = request.query_params.get('ordering', '-scheduled_date')
        queryset = queryset.order_by(ordering)
        
        # Apply pagination
        paginator = ConsultationPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = ConsultationListSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = ConsultationListSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Patient consultations retrieved successfully',
            'timestamp': timezone.now().isoformat()
        })

    def post(self, request):
        """Auto-complete overdue consultations for the patient"""
        try:
            # Get parameters from request
            hours_overdue = request.data.get('hours_overdue', 1)
            status_filter = request.data.get('status_filter', 'both')
            
            # Call the auto-completion service
            result = ConsultationAutoCompletionService.check_and_complete_overdue_consultations(
                hours_overdue=hours_overdue,
                status_filter=status_filter
            )
            
            if result['success']:
                return Response({
                    'success': True,
                    'data': result,
                    'message': result['message'],
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'AUTO_COMPLETION_ERROR',
                        'message': result['error']
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'AUTO_COMPLETION_ERROR',
                    'message': str(e)
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationViewSet(ModelViewSet):
    """ViewSet for consultation management"""
    queryset = Consultation.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = ConsultationPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['patient__name', 'doctor__name', 'chief_complaint']
    ordering_fields = ['scheduled_date', 'scheduled_time', 'created_at', 'status']
    ordering = ['-scheduled_date', '-scheduled_time']
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return ConsultationUpdateSerializer
        elif self.action == 'list':
            return ConsultationListSerializer
        elif self.action == 'retrieve':
            return ConsultationDetailSerializer
        return ConsultationSerializer
    
    def get_queryset(self):
        """Filter queryset based on user role"""
        user = self.request.user
        queryset = Consultation.objects.select_related('patient', 'doctor', 'clinic')
        
        if user.role == 'patient':
            # Patients can only see their own consultations
            return queryset.filter(patient=user)
        elif user.role == 'doctor':
            # Doctors can see consultations they are assigned to
            return queryset.filter(doctor=user)
        elif user.role == 'admin':
            # Admins can see consultations for their assigned clinic
            try:
                # Get the clinic that this admin is assigned to
                assigned_clinic = user.administered_clinic
                if assigned_clinic:
                    return queryset.filter(clinic=assigned_clinic)
                else:
                    # If admin is not assigned to any clinic, they can see all consultations
                    # This is a fallback for admins without specific clinic assignments
                    return queryset
            except AttributeError:
                # If admin is not assigned to any clinic, they can see all consultations
                return queryset
            except Exception as e:
                # Log the error and return all consultations as fallback
                print(f"Error getting admin clinic: {e}")
                return queryset
        elif user.role == 'superadmin':
            # SuperAdmin can see all consultations
            return queryset
        
        return queryset.none()
    
    def destroy(self, request, pk=None):
        """Delete consultation"""
        try:
            consultation = self.get_object()
            
            # Check if consultation can be deleted
            # Only prevent deletion of consultations that are currently in progress
            if consultation.status in ['in_progress', 'ready_for_consultation']:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'CANNOT_DELETE',
                        'message': f'Cannot delete consultation that is currently in progress or ready for consultation. Status: {consultation.status}'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # For completed consultations, add a warning but allow deletion
            if consultation.status == 'completed':
                # Log the deletion for audit purposes
                print(f"Warning: Deleting completed consultation {consultation.id} by user {request.user.id}")
            
            consultation.delete()
            return Response({
                'success': True,
                'message': 'Consultation deleted successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_204_NO_CONTENT)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'DELETE_ERROR',
                    'message': str(e)
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        responses={200: ConsultationSerializer},
        description="Get consultation by ID"
    )
    def retrieve(self, request, pk=None):
        """Get consultation by ID"""
        consultation = self.get_object()
        serializer = self.get_serializer(consultation)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        parameters=[
            OpenApiParameter('upcoming', OpenApiTypes.BOOL, description='Filter upcoming consultations only'),
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by status'),
            OpenApiParameter('payment_status', OpenApiTypes.STR, description='Filter by payment status'),
            OpenApiParameter('clinic_id', OpenApiTypes.STR, description='Filter by clinic ID'),
            OpenApiParameter('doctor_id', OpenApiTypes.STR, description='Filter by doctor ID'),
            OpenApiParameter('start_date', OpenApiTypes.DATE, description='Filter consultations from this date (YYYY-MM-DD)'),
            OpenApiParameter('end_date', OpenApiTypes.DATE, description='Filter consultations until this date (YYYY-MM-DD)'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="List all consultations with pagination and filtering"
    )
    def list(self, request):
        """List consultations with pagination and filtering"""
        queryset = self.filter_queryset(self.get_queryset())
        
        # Filter by clinic_id (for superadmin and admin users)
        clinic_id = request.query_params.get('clinic_id')
        if clinic_id and request.user.role in ['superadmin', 'admin']:
            queryset = queryset.filter(clinic_id=clinic_id)
        
        # Filter by doctor_id (for superadmin and admin users)
        doctor_id = request.query_params.get('doctor_id')
        if doctor_id and request.user.role in ['superadmin', 'admin']:
            queryset = queryset.filter(doctor_id=doctor_id)
        
        # Filter by date range
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if start_date:
            try:
                from datetime import datetime
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(scheduled_date__gte=start_date_obj)
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        if end_date:
            try:
                from datetime import datetime
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(scheduled_date__lte=end_date_obj)
            except ValueError:
                pass  # Invalid date format, ignore filter
        
        # Filter upcoming consultations
        upcoming_only = request.query_params.get('upcoming', '').lower() == 'true'
        if upcoming_only:
            from datetime import datetime, timedelta
            now = timezone.now()
            # Get consultations scheduled for today and future dates
            queryset = queryset.filter(
                scheduled_date__gte=now.date()
            ).filter(
                # For today's consultations, check if time hasn't passed
                Q(scheduled_date__gt=now.date()) |
                Q(scheduled_date=now.date(), scheduled_time__gte=now.time())
            )
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter:
            if status_filter == 'overdue':
                # For overdue filter, find consultations that are past their scheduled time
                # regardless of their static status
                from datetime import datetime
                now = timezone.now()
                
                # Get scheduled consultations that have passed their scheduled time (overdue)
                # Need to handle timezone properly - convert to local timezone for comparison
                import pytz
                local_tz = pytz.timezone('Asia/Kolkata')  # IST timezone
                local_now = now.astimezone(local_tz)
                
                queryset = queryset.filter(
                    status='scheduled'  # Only scheduled consultations can be overdue
                ).filter(
                    Q(scheduled_date__lt=local_now.date()) |
                    Q(scheduled_date=local_now.date(), scheduled_time__lt=local_now.time())
                )
            else:
                queryset = queryset.filter(status=status_filter)
        
        # Filter by payment status
        payment_status_filter = request.query_params.get('payment_status')
        if payment_status_filter:
            queryset = queryset.filter(payment_status=payment_status_filter)
        
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Consultations retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultations retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        request=ConsultationCreateSerializer,
        responses={201: ConsultationSerializer},
        description="Create consultation"
    )
    def create(self, request):
        """Create consultation"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            consultation = serializer.save()
            response_serializer = ConsultationSerializer(consultation)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Consultation created successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid data provided',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        request=ConsultationCreateDynamicSerializer,
        responses={201: ConsultationSerializer},
        description="Create consultation with dynamic slots (no slot_id required)"
    )
    @action(detail=False, methods=['post'], url_path='create-dynamic')
    def create_dynamic(self, request):
        """Create consultation with dynamic slots (no slot_id required)"""
        from .serializers import ConsultationCreateDynamicSerializer
        
        print(f"🔍 create_dynamic called with data: {request.data}")
        print(f"🔍 Using ConsultationCreateDynamicSerializer")
        
        serializer = ConsultationCreateDynamicSerializer(data=request.data)
        print(f"🔍 Serializer created: {serializer}")
        
        if serializer.is_valid():
            print(f"🔍 Serializer is valid")
            consultation = serializer.save()
            response_serializer = ConsultationSerializer(consultation)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Consultation created successfully with dynamic slot',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
        else:
            print(f"🔍 Serializer errors: {serializer.errors}")
            return Response({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Invalid data provided',
                    'details': serializer.errors
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='doctor/my-consultations')
    def doctor_consultations(self, request):
        """Get consultations for the logged-in doctor"""
        if request.user.role != 'doctor':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only doctors can access this endpoint'
                }
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get consultations for the logged-in doctor
        consultations = Consultation.objects.filter(
            doctor=request.user
        ).select_related('patient', 'doctor', 'clinic').order_by(
            'scheduled_date', 'scheduled_time'
        )
        
        # Apply status filter if provided
        status_filter = request.query_params.get('status')
        if status_filter:
            consultations = consultations.filter(status=status_filter)
        
        # Apply date filter if provided
        date_filter = request.query_params.get('date')
        if date_filter:
            consultations = consultations.filter(scheduled_date=date_filter)
        
        serializer = ConsultationListSerializer(consultations, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'message': f'Found {len(serializer.data)} consultations for doctor',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def available_slots(self, request):
        """Get available slots for consultation booking"""
        doctor_id = request.query_params.get('doctor_id')
        clinic_id = request.query_params.get('clinic_id')
        date = request.query_params.get('date')
        
        if not doctor_id or not clinic_id or not date:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_PARAMETERS',
                    'message': 'doctor_id, clinic_id, and date are required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            from datetime import datetime
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
        except ValueError:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_DATE',
                    'message': 'Invalid date format. Use YYYY-MM-DD'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get available slots
        from doctors.models import DoctorSlot
        slots = DoctorSlot.objects.filter(
            doctor_id=doctor_id,
            clinic_id=clinic_id,
            date=date_obj,
            is_available=True,
            is_booked=False
        ).order_by('start_time')
        
        serializer = DoctorSlotSerializer(slots, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': f'Available slots for {date}',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='clinic-stats')
    def clinic_statistics(self, request):
        """Get consultation statistics for a specific clinic"""
        # Check permissions
        if request.user.role not in ['admin', 'superadmin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only admin and superadmin can access this endpoint'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get clinic_id from query params or use admin's assigned clinic
        clinic_id = request.query_params.get('clinic_id')
        
        if request.user.role == 'admin':
            # For admin users, use their assigned clinic if no clinic_id provided
            if not clinic_id:
                try:
                    clinic_id = request.user.administered_clinic.id if request.user.administered_clinic else None
                except AttributeError:
                    return Response({
                        'success': False,
                        'error': {
                            'code': 'NO_CLINIC_ASSIGNED',
                            'message': 'Admin is not assigned to any clinic'
                        },
                        'timestamp': timezone.now().isoformat()
                    }, status=status.HTTP_400_BAD_REQUEST)
        
        if not clinic_id:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_CLINIC_ID',
                    'message': 'clinic_id is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get consultations for the specific clinic
            consultations = Consultation.objects.filter(clinic_id=clinic_id)
            
            # Calculate statistics
            total_consultations = consultations.count()
            scheduled_consultations = consultations.filter(status='scheduled').count()
            checked_in_consultations = consultations.filter(status='patient_checked_in').count()
            ready_consultations = consultations.filter(status='ready_for_consultation').count()
            in_progress_consultations = consultations.filter(status='in_progress').count()
            completed_consultations = consultations.filter(status='completed').count()
            
            # Get clinic name
            from eclinic.models import Clinic
            try:
                clinic = Clinic.objects.get(id=clinic_id)
                clinic_name = clinic.name
            except Clinic.DoesNotExist:
                clinic_name = f"Clinic {clinic_id}"
            
            stats = {
                'clinic_id': clinic_id,
                'clinic_name': clinic_name,
                'total': total_consultations,
                'scheduled': scheduled_consultations,
                'checked_in': checked_in_consultations,
                'ready': ready_consultations,
                'in_progress': in_progress_consultations,
                'completed': completed_consultations,
                'timestamp': timezone.now().isoformat()
            }
            
            return Response({
                'success': True,
                'data': stats,
                'message': f'Statistics for {clinic_name}',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CALCULATION_ERROR',
                    'message': f'Error calculating statistics: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @extend_schema(
        parameters=[
            OpenApiParameter('clinic_id', OpenApiTypes.STR, description='Clinic ID to filter consultations', required=True),
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by consultation status'),
            OpenApiParameter('payment_status', OpenApiTypes.STR, description='Filter by payment status'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Number of items per page'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="Get consultations for a specific clinic"
    )
    @action(detail=False, methods=['get'], url_path='clinic/(?P<clinic_id>[^/.]+)')
    def clinic_consultations(self, request, clinic_id=None):
        """Get consultations for a specific clinic"""
        if not clinic_id:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_CLINIC_ID',
                    'message': 'clinic_id parameter is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user has permission to access this clinic
        user = request.user
        if user.role == 'admin':
            # Admin can only access their assigned clinic
            try:
                if not hasattr(user, 'administered_clinic') or user.administered_clinic.id != clinic_id:
                    return Response({
                        'success': False,
                        'error': {
                            'code': 'PERMISSION_DENIED',
                            'message': 'You can only access consultations for your assigned clinic'
                        },
                        'timestamp': timezone.now().isoformat()
                    }, status=status.HTTP_403_FORBIDDEN)
            except:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'PERMISSION_DENIED',
                        'message': 'You can only access consultations for your assigned clinic'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_403_FORBIDDEN)
        
        # Get consultations for the specific clinic
        queryset = Consultation.objects.filter(clinic_id=clinic_id).select_related('patient', 'doctor', 'clinic')
        
        # Apply additional filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        payment_status_filter = request.query_params.get('payment_status')
        if payment_status_filter:
            queryset = queryset.filter(payment_status=payment_status_filter)
        
        # Apply pagination
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': f'Consultations for clinic {clinic_id} retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': f'Consultations for clinic {clinic_id} retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], permission_classes=[permissions.AllowAny])
    def calculate_available_slots(self, request):
        """Calculate available slots dynamically based on doctor availability and clinic duration"""
        doctor_id = request.query_params.get('doctor_id')
        clinic_id = request.query_params.get('clinic_id')  # Made optional
        date = request.query_params.get('date')
        
        if not doctor_id or not date:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_PARAMETERS',
                    'message': 'doctor_id and date are required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            from datetime import datetime, timedelta
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
        except ValueError:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_DATE',
                    'message': 'Invalid date format. Use YYYY-MM-DD'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Get doctor and clinic
            from doctors.models import DoctorSlot, DoctorProfile
            from eclinic.models import Clinic
            from authentication.models import User
            
            doctor = User.objects.get(id=doctor_id, role='doctor')
            
            # Handle clinic_id - if not provided, use a default clinic or get from doctor's profile
            if clinic_id:
                try:
                    clinic = Clinic.objects.get(id=clinic_id)
                except Clinic.DoesNotExist:
                    clinic = None
            else:
                clinic = None
            
            # Get doctor's consultation duration (default to 5 minutes if not set)
            try:
                doctor_profile = DoctorProfile.objects.get(user=doctor)
                consultation_duration = doctor_profile.consultation_duration or 5  # in minutes
            except DoctorProfile.DoesNotExist:
                consultation_duration = 5  # Default to 5 minutes if no profile exists
            
            # OPTIMIZATION: Pre-fetch all existing consultations for this doctor and date
            # Use select_related to avoid N+1 queries and only fetch needed fields
            # Include completed consultations as they also block time slots
            existing_consultations = Consultation.objects.filter(
                doctor=doctor,
                scheduled_date=date_obj,
                status__in=['scheduled', 'in_progress', 'confirmed', 'completed']
            ).only('scheduled_time', 'duration')
            
            # OPTIMIZATION: Pre-fetch all booked slots for this doctor and date
            booked_slots = DoctorSlot.objects.filter(
                doctor=doctor,
                date=date_obj,
                is_booked=True
            ).only('start_time', 'end_time')
            
            # OPTIMIZATION: Create a set of blocked time ranges for fast lookup
            blocked_ranges = set()
            
            # Add consultation time ranges to blocked ranges
            for consultation in existing_consultations:
                start_time = consultation.scheduled_time
                end_time = (datetime.combine(date_obj, start_time) + 
                           timedelta(minutes=consultation.duration)).time()
                blocked_ranges.add((start_time, end_time))
            
            # Add booked slot time ranges to blocked ranges
            for slot in booked_slots:
                blocked_ranges.add((slot.start_time, slot.end_time))
            
            # Get doctor's availability for the date
            available_slots_query = DoctorSlot.objects.filter(
                doctor=doctor,
                date=date_obj,
                is_available=True,
                is_booked=False
            ).order_by('start_time')
            
            calculated_slots = []
            
            # If no specific slots are found, we provide a default daily shift (9 AM to 6 PM)
            # This ensures dynamic booking still works even if doctor hasn't set slots.
            if not available_slots_query.exists():
                from datetime import time
                print(f"DEBUG: No specific slots for {doctor.name}, using default shift")
                # Create a list with one large "availability window" object for calculation
                class DummySlot:
                    def __init__(self, start, end):
                        self.start_time = start
                        self.end_time = end
                available_slots = [DummySlot(time(9, 0), time(12, 30)), DummySlot(time(14, 0), time(18, 0))]
            else:
                available_slots = list(available_slots_query)
            
            print(f"DEBUG: Doctor {doctor.name} has {len(available_slots)} slot windows")
            print(f"DEBUG: Found {len(existing_consultations)} existing consultations")
            
            for slot in available_slots:
                slot_start = datetime.combine(date_obj, slot.start_time)
                slot_end = datetime.combine(date_obj, slot.end_time)
                current_time = slot_start
                
                while current_time < slot_end:
                    slot_end_time = current_time + timedelta(minutes=30) # Using 30 min increments for frontend alignment
                    if slot_end_time > slot_end: break
                    
                    slot_start_time = current_time.time()
                    slot_end_time_obj = slot_end_time.time()
                    
                    is_blocked = False
                    for blocked_start, blocked_end in blocked_ranges:
                        # Check for ANY overlap
                        if (slot_start_time < blocked_end and slot_end_time_obj > blocked_start):
                            is_blocked = True
                            break
                    
                    if not is_blocked:
                        calculated_slots.append({
                            'start_time': slot_start_time.strftime('%H:%M'),
                            'end_time': slot_end_time_obj.strftime('%H:%M'),
                            'duration_minutes': 30,
                            'clinic_name': clinic.name if clinic else 'Sushrusha eClinic',
                            'doctor_name': doctor.name,
                            'is_available': True
                        })
                    
                    current_time = slot_end_time
            
            print(f"DEBUG: Final result - {len(calculated_slots)} slots calculated")
            
            return Response({
                'success': True,
                'data': {
                    'slots': calculated_slots,
                    'clinic_duration': consultation_duration,  # This is now doctor's consultation duration
                    'doctor_consultation_duration': consultation_duration,  # Add explicit field for clarity
                    'date': date,
                    'doctor_name': doctor.name,
                    'clinic_name': clinic.name if clinic else 'Default Clinic'
                },
                'message': f'Calculated {len(calculated_slots)} available slots for {date}',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'DOCTOR_NOT_FOUND',
                    'message': 'Doctor not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CALCULATION_ERROR',
                    'message': f'Error calculating slots: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start consultation"""
        consultation = self.get_object()
        
        if consultation.status != 'scheduled':
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Consultation can only be started if it is scheduled'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        consultation.status = 'in_progress'
        consultation.actual_start_time = timezone.now()
        consultation.save()
        
        serializer = ConsultationSerializer(consultation)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation started successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete consultation"""
        consultation = self.get_object()
        
        if consultation.status != 'in_progress':
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Consultation can only be completed if it is in progress'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        consultation.status = 'completed'
        consultation.actual_end_time = timezone.now()
        consultation.save()
        
        serializer = ConsultationSerializer(consultation)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation completed successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel consultation"""
        consultation = self.get_object()
        
        if consultation.status in ['completed', 'cancelled']:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Cannot cancel a completed or already cancelled consultation'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        consultation.status = 'cancelled'
        consultation.save()
        
        serializer = ConsultationSerializer(consultation)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation cancelled successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def generate_receipt(self, request, pk=None):
        """Generate receipt for consultation"""
        consultation = self.get_object()
        
        try:
            # Check if receipt already exists
            existing_receipt = ConsultationReceipt.objects.filter(consultation=consultation).first()
            if existing_receipt:
                serializer = ConsultationReceiptSerializer(existing_receipt)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'Receipt already exists',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            
            # Create new receipt
            receipt_data = {
                'consultation': consultation,
                'amount': consultation.consultation_fee,
                'payment_method': consultation.payment_method,
                'payment_status': consultation.payment_status,
                'issued_by': request.user
            }
            
            receipt_serializer = ConsultationReceiptCreateSerializer(data=receipt_data)
            if receipt_serializer.is_valid():
                receipt = receipt_serializer.save()
                response_serializer = ConsultationReceiptSerializer(receipt)
                return Response({
                    'success': True,
                    'data': response_serializer.data,
                    'message': 'Receipt generated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Invalid receipt data',
                        'details': receipt_serializer.errors
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'RECEIPT_GENERATION_ERROR',
                    'message': f'Error generating receipt: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SuperAdminConsultationManagementView(APIView):
    """Dedicated API endpoint for SuperAdmin consultation management with advanced filtering"""
    permission_classes = [IsAdminOrSuperAdmin]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Number of items per page'),
            OpenApiParameter('search', OpenApiTypes.STR, description='Search term for patient, doctor, clinic, or consultation ID'),
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by consultation status'),
            OpenApiParameter('payment_status', OpenApiTypes.STR, description='Filter by payment status'),
            OpenApiParameter('clinic_id', OpenApiTypes.STR, description='Filter by clinic ID'),
            OpenApiParameter('doctor_id', OpenApiTypes.STR, description='Filter by doctor ID'),
            OpenApiParameter('start_date', OpenApiTypes.DATE, description='Filter consultations from this date (YYYY-MM-DD)'),
            OpenApiParameter('end_date', OpenApiTypes.DATE, description='Filter consultations until this date (YYYY-MM-DD)'),
            OpenApiParameter('ordering', OpenApiTypes.STR, description='Order by field (e.g., -scheduled_date, status)'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="Get all consultations with advanced filtering for SuperAdmin"
    )
    def get(self, request):
        """Get consultations with advanced filtering for SuperAdmin"""
        try:
            # Get query parameters
            page = int(request.query_params.get('page', 1))
            page_size = min(int(request.query_params.get('page_size', 50)), 100)  # Max 100 per page
            search = request.query_params.get('search', '').strip()
            status_filter = request.query_params.get('status', '').strip()
            payment_status_filter = request.query_params.get('payment_status', '').strip()
            clinic_id = request.query_params.get('clinic_id', '').strip()
            doctor_id = request.query_params.get('doctor_id', '').strip()
            start_date = request.query_params.get('start_date', '').strip()
            end_date = request.query_params.get('end_date', '').strip()
            ordering = request.query_params.get('ordering', '-scheduled_date,-scheduled_time')
            
            # Start with base queryset
            queryset = Consultation.objects.select_related(
                'patient', 'doctor', 'clinic'
            ).prefetch_related(
                'diagnoses',
                'vital_signs',
                'attachments',
                'notes',
                'recorded_symptoms'
            )
            
            # Apply search filter
            if search:
                search_query = Q(
                    Q(patient__name__icontains=search) |
                    Q(patient__phone__icontains=search) |
                    Q(doctor__name__icontains=search) |
                    Q(clinic__name__icontains=search) |
                    Q(chief_complaint__icontains=search) |
                    Q(id__icontains=search)
                )
                queryset = queryset.filter(search_query)
            
            # Apply status filter
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            # Apply payment status filter
            if payment_status_filter:
                queryset = queryset.filter(payment_status=payment_status_filter)
            
            # Apply clinic filter
            if clinic_id:
                queryset = queryset.filter(clinic_id=clinic_id)
            
            # Apply doctor filter
            if doctor_id:
                queryset = queryset.filter(doctor_id=doctor_id)
            
            # Apply date range filters
            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                    queryset = queryset.filter(scheduled_date__gte=start_date_obj)
                except ValueError:
                    return Response({
                        'success': False,
                        'error': {
                            'code': 'INVALID_DATE_FORMAT',
                            'message': 'Invalid start_date format. Use YYYY-MM-DD'
                        },
                        'timestamp': timezone.now().isoformat()
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                    queryset = queryset.filter(scheduled_date__lte=end_date_obj)
                except ValueError:
                    return Response({
                        'success': False,
                        'error': {
                            'code': 'INVALID_DATE_FORMAT',
                            'message': 'Invalid end_date format. Use YYYY-MM-DD'
                        },
                        'timestamp': timezone.now().isoformat()
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Apply ordering - split comma-separated ordering fields
            if ordering:
                ordering_fields = [field.strip() for field in ordering.split(',')]
                # Validate ordering fields
                valid_fields = ['scheduled_date', 'scheduled_time', 'created_at', 'updated_at', 'status', 'payment_status', 'consultation_fee']
                for field in ordering_fields:
                    # Remove the '-' prefix for validation
                    clean_field = field.lstrip('-')
                    if clean_field not in valid_fields:
                        return Response({
                            'success': False,
                            'error': {
                                'code': 'INVALID_ORDERING_FIELD',
                                'message': f'Invalid ordering field: {clean_field}. Valid fields are: {", ".join(valid_fields)}'
                            },
                            'timestamp': timezone.now().isoformat()
                        }, status=status.HTTP_400_BAD_REQUEST)
                
                queryset = queryset.order_by(*ordering_fields)
            else:
                queryset = queryset.order_by('-scheduled_date', '-scheduled_time')
            
            # Calculate pagination
            total_count = queryset.count()
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            
            # Get paginated results
            consultations = queryset[start_index:end_index]
            
            # Serialize the data
            serializer = ConsultationListSerializer(consultations, many=True)
            
            # Calculate pagination info
            total_pages = (total_count + page_size - 1) // page_size
            has_next = page < total_pages
            has_previous = page > 1
            
            return Response({
                'success': True,
                'results': serializer.data,
                'count': total_count,
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_previous': has_previous,
                'next': f"?page={page + 1}&page_size={page_size}" if has_next else None,
                'previous': f"?page={page - 1}&page_size={page_size}" if has_previous else None,
                'message': 'Consultations retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'FETCH_ERROR',
                    'message': f'Error fetching consultations: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationDiagnosisViewSet(ModelViewSet):
    """ViewSet for consultation diagnosis"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get diagnosis for specific consultation"""
        consultation_id = self.kwargs.get('consultation_id')
        return ConsultationDiagnosis.objects.filter(consultation_id=consultation_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationDiagnosisCreateSerializer
        return ConsultationDiagnosisSerializer


class ConsultationVitalSignsViewSet(ModelViewSet):
    """ViewSet for vital signs"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get vital signs for specific consultation"""
        consultation_id = self.kwargs.get('consultation_id')
        return ConsultationVitalSigns.objects.filter(consultation_id=consultation_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationVitalSignsCreateSerializer
        return ConsultationVitalSignsSerializer


class ConsultationAttachmentViewSet(ModelViewSet):
    """ViewSet for consultation documents"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get documents for specific consultation"""
        consultation_id = self.kwargs.get('consultation_id')
        return ConsultationAttachment.objects.filter(consultation_id=consultation_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationAttachmentCreateSerializer
        return ConsultationAttachmentSerializer


class ConsultationNoteViewSet(ModelViewSet):
    """ViewSet for consultation notes"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get notes for specific consultation"""
        consultation_id = self.kwargs.get('consultation_id')
        queryset = ConsultationNote.objects.filter(consultation_id=consultation_id)
        
        # Filter private notes based on user role
        user = self.request.user
        if user.role == 'patient':
            # Patients can see non-private notes
            return queryset.filter(is_private=False)
        
        return queryset
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationNoteCreateSerializer
        return ConsultationNoteSerializer


class ConsultationSymptomViewSet(ModelViewSet):
    """ViewSet for consultation symptoms"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get symptoms for specific consultation"""
        consultation_id = self.kwargs.get('consultation_id')
        return ConsultationSymptom.objects.filter(consultation_id=consultation_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ConsultationSymptomCreateSerializer
        return ConsultationSymptomSerializer


class ConsultationSearchView(APIView):
    """Search consultations with advanced filters"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('query', OpenApiTypes.STR, description='Search query'),
            OpenApiParameter('patient_id', OpenApiTypes.INT, description='Patient ID filter'),
            OpenApiParameter('doctor_id', OpenApiTypes.INT, description='Doctor ID filter'),
            OpenApiParameter('consultation_type', OpenApiTypes.STR, description='Consultation type'),
            OpenApiParameter('status', OpenApiTypes.STR, description='Status filter'),
            OpenApiParameter('payment_status', OpenApiTypes.STR, description='Payment status'),
            OpenApiParameter('date_from', OpenApiTypes.DATE, description='Start date filter'),
            OpenApiParameter('date_to', OpenApiTypes.DATE, description='End date filter'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="Search consultations with advanced filters"
    )
    def get(self, request):
        """Search consultations with advanced filters"""
        serializer = ConsultationSearchSerializer(data=request.query_params)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Invalid search parameters',
                    'details': serializer.errors
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Build query
        queryset = Consultation.objects.select_related('patient', 'doctor')
        
        # Apply role-based filtering
        user = request.user
        if user.role == 'patient':
            queryset = queryset.filter(patient=user)
        elif user.role == 'doctor':
            queryset = queryset.filter(doctor=user)
        elif user.role == 'admin':
            # Admins can only see consultations for their assigned clinic
            try:
                # Get the clinic that this admin is assigned to
                assigned_clinic = user.administered_clinic
                queryset = queryset.filter(clinic=assigned_clinic)
            except:
                # If admin is not assigned to any clinic, return empty queryset
                queryset = queryset.none()
        elif user.role == 'superadmin':
            # SuperAdmin can see all consultations
            pass
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Insufficient permissions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Apply search filters
        search_data = serializer.validated_data
        
        if search_data.get('query'):
            query = search_data['query']
            queryset = queryset.filter(
                Q(patient__name__icontains=query) |
                Q(doctor__name__icontains=query) |
                Q(chief_complaint__icontains=query)
            )
        
        if search_data.get('patient_id'):
            queryset = queryset.filter(patient_id=search_data['patient_id'])
        
        if search_data.get('doctor_id'):
            queryset = queryset.filter(doctor_id=search_data['doctor_id'])
        
        if search_data.get('consultation_type'):
            queryset = queryset.filter(consultation_type=search_data['consultation_type'])
        
        if search_data.get('status'):
            queryset = queryset.filter(status=search_data['status'])
        
        if search_data.get('payment_status'):
            queryset = queryset.filter(payment_status=search_data['payment_status'])
        
        if search_data.get('date_from'):
            queryset = queryset.filter(scheduled_at__date__gte=search_data['date_from'])
        
        if search_data.get('date_to'):
            queryset = queryset.filter(scheduled_at__date__lte=search_data['date_to'])
        
        # Paginate results
        paginator = ConsultationPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = ConsultationListSerializer(page, many=True)
            return paginator.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Search results retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = ConsultationListSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Search results retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class OverdueConsultationsView(APIView):
    """Get overdue consultations with proper e-clinic filtering"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get overdue consultations based on user role and e-clinic assignment"""
        try:
            user = request.user
            now = timezone.now()
            
            # Base query for overdue consultations (scheduled consultations that have passed their time)
            # Handle timezone properly - convert to local timezone for comparison
            import pytz
            local_tz = pytz.timezone('Asia/Kolkata')  # IST timezone
            local_now = now.astimezone(local_tz)
            
            overdue_queryset = Consultation.objects.filter(
                status='scheduled'  # Only scheduled consultations can be overdue
            ).filter(
                Q(scheduled_date__lt=local_now.date()) |
                Q(scheduled_date=local_now.date(), scheduled_time__lt=local_now.time())
            ).select_related('patient', 'doctor', 'clinic')
            
            print(f'🔍 Checking for overdue consultations at {now} (date: {now.date()}, time: {now.time()})')
            print(f'🔍 Base overdue query found: {overdue_queryset.count()} consultations')
            
            # Apply role-based filtering
            if user.role == 'doctor':
                # Doctors see only their own overdue consultations
                overdue_queryset = overdue_queryset.filter(doctor=user)
            elif user.role == 'admin':
                # Admins see consultations from their assigned e-clinic + consultations with no clinic
                try:
                    # Use the same logic as the main consultation filtering
                    assigned_clinic = getattr(user, 'administered_clinic', None)
                    if assigned_clinic:
                        # Admin assigned to a clinic - see clinic consultations + unassigned consultations
                        overdue_queryset = overdue_queryset.filter(
                            Q(clinic=assigned_clinic) | Q(clinic__isnull=True)
                        )
                        print(f'🔍 Admin {user.id} assigned to clinic {assigned_clinic.name}')
                    else:
                        # Admin with no clinic assignment sees all consultations (fallback)
                        print(f'🔍 Admin {user.id} has no clinic assignment - showing all overdue')
                        pass  # No additional filtering
                except AttributeError as e:
                    print(f'🔍 Admin {user.id} clinic access error: {e} - showing all overdue')
                    # Fallback: show all overdue consultations
                    pass
            elif user.role == 'superadmin':
                # Superadmins see all overdue consultations
                pass  # No additional filtering needed
            else:
                # Other roles see no overdue consultations
                overdue_queryset = overdue_queryset.none()
            
            # Serialize the results
            serializer = ConsultationListSerializer(overdue_queryset, many=True)
            
            return Response({
                'success': True,
                'data': serializer.data,
                'count': overdue_queryset.count(),
                'message': f'Found {overdue_queryset.count()} overdue consultations',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f'Error in OverdueConsultationsView: {e}')
            return Response({
                'success': False,
                'error': {
                    'code': 'OVERDUE_FETCH_ERROR',
                    'message': 'Failed to fetch overdue consultations',
                    'details': str(e)
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationStatsView(APIView):
    """Get consultation statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: ConsultationStatsSerializer},
        description="Get consultation statistics and analytics"
    )
    def get(self, request):
        """Get consultation statistics"""
        user = request.user
        
        # Apply role-based filtering
        if user.role == 'doctor':
            # Doctors can see their own consultations
            base_queryset = Consultation.objects.filter(doctor=user)
        elif user.role == 'admin':
            try:
                # Get the clinic that this admin is assigned to
                assigned_clinic = user.administered_clinic
                base_queryset = Consultation.objects.filter(clinic=assigned_clinic)
            except:
                # If admin is not assigned to any clinic, return empty stats
                base_queryset = Consultation.objects.none()
        elif user.role == 'superadmin':
            # SuperAdmin can see all consultations
            base_queryset = Consultation.objects.all()
        else:
            # Other roles get no access
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Insufficient permissions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Calculate statistics
        total_consultations = base_queryset.count()
        completed_consultations = base_queryset.filter(status='completed').count()
        cancelled_consultations = base_queryset.filter(status='cancelled').count()
        pending_consultations = base_queryset.filter(status='scheduled').count()
        
        # Consultation type distribution
        consultation_type_distribution = dict(
            base_queryset.values('consultation_type').annotate(
                count=Count('consultation_type')
            ).values_list('consultation_type', 'count')
        )
        
        # Average duration and rating
        completed_consultations_qs = base_queryset.filter(
            status='completed', actual_start_time__isnull=False, actual_end_time__isnull=False
        )
        
        avg_duration = 0
        if completed_consultations_qs.exists():
            total_duration = sum([
                (c.actual_end_time - c.actual_start_time).total_seconds() / 60
                for c in completed_consultations_qs
            ])
            avg_duration = total_duration / completed_consultations_qs.count()
        
        # Rating field doesn't exist in the model, so we'll set it to 0
        avg_rating = 0
        
        # Revenue stats
        total_revenue = base_queryset.filter(
            payment_status='paid'
        ).aggregate(total=Sum('consultation_fee'))['total'] or 0
        
        revenue_stats = {
            'total_revenue': total_revenue,
            'average_consultation_fee': base_queryset.aggregate(
                avg_fee=Avg('consultation_fee')
            )['avg_fee'] or 0,
            'pending_payments': base_queryset.filter(
                payment_status='pending'
            ).aggregate(total=Sum('consultation_fee'))['total'] or 0
        }
        
        # Monthly trends (last 12 months)
        monthly_trends = []
        for i in range(12):
            month_start = timezone.now().replace(day=1) - timedelta(days=30*i)
            month_end = month_start + timedelta(days=30)
            
            month_consultations = base_queryset.filter(
                created_at__gte=month_start,
                created_at__lt=month_end
            ).count()
            
            monthly_trends.append({
                'month': month_start.strftime('%Y-%m'),
                'consultations': month_consultations
            })
        
        stats_data = {
            'total_consultations': total_consultations,
            'scheduled_consultations': pending_consultations,  # Use pending as scheduled
            'completed_consultations': completed_consultations,
            'cancelled_consultations': cancelled_consultations,
            'total_revenue': total_revenue,
            'consultation_trends': monthly_trends,
            'doctor_consultation_stats': {
                'average_duration': avg_duration,
                'average_rating': avg_rating,
                'consultation_type_distribution': consultation_type_distribution,
                'revenue_stats': revenue_stats
            }
        }
        
        serializer = ConsultationStatsSerializer(stats_data)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation statistics retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class ConsultationPrescriptionView(APIView):
    """Get prescription for a specific consultation"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: 'PrescriptionSerializer'},
        description="Get prescription associated with a consultation"
    )
    def get(self, request, consultation_id):
        """Get prescription for consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check permissions
            user = request.user
            if user.role == 'patient' and consultation.patient != user:
                return Response({
                    'success': False,
                    'error': 'You can only view your own consultation prescriptions'
                }, status=status.HTTP_403_FORBIDDEN)
            
            if user.role == 'doctor' and consultation.doctor != user:
                return Response({
                    'success': False,
                    'error': 'You can only view prescriptions for your consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get prescription
            from prescriptions.models import Prescription
            try:
                prescription = Prescription.objects.get(consultation=consultation)
                from prescriptions.serializers import PrescriptionSerializer
                serializer = PrescriptionSerializer(prescription)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'Prescription retrieved successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            except Prescription.DoesNotExist:
                return Response({
                    'success': False,
                    'error': 'No prescription found for this consultation'
                }, status=status.HTTP_404_NOT_FOUND)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)


class ConsultationReceiptView(APIView):
    """Handle consultation receipt generation and retrieval"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={201: ConsultationReceiptSerializer},
        description="Generate receipt for consultation payment"
    )
    def post(self, request, consultation_id):
        """Generate receipt for consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check permissions
            user = request.user
            if user.role == 'admin':
                # Admin can generate receipts for any consultation in their clinic
                if not hasattr(user, 'administered_clinic') or consultation.clinic != user.administered_clinic:
                    return Response({
                        'success': False,
                        'error': 'You can only generate receipts for consultations in your clinic'
                    }, status=status.HTTP_403_FORBIDDEN)
            elif user.role == 'doctor' and consultation.doctor != user:
                return Response({
                    'success': False,
                    'error': 'You can only generate receipts for your consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            elif user.role == 'patient' and consultation.patient != user:
                return Response({
                    'success': False,
                    'error': 'You can only generate receipts for your consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Check if receipt already exists
            from .models import ConsultationReceipt
            existing_receipt = ConsultationReceipt.objects.filter(consultation=consultation).first()
            if existing_receipt:
                response_serializer = ConsultationReceiptSerializer(existing_receipt)
                return Response({
                    'success': True,
                    'data': response_serializer.data,
                    'message': 'Receipt already exists',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            
            # Create receipt data
            receipt_data = {
                'consultation': consultation,
                'amount': consultation.consultation_fee,
                'payment_method': consultation.payment_method or 'cash',
                'payment_status': consultation.payment_status,
                'issued_by': user
            }
            
            serializer = ConsultationReceiptCreateSerializer(data=receipt_data)
            if serializer.is_valid():
                receipt = serializer.save()
                response_serializer = ConsultationReceiptSerializer(receipt)
                return Response({
                    'success': True,
                    'data': response_serializer.data,
                    'message': 'Receipt generated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'error': 'Invalid receipt data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        responses={200: ConsultationReceiptSerializer},
        description="Get receipt for consultation"
    )
    def get(self, request, consultation_id):
        """Get receipt for consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check permissions
            user = request.user
            if user.role == 'admin':
                if not hasattr(user, 'administered_clinic') or consultation.clinic != user.administered_clinic:
                    return Response({
                        'success': False,
                        'error': 'You can only view receipts for consultations in your clinic'
                    }, status=status.HTTP_403_FORBIDDEN)
            elif user.role == 'doctor' and consultation.doctor != user:
                return Response({
                    'success': False,
                    'error': 'You can only view receipts for your consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            elif user.role == 'patient' and consultation.patient != user:
                return Response({
                    'success': False,
                    'error': 'You can only view receipts for your consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get receipt
            from .models import ConsultationReceipt
            try:
                receipt = ConsultationReceipt.objects.get(consultation=consultation)
                serializer = ConsultationReceiptSerializer(receipt)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'Receipt retrieved successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            except ConsultationReceipt.DoesNotExist:
                return Response({
                    'success': False,
                    'error': 'No receipt found for this consultation'
                }, status=status.HTTP_404_NOT_FOUND)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([])  # No authentication required for testing
def test_generate_receipt(request, consultation_id):
    """Test endpoint to generate receipt without authentication (development only)"""
    try:
        consultation = Consultation.objects.get(id=consultation_id)
        
        # Check if receipt already exists
        existing_receipt = ConsultationReceipt.objects.filter(consultation=consultation).first()
        if existing_receipt:
            serializer = ConsultationReceiptSerializer(existing_receipt)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Receipt already exists',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        # Create new receipt - try to get a superadmin user for issued_by
        try:
            issued_by_user = User.objects.filter(role='superadmin').first()
        except:
            issued_by_user = None
            
        receipt_data = {
            'consultation': consultation.id,
            'amount': consultation.consultation_fee,
            'payment_method': consultation.payment_method,
            'payment_status': consultation.payment_status,
            'issued_by': issued_by_user.id if issued_by_user else None
        }
        
        receipt_serializer = ConsultationReceiptCreateSerializer(data=receipt_data)
        if receipt_serializer.is_valid():
            receipt = receipt_serializer.save()
            response_serializer = ConsultationReceiptSerializer(receipt)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Receipt generated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Invalid receipt data',
                    'details': receipt_serializer.errors
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Consultation.DoesNotExist:
        return Response({
            'success': False,
            'error': {
                'code': 'CONSULTATION_NOT_FOUND',
                'message': f'Consultation with ID {consultation_id} not found'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'RECEIPT_GENERATION_ERROR',
                'message': f'Error generating receipt: {str(e)}'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_calculate_available_slots(request):
    """Test endpoint to calculate available slots without authentication (development only)"""
    try:
        doctor_id = request.query_params.get('doctor_id', 'DOC018')
        clinic_id = request.query_params.get('clinic_id', '1')
        date = request.query_params.get('date', '2025-08-04')
        
        from datetime import datetime, timedelta
        from doctors.models import DoctorSlot
        from eclinic.models import Clinic
        from authentication.models import User
        
        date_obj = datetime.strptime(date, '%Y-%m-%d').date()
        doctor = User.objects.get(id=doctor_id, role='doctor')
        
        # Try to get clinic by ID first, then by name
        try:
            clinic = Clinic.objects.get(id=clinic_id)
        except (Clinic.DoesNotExist, ValueError):
            try:
                clinic = Clinic.objects.get(name=clinic_id)
            except Clinic.DoesNotExist:
                # Use a default clinic or create one
                clinic, created = Clinic.objects.get_or_create(
                    name='Default Clinic',
                    defaults={
                        'consultation_duration': 15,
                        'is_active': True
                    }
                )
        
        # Get clinic consultation duration
        consultation_duration = clinic.consultation_duration  # in minutes
        
        # OPTIMIZATION: Pre-fetch all existing consultations for this doctor and date
        existing_consultations = Consultation.objects.filter(
            doctor=doctor,
            scheduled_date=date_obj,
            status__in=['scheduled', 'in_progress', 'confirmed']
        ).only('scheduled_time', 'duration')
        
        # OPTIMIZATION: Pre-fetch all booked slots for this doctor and date
        booked_slots = DoctorSlot.objects.filter(
            doctor=doctor,
            date=date_obj,
            is_booked=True
        ).only('start_time', 'end_time')
        
        # OPTIMIZATION: Create a set of blocked time ranges for fast lookup
        blocked_ranges = set()
        
        # Add consultation time ranges to blocked ranges
        for consultation in existing_consultations:
            start_time = consultation.scheduled_time
            end_time = (datetime.combine(date_obj, start_time) + 
                       timedelta(minutes=consultation.duration)).time()
            blocked_ranges.add((start_time, end_time))
        
        # Add booked slot time ranges to blocked ranges
        for slot in booked_slots:
            blocked_ranges.add((slot.start_time, slot.end_time))
        
        # Get doctor's availability for the date
        available_slots = DoctorSlot.objects.filter(
            doctor=doctor,
            date=date_obj,
            is_available=True,
            is_booked=False
        ).order_by('start_time')
        
        calculated_slots = []
        
        for slot in available_slots:
            # Convert slot times to datetime for calculation
            slot_start = datetime.combine(date_obj, slot.start_time)
            slot_end = datetime.combine(date_obj, slot.end_time)
            
            current_time = slot_start
            
            # Generate consultation slots within this availability period
            while current_time < slot_end:
                slot_end_time = current_time + timedelta(minutes=consultation_duration)
                
                # Don't create slot if it would exceed the availability period
                if slot_end_time > slot_end:
                    break
                
                # OPTIMIZATION: Fast overlap check using pre-computed blocked ranges
                slot_start_time = current_time.time()
                slot_end_time_obj = slot_end_time.time()
                
                # Check if this slot overlaps with any blocked range
                is_blocked = False
                for blocked_start, blocked_end in blocked_ranges:
                    if (slot_start_time < blocked_end and slot_end_time_obj > blocked_start):
                        is_blocked = True
                        break
                
                if not is_blocked:
                    calculated_slots.append({
                        'start_time': current_time.time().strftime('%H:%M'),
                        'end_time': slot_end_time.time().strftime('%H:%M'),
                        'duration_minutes': consultation_duration,
                        'clinic_name': clinic.name,
                        'doctor_name': doctor.name,
                        'is_available': True
                    })
                
                # Move to next slot
                current_time = slot_end_time
        
        return Response({
            'success': True,
            'data': {
                'slots': calculated_slots,
                'clinic_duration': consultation_duration,
                'date': date,
                'doctor_name': doctor.name,
                'clinic_name': clinic.name,
                'total_available_slots': len(calculated_slots)
            },
            'message': f'Calculated {len(calculated_slots)} available slots for {date}',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'ERROR',
                'message': str(e)
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_consultation_list(request):
    """Test endpoint to list consultations without authentication (development only)"""
    try:
        from datetime import datetime, timedelta
        now = timezone.now()
        
        # Get all consultations
        consultations = Consultation.objects.select_related('patient', 'doctor', 'clinic').all()
        
        # Filter upcoming consultations if requested
        upcoming_only = request.query_params.get('upcoming', '').lower() == 'true'
        if upcoming_only:
            consultations = consultations.filter(
                scheduled_date__gte=now.date()
            ).filter(
                # For today's consultations, check if time hasn't passed
                Q(scheduled_date__gt=now.date()) |
                Q(scheduled_date=now.date(), scheduled_time__gte=now.time())
            )
        
        # Filter by status
        status_filter = request.query_params.get('status')
        if status_filter:
            consultations = consultations.filter(status=status_filter)
        
        # Filter by payment status
        payment_status_filter = request.query_params.get('payment_status')
        if payment_status_filter:
            consultations = consultations.filter(payment_status=payment_status_filter)
        
        # Serialize the consultations
        serializer = ConsultationListSerializer(consultations, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'count': len(serializer.data),
            'message': 'Consultations retrieved successfully (test endpoint)',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'ERROR',
                'message': str(e)
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_admin_consultation_access(request):
    """Test endpoint to check admin consultation access (development only)"""
    try:
        # Get all admin users and their consultation access
        admin_users = User.objects.filter(role='admin')
        admin_access_data = []
        
        for admin in admin_users:
            try:
                clinic = admin.administered_clinic
                clinic_info = {
                    'id': clinic.id,
                    'name': clinic.name
                } if clinic else None
                
                # Get consultations this admin can access
                if clinic:
                    consultations = Consultation.objects.filter(clinic=clinic)
                else:
                    # Admin without clinic can see all consultations
                    consultations = Consultation.objects.all()
                
                consultation_count = consultations.count()
                consultation_ids = list(consultations.values_list('id', flat=True)[:5])  # First 5 IDs
                
            except AttributeError:
                clinic_info = None
                consultations = Consultation.objects.all()
                consultation_count = consultations.count()
                consultation_ids = list(consultations.values_list('id', flat=True)[:5])
            
            admin_access_data.append({
                'user_id': admin.id,
                'name': admin.name,
                'email': admin.email,
                'phone': admin.phone,
                'role': admin.role,
                'assigned_clinic': clinic_info,
                'has_clinic': clinic_info is not None,
                'consultation_access': {
                    'total_consultations': consultation_count,
                    'sample_consultation_ids': consultation_ids,
                    'can_access_all': clinic_info is None
                }
            })
        
        return Response({
            'success': True,
            'data': {
                'admin_access_data': admin_access_data,
                'total_admins': len(admin_access_data)
            },
            'message': 'Admin consultation access check completed',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'ERROR',
                'message': str(e)
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_admin_permissions(request):
    """Test endpoint to check admin permissions and clinic assignments (development only)"""
    try:
        # Get all admin users
        admin_users = User.objects.filter(role='admin')
        admin_data = []
        
        for admin in admin_users:
            try:
                clinic = admin.administered_clinic
                clinic_info = {
                    'id': clinic.id,
                    'name': clinic.name
                } if clinic else None
            except AttributeError:
                clinic_info = None
            
            admin_data.append({
                'user_id': admin.id,
                'name': admin.name,
                'email': admin.email,
                'phone': admin.phone,
                'role': admin.role,
                'assigned_clinic': clinic_info,
                'has_clinic': clinic_info is not None
            })
        
        # Get all superadmin users
        superadmin_users = User.objects.filter(role='superadmin')
        superadmin_data = []
        
        for superadmin in superadmin_users:
            superadmin_data.append({
                'user_id': superadmin.id,
                'name': superadmin.name,
                'email': superadmin.email,
                'phone': superadmin.phone,
                'role': superadmin.role
            })
        
        return Response({
            'success': True,
            'data': {
                'admin_users': admin_data,
                'superadmin_users': superadmin_data,
                'total_admins': len(admin_data),
                'total_superadmins': len(superadmin_data)
            },
            'message': 'Admin permissions check completed',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'ERROR',
                'message': str(e)
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_consultation_detail(request, consultation_id):
    """Test endpoint to view consultation details without authentication (development only)"""
    try:
        consultation = Consultation.objects.get(id=consultation_id)
        serializer = ConsultationDetailSerializer(consultation)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Consultation retrieved successfully (test endpoint)',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    except Consultation.DoesNotExist:
        return Response({
            'success': False,
            'error': {
                'code': 'CONSULTATION_NOT_FOUND',
                'message': f'Consultation with ID {consultation_id} not found'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'ERROR',
                'message': str(e)
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IsDoctor(BasePermission):
    """Custom permission to allow only doctors"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'doctor'


class DoctorConsultationViewSet(ModelViewSet):
    """ViewSet for doctor's consultation management"""
    serializer_class = ConsultationListSerializer
    permission_classes = [IsDoctor]
    pagination_class = ConsultationPagination

    def get_queryset(self):
        """Filter queryset to only include consultations for the logged-in doctor"""
        return Consultation.objects.filter(doctor=self.request.user).select_related('patient', 'clinic')

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action in ['add_note', 'get_notes']:
            return ConsultationNoteSerializer
        return self.serializer_class

    @extend_schema(
        parameters=[
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by consultation status (scheduled, in_progress, completed, cancelled)'),
            OpenApiParameter('search', OpenApiTypes.STR, description='Search in patient name, phone, chief complaint, or symptoms'),
            OpenApiParameter('ordering', OpenApiTypes.STR, description='Order by field (e.g., -scheduled_date, scheduled_time)'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Number of items per page (max 100)'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="List consultations for the logged-in doctor with filtering and pagination"
    )
    def list(self, request, *args, **kwargs):
        """List consultations with filtering and pagination"""
        queryset = self.get_queryset()
        
        # Apply status filter
        status_filter = request.query_params.get('status')
        if status_filter and status_filter != 'all':
            queryset = queryset.filter(status=status_filter)
        
        # Apply search filter
        search_term = request.query_params.get('search')
        if search_term:
            queryset = queryset.filter(
                Q(patient__name__icontains=search_term) |
                Q(patient__phone__icontains=search_term) |
                Q(chief_complaint__icontains=search_term) |
                Q(symptoms__icontains=search_term)
            )
        
        # Apply ordering
        ordering = request.query_params.get('ordering', '-scheduled_date')
        if ordering:
            queryset = queryset.order_by(ordering)
        
        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a consultation"""
        consultation = self.get_object()
        if consultation.status != 'scheduled':
            return Response(
                {'error': 'Consultation can only be started if it is scheduled.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        consultation.status = 'in_progress'
        consultation.save()
        return Response(self.get_serializer(consultation).data)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Complete a consultation"""
        consultation = self.get_object()
        if consultation.status != 'in_progress':
            return Response(
                {'error': 'Consultation can only be completed if it is in progress.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        consultation.status = 'completed'
        consultation.save()
        return Response(self.get_serializer(consultation).data)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a consultation"""
        consultation = self.get_object()
        if consultation.status in ['completed', 'cancelled']:
            return Response(
                {'error': 'Cannot cancel a completed or already cancelled consultation.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        consultation.status = 'cancelled'
        consultation.save()
        return Response(self.get_serializer(consultation).data)

    @action(detail=True, methods=['post'], url_path='notes')
    def add_note(self, request, pk=None):
        """Add a note to a consultation"""
        consultation = self.get_object()
        serializer = ConsultationNoteCreateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(consultation=consultation, created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='notes')
    def get_notes(self, request, pk=None):
        """Get notes for a consultation"""
        consultation = self.get_object()
        notes = ConsultationNote.objects.filter(consultation=consultation)
        serializer = ConsultationNoteSerializer(notes, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='vital-signs')
    def add_vital_signs(self, request, pk=None):
        """Add vital signs for a consultation"""
        consultation = self.get_object()
        
        # Check if vital signs already exist
        vital_signs, created = ConsultationVitalSigns.objects.get_or_create(
            consultation=consultation,
            defaults={'doctor': request.user}
        )
        
        serializer = ConsultationVitalSignsCreateSerializer(vital_signs, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='vital-signs')
    def get_vital_signs(self, request, pk=None):
        """Get vital signs for a consultation"""
        consultation = self.get_object()
        try:
            vital_signs = ConsultationVitalSigns.objects.get(consultation=consultation)
            serializer = ConsultationVitalSignsSerializer(vital_signs)
            return Response(serializer.data)
        except ConsultationVitalSigns.DoesNotExist:
            return Response({'message': 'No vital signs recorded yet'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'], url_path='assessment')
    def save_assessment(self, request, pk=None):
        """Save consultation assessment"""
        consultation = self.get_object()
        
        # Update consultation with assessment data
        assessment_data = request.data.get('assessment', {})
        if assessment_data:
            consultation.chief_complaint = assessment_data.get('chief_complaint', consultation.chief_complaint)
            consultation.symptoms = assessment_data.get('symptoms', consultation.symptoms)
            consultation.save()
        
        # Save symptoms if provided
        symptoms_data = request.data.get('symptoms', [])
        if symptoms_data:
            # Clear existing symptoms
            ConsultationSymptom.objects.filter(consultation=consultation).delete()
            
            # Add new symptoms
            for symptom_data in symptoms_data:
                ConsultationSymptom.objects.create(
                    consultation=consultation,
                    symptom=symptom_data.get('symptom', ''),
                    severity=symptom_data.get('severity', 'mild'),
                    duration=symptom_data.get('duration', ''),
                    doctor=request.user
                )
        
        return Response({'message': 'Assessment saved successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='diagnosis')
    def save_diagnosis(self, request, pk=None):
        """Save consultation diagnosis"""
        consultation = self.get_object()
        
        # Save diagnosis
        diagnosis_data = request.data.get('diagnosis', {})
        if diagnosis_data:
            diagnosis, created = ConsultationDiagnosis.objects.get_or_create(
                consultation=consultation,
                defaults={'doctor': request.user}
            )
            
            diagnosis.primary_diagnosis = diagnosis_data.get('primary_diagnosis', '')
            diagnosis.differential_diagnosis = diagnosis_data.get('differential_diagnosis', '')
            diagnosis.clinical_findings = diagnosis_data.get('clinical_findings', '')
            diagnosis.lab_results = diagnosis_data.get('lab_results', '')
            diagnosis.imaging = diagnosis_data.get('imaging', '')
            diagnosis.save()
        
        return Response({'message': 'Diagnosis saved successfully'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='prescription')
    def save_prescription(self, request, pk=None):
        """Save prescription for a consultation"""
        consultation = self.get_object()
        
        try:
            from prescriptions.models import Prescription
            from prescriptions.serializers import PrescriptionCreateSerializer
            
            # Create or update prescription
            prescription_data = request.data.get('prescription', {})
            if prescription_data:
                # Check if prescription already exists
                prescription, created = Prescription.objects.get_or_create(
                    consultation=consultation,
                    defaults={
                        'doctor': request.user,
                        'patient': consultation.patient,
                        'clinic': consultation.clinic
                    }
                )
                
                # Update prescription data
                prescription.instructions = prescription_data.get('instructions', '')
                prescription.follow_up = prescription_data.get('follow_up', '')
                prescription.next_visit = prescription_data.get('next_visit', '')
                prescription.diagnosis = prescription_data.get('diagnosis', '')
                prescription.save()
                
                # Handle medications
                medications_data = prescription_data.get('medications', [])
                if medications_data:
                    # Clear existing medications
                    prescription.medicines.clear()
                    
                    # Add new medications
                    for med_data in medications_data:
                        from prescriptions.models import Medicine
                        medicine, created = Medicine.objects.get_or_create(
                            name=med_data.get('name', ''),
                            defaults={
                                'dosage': med_data.get('dosage', ''),
                                'frequency': med_data.get('frequency', ''),
                                'duration': med_data.get('duration', ''),
                                'instructions': med_data.get('instructions', ''),
                                'before_meal': med_data.get('before_meal', True),
                                'is_generic': med_data.get('is_generic', False),
                                'quantity': med_data.get('quantity', '')
                            }
                        )
                        prescription.medicines.add(medicine)
                
                return Response({
                    'message': 'Prescription saved successfully',
                    'prescription_id': prescription.id
                }, status=status.HTTP_200_OK)
            
            return Response({'error': 'No prescription data provided'}, status=status.HTTP_400_BAD_REQUEST)
            
        except ImportError:
            return Response({'error': 'Prescription module not available'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'])
    def upcoming(self, request):
        """Get upcoming consultations for the logged-in doctor"""
        upcoming_consultations = self.get_queryset().filter(
            status='scheduled',
            scheduled_date__gte=timezone.now().date()
        ).order_by('scheduled_date', 'scheduled_time')
        
        page = self.paginate_queryset(upcoming_consultations)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(upcoming_consultations, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def completed(self, request):
        """Get completed consultations for the logged-in doctor"""
        completed_consultations = self.get_queryset().filter(status='completed').order_by('-scheduled_date', '-scheduled_time')
        
        page = self.paginate_queryset(completed_consultations)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(completed_consultations, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='real-time-updates')
    def real_time_updates(self, request):
        """Get real-time consultation updates for the logged-in doctor"""
        try:
            # Get recent consultations with updates
            recent_consultations = ConsultationService.get_doctor_consultations(
                doctor=request.user,
                date_from=timezone.now().date() - timedelta(days=7)
            )
            
            # Get today's consultations
            today_consultations = ConsultationService.get_today_consultations(request.user)
            
            # Get upcoming consultations
            upcoming_consultations = ConsultationService.get_upcoming_consultations(request.user, days=3)
            
            response_data = {
                'recent_updates': ConsultationListSerializer(recent_consultations[:10], many=True).data,
                'today_consultations': ConsultationListSerializer(today_consultations, many=True).data,
                'upcoming_consultations': ConsultationListSerializer(upcoming_consultations, many=True).data,
                'last_updated': timezone.now().isoformat()
            }
            
            return Response({
                'success': True,
                'data': response_data,
                'message': 'Real-time updates retrieved successfully'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='analytics')
    def analytics(self, request):
        """Get consultation analytics for the logged-in doctor"""
        try:
            # Get date range from query parameters
            days = int(request.query_params.get('days', 30))
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get performance metrics
            performance_metrics = ConsultationAnalyticsService.get_doctor_performance_metrics(
                doctor=request.user,
                start_date=start_date,
                end_date=end_date
            )
            
            # Get consultation trends
            trends = ConsultationAnalyticsService.get_consultation_trends(
                doctor=request.user,
                days=days
            )
            
            # Get revenue analytics
            revenue_analytics = ConsultationAnalyticsService.get_revenue_analytics(
                doctor=request.user,
                start_date=start_date,
                end_date=end_date
            )
            
            response_data = {
                'performance_metrics': performance_metrics,
                'consultation_trends': trends,
                'revenue_analytics': revenue_analytics,
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': days
                }
            }
            
            return Response({
                'success': True,
                'data': response_data,
                'message': 'Analytics retrieved successfully'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'], url_path='reschedule')
    def reschedule_consultation(self, request, pk=None):
        """Reschedule a consultation"""
        try:
            consultation = self.get_object()
            
            # Validate input data
            new_date = request.data.get('new_date')
            new_time = request.data.get('new_time')
            reason = request.data.get('reason', '')
            
            if not new_date or not new_time:
                return Response({
                    'success': False,
                    'error': 'New date and time are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Parse date and time
            try:
                new_date = datetime.strptime(new_date, '%Y-%m-%d').date()
                new_time = datetime.strptime(new_time, '%H:%M:%S').time()
            except ValueError:
                return Response({
                    'success': False,
                    'error': 'Invalid date or time format'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Reschedule consultation
            ConsultationService.reschedule_consultation(
                consultation=consultation,
                new_date=new_date,
                new_time=new_time,
                rescheduled_by=request.user,
                reason=reason
            )
            
            return Response({
                'success': True,
                'data': self.get_serializer(consultation).data,
                'message': 'Consultation rescheduled successfully'
            }, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'], url_path='bulk-actions')
    def bulk_actions(self, request, pk=None):
        """Perform bulk actions on consultations"""
        try:
            action_type = request.data.get('action')
            consultation_ids = request.data.get('consultation_ids', [])
            
            if not action_type or not consultation_ids:
                return Response({
                    'success': False,
                    'error': 'Action type and consultation IDs are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            consultations = Consultation.objects.filter(
                id__in=consultation_ids,
                doctor=request.user
            )
            
            results = []
            
            if action_type == 'start':
                for consultation in consultations:
                    try:
                        ConsultationService.start_consultation(consultation)
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'success',
                            'message': 'Consultation started'
                        })
                    except Exception as e:
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'error',
                            'message': str(e)
                        })
            
            elif action_type == 'complete':
                for consultation in consultations:
                    try:
                        ConsultationService.complete_consultation(consultation)
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'success',
                            'message': 'Consultation completed'
                        })
                    except Exception as e:
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'error',
                            'message': str(e)
                        })
            
            elif action_type == 'cancel':
                reason = request.data.get('reason', '')
                for consultation in consultations:
                    try:
                        ConsultationService.cancel_consultation(
                            consultation=consultation,
                            cancelled_by=request.user,
                            reason=reason
                        )
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'success',
                            'message': 'Consultation cancelled'
                        })
                    except Exception as e:
                        results.append({
                            'consultation_id': consultation.id,
                            'status': 'error',
                            'message': str(e)
                        })
            
            else:
                return Response({
                    'success': False,
                    'error': 'Invalid action type'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'success': True,
                'data': {
                    'action_type': action_type,
                    'results': results,
                    'total_processed': len(results)
                },
                'message': f'Bulk action {action_type} completed'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='dashboard-stats')
    def dashboard_stats(self, request):
        """Get dashboard statistics for the logged-in doctor"""
        try:
            today = timezone.now().date()
            
            # Get today's statistics
            today_stats = ConsultationService.get_consultation_statistics(
                doctor=request.user,
                date_from=today,
                date_to=today
            )
            
            # Get this week's statistics
            week_start = today - timedelta(days=today.weekday())
            week_stats = ConsultationService.get_consultation_statistics(
                doctor=request.user,
                date_from=week_start,
                date_to=today
            )
            
            # Get this month's statistics
            month_start = today.replace(day=1)
            month_stats = ConsultationService.get_consultation_statistics(
                doctor=request.user,
                date_from=month_start,
                date_to=today
            )
            
            # Get upcoming consultations count
            upcoming_count = ConsultationService.get_upcoming_consultations(
                doctor=request.user,
                days=7
            ).count()
            
            response_data = {
                'today': today_stats,
                'this_week': week_stats,
                'this_month': month_stats,
                'upcoming_consultations': upcoming_count,
                'last_updated': timezone.now().isoformat()
            }
            
            return Response({
                'success': True,
                'data': response_data,
                'message': 'Dashboard statistics retrieved successfully'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='overdue')
    def get_overdue_consultations(self, request):
        """Get all overdue consultations (admin/superadmin/doctor)"""
        try:
            # Get overdue consultations using the service
            from .services import ConsultationAutoCompletionService
            overdue_consultations = ConsultationAutoCompletionService.get_overdue_consultations()
            print(f'🔍 Overdue endpoint called by user: {request.user.role} ({request.user.id})')
            print(f'🔍 Found {len(overdue_consultations)} overdue consultations from service')
            
            # Filter based on user role (since service returns list of dicts, we filter after)
            user = request.user
            filtered_consultations = []
            
            for consultation_data in overdue_consultations:
                # For role-based filtering, we need to get the actual consultation object
                consultation_id = consultation_data['id']
                try:
                    consultation = Consultation.objects.get(id=consultation_id)
                    
                    # Apply role-based filtering
                    if user.role == 'doctor':
                        # Doctors can only see their own overdue consultations
                        if consultation.doctor == user:
                            filtered_consultations.append(consultation_data)
                    elif user.role == 'admin':
                        # Admins can see overdue consultations for their assigned clinic
                        # AND consultations without clinic assignment
                        try:
                            assigned_clinic = getattr(user, 'administered_clinic', None)
                            if assigned_clinic and consultation.clinic == assigned_clinic:
                                # Consultation belongs to admin's clinic
                                filtered_consultations.append(consultation_data)
                            elif not consultation.clinic:
                                # Consultation has no clinic assignment - admin can see it
                                filtered_consultations.append(consultation_data)
                            elif not assigned_clinic:
                                # Admin has no clinic assignment - can see all
                                filtered_consultations.append(consultation_data)
                        except AttributeError:
                            # Admin without clinic assignment can see all
                            filtered_consultations.append(consultation_data)
                    else:
                        # Superadmin can see all
                        filtered_consultations.append(consultation_data)
                        
                except Consultation.DoesNotExist:
                    continue  # Skip if consultation not found
            
            # Serialize the results using the overdue serializer
            serializer = ConsultationOverdueSerializer(filtered_consultations, many=True)
            
            return Response({
                'success': True,
                'data': serializer.data,
                'message': f'Found {len(filtered_consultations)} overdue consultations',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def test_whatsapp_notification(request):
    """Test endpoint for WhatsApp notifications"""
    try:
        consultation_id = request.data.get('consultation_id')
        if not consultation_id:
            return Response(
                {'error': 'consultation_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        consultation = Consultation.objects.get(id=consultation_id)
        whatsapp_service = WhatsAppNotificationService()
        
        # Test doctor notification
        doctor_result = whatsapp_service.send_doctor_appointment_notification(consultation)
        
        # Test patient notification
        patient_result = whatsapp_service.send_patient_appointment_confirmation(consultation)
        
        return Response({
            'success': True,
            'doctor_notification_sent': doctor_result,
            'patient_notification_sent': patient_result,
            'consultation_id': consultation_id,
            'doctor_name': consultation.doctor.name,
            'patient_name': consultation.patient.name
        })
        
    except Consultation.DoesNotExist:
        return Response(
            {'error': 'Consultation not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ============================================================================
# CHECK-IN MANAGEMENT VIEWS
# ============================================================================

class ConsultationCheckInView(APIView):
    """Handle patient check-in for consultations"""
    permission_classes = [IsAdminOrSuperAdmin]
    
    @extend_schema(
        responses={200: ConsultationCheckInSerializer},
        description="Check in a patient for consultation"
    )
    def post(self, request, consultation_id):
        """Check in a patient for consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check if consultation is in scheduled status
            if consultation.status != 'scheduled':
                return Response({
                    'success': False,
                    'error': f'Cannot check in patient. Consultation status is: {consultation.status}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check in the patient
            if consultation.check_in_patient(request.user):
                serializer = ConsultationCheckInSerializer(consultation)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': f'Patient {consultation.patient.name} checked in successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'error': 'Failed to check in patient. Invalid consultation status.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationReadyView(APIView):
    """Handle marking patient as ready for consultation"""
    permission_classes = [IsAdminOrSuperAdmin]
    
    @extend_schema(
        responses={200: ConsultationReadySerializer},
        description="Mark patient as ready for consultation"
    )
    def post(self, request, consultation_id):
        """Mark patient as ready for consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check if consultation can be marked as ready
            if consultation.status not in ['scheduled', 'patient_checked_in']:
                return Response({
                    'success': False,
                    'error': f'Cannot mark patient as ready. Consultation status is: {consultation.status}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Mark patient as ready
            if consultation.mark_ready_for_consultation(request.user):
                serializer = ConsultationReadySerializer(consultation)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': f'Patient {consultation.patient.name} marked as ready for consultation',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'error': 'Failed to mark patient as ready. Invalid consultation status.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationStartView(APIView):
    """Handle starting a consultation"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: ConsultationStartSerializer},
        description="Start a consultation"
    )
    def post(self, request, consultation_id):
        """Start a consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check permissions - only doctors can start consultations
            user = request.user
            if user.role != 'doctor':
                return Response({
                    'success': False,
                    'error': 'Only doctors can start consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            if consultation.doctor != user:
                return Response({
                    'success': False,
                    'error': 'You can only start your own consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Check if consultation can be started
            if consultation.status not in ['ready_for_consultation', 'patient_checked_in']:
                return Response({
                    'success': False,
                    'error': f'Cannot start consultation. Status is: {consultation.status}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Start the consultation
            if consultation.start_consultation():
                serializer = ConsultationStartSerializer(consultation)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': f'Consultation {consultation.id} started successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'error': 'Failed to start consultation. Invalid status.'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationCompleteView(APIView):
    """Handle completing a consultation"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: ConsultationStartSerializer},
        description="Complete a consultation"
    )
    def post(self, request, consultation_id):
        """Complete a consultation"""
        try:
            consultation = Consultation.objects.get(id=consultation_id)
            
            # Check permissions - only doctors can complete consultations
            user = request.user
            if user.role != 'doctor':
                return Response({
                    'success': False,
                    'error': 'Only doctors can complete consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            if consultation.doctor != user:
                return Response({
                    'success': False,
                    'error': 'You can only complete your own consultations'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Check if consultation can be completed
            if consultation.status != 'in_progress':
                return Response({
                    'success': False,
                    'error': f'Cannot complete consultation. Current status is: {consultation.status}. Only in-progress consultations can be completed.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Complete the consultation
            try:
                from .services import ConsultationService
                ConsultationService.complete_consultation(consultation)
                
                serializer = ConsultationStartSerializer(consultation)
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': f'Consultation {consultation.id} completed successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            except ValidationError as e:
                return Response({
                    'success': False,
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Consultation.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Consultation not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsultationManagementView(APIView):
    """Get consultations for admin management with check-in status"""
    permission_classes = [IsAdminOrSuperAdmin]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by consultation status'),
            OpenApiParameter('date', OpenApiTypes.DATE, description='Filter by date (YYYY-MM-DD)'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Number of items per page'),
        ],
        responses={200: ConsultationListSerializer(many=True)},
        description="Get consultations for admin management"
    )
    def get(self, request):
        """Get consultations for admin management"""
        try:
            # Get query parameters
            status_filter = request.query_params.get('status', '')
            date_filter = request.query_params.get('date', '')
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            
            # Build queryset
            queryset = Consultation.objects.select_related(
                'patient', 'doctor', 'clinic'
            ).order_by('-scheduled_date', '-scheduled_time')
            
            # Apply filters
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            if date_filter:
                try:
                    filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                    queryset = queryset.filter(scheduled_date=filter_date)
                except ValueError:
                    return Response({
                        'success': False,
                        'error': 'Invalid date format. Use YYYY-MM-DD'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Pagination
            paginator = ConsultationPagination()
            paginated_queryset = paginator.paginate_queryset(queryset, request)
            
            serializer = ConsultationListSerializer(paginated_queryset, many=True)
            
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Consultations retrieved successfully for management',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)