from rest_framework import status, permissions, filters
from rest_framework.permissions import BasePermission
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.pagination import PageNumberPagination
from django.utils import timezone
from django.db.models import Q, Count, Avg, Sum
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from datetime import datetime, timedelta
from django.db import IntegrityError, transaction
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json

from authentication.models import User
from .models import (
    DoctorProfile, DoctorEducation, DoctorExperience, 
    DoctorDocument, DoctorSchedule, DoctorReview, DoctorSlot, DoctorStatus
)
from .serializers import (
    DoctorProfileSerializer, DoctorProfileCreateSerializer, DoctorProfileUpdateSerializer,
    DoctorEducationSerializer, DoctorExperienceSerializer,
    DoctorDocumentSerializer, DoctorScheduleSerializer,
    DoctorReviewSerializer, DoctorListSerializer, DoctorSearchSerializer,
    DoctorStatsSerializer, DoctorScheduleCreateSerializer, DoctorSlotSerializer,
    DoctorSlotGenerationSerializer, DoctorStatusSerializer, DoctorStatusUpdateSerializer, DoctorStatusListSerializer,
    PublicDoctorListSerializer
)


class DoctorPagination(PageNumberPagination):
    """Custom pagination for doctor lists"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# Custom permission to allow only admin and superadmin
class IsAdminOrSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['admin', 'superadmin']


# Custom permission for doctor slots - allows doctor to manage their own slots or superadmin to manage any doctor's slots
class IsDoctorOrSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superadmin can manage any doctor's slots
        if request.user.role == 'superadmin':
            return True
        
        # Doctor can only manage their own slots
        if request.user.role == 'doctor':
            doctor_id = view.kwargs.get('doctor_id')
            # Allow if doctor_id matches current user or if it's 'current' (for self-reference)
            return doctor_id == str(request.user.id) or doctor_id == 'current'
        
        # Admin can also manage any doctor's slots
        if request.user.role == 'admin':
            return True
        
        return False


class DoctorProfileViewSet(ModelViewSet):
    """ViewSet for doctor profile management"""
    queryset = DoctorProfile.objects.all()
    def get_permissions(self):
        # Only allow admin/superadmin for superadmin endpoints
        if self.request.path.startswith('/api/doctors/superadmin/'):
            return [IsAdminOrSuperAdmin()]
        return [permissions.IsAuthenticated()]
    pagination_class = DoctorPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['user__name', 'specialization', 'qualification']
    ordering_fields = ['created_at', 'user__name', 'rating', 'consultation_fee']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return DoctorProfileCreateSerializer
        elif self.action == 'update' or self.action == 'partial_update':
            return DoctorProfileUpdateSerializer
        elif self.action == 'list':
            return DoctorListSerializer
        return DoctorProfileSerializer
    
    def get_queryset(self):
        """Filter queryset based on user role"""
        user = self.request.user
        queryset = DoctorProfile.objects.select_related('user')
        
        if user.role == 'doctor':
            # Doctors can only see their own profile
            return queryset.filter(user=user)
        elif user.role == 'patient':
            # Patients can see all verified and active doctors
            return queryset.filter(is_verified=True, is_active=True)
        elif user.role in ['admin', 'superadmin']:
            # Admins can see all doctors
            return queryset
        
        return queryset.filter(is_verified=True, is_active=True)
    
    @extend_schema(
        responses={200: DoctorProfileSerializer},
        description="Get doctor profile by ID"
    )
    def retrieve(self, request, pk=None):
        """Get doctor profile by ID"""
        doctor = self.get_object()
        serializer = DoctorProfileSerializer(doctor)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Doctor profile retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        responses={200: DoctorListSerializer(many=True)},
        description="List all doctors with pagination and filtering"
    )
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current doctor's profile"""
        if request.user.role != 'doctor':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only doctors can access their own profile'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            doctor_profile = DoctorProfile.objects.get(user=request.user)
            serializer = DoctorProfileSerializer(doctor_profile)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Doctor profile retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        except DoctorProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'PROFILE_NOT_FOUND',
                    'message': 'Doctor profile not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_me(self, request):
        """Update current doctor's profile"""
        if request.user.role != 'doctor':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only doctors can update their own profile'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            doctor_profile = DoctorProfile.objects.get(user=request.user)
            
            # Handle profile picture update for user
            if 'profile_picture' in request.FILES:
                request.user.profile_picture = request.FILES['profile_picture']
                request.user.save()
            
            # Handle other profile fields
            serializer = DoctorProfileUpdateSerializer(
                doctor_profile, 
                data=request.data, 
                partial=True,
                context={'request': request}
            )
            
            if serializer.is_valid():
                updated_profile = serializer.save()
                response_serializer = DoctorProfileSerializer(updated_profile)
                return Response({
                    'success': True,
                    'data': response_serializer.data,
                    'message': 'Doctor profile updated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Invalid data provided',
                        'details': serializer.errors
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except DoctorProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'PROFILE_NOT_FOUND',
                    'message': 'Doctor profile not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    def list(self, request):
        """List doctors with pagination and filtering"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Doctors retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Doctors retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        request=DoctorProfileCreateSerializer,
        responses={201: DoctorProfileSerializer},
        description="Create doctor profile"
    )
    def create(self, request):
        """Create doctor profile"""
        # Check if doctor profile already exists
        if hasattr(request.user, 'doctor_profile'):
            return Response({
                'success': False,
                'error': {
                    'code': 'PROFILE_EXISTS',
                    'message': 'Doctor profile already exists'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            doctor_profile = serializer.save()
            response_serializer = DoctorProfileSerializer(doctor_profile)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Doctor profile created successfully',
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


class DoctorEducationViewSet(ModelViewSet):
    """ViewSet for doctor education"""
    serializer_class = DoctorEducationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get education records for specific doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        return DoctorEducation.objects.filter(doctor_id=doctor_id)
    
    def perform_create(self, serializer):
        """Create education record for doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        serializer.save(doctor_id=doctor_id)


class DoctorExperienceViewSet(ModelViewSet):
    """ViewSet for doctor experience"""
    serializer_class = DoctorExperienceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get experience records for specific doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        return DoctorExperience.objects.filter(doctor_id=doctor_id)
    
    def perform_create(self, serializer):
        """Create experience record for doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        serializer.save(doctor_id=doctor_id)


class DoctorDocumentViewSet(ModelViewSet):
    """ViewSet for doctor documents"""
    serializer_class = DoctorDocumentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get documents for specific doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        return DoctorDocument.objects.filter(doctor_id=doctor_id)
    
    def perform_create(self, serializer):
        """Create document for doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        serializer.save(doctor_id=doctor_id, uploaded_by=self.request.user)


class DoctorScheduleViewSet(ModelViewSet):
    """ViewSet for doctor schedule"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get schedule for specific doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        queryset = DoctorSchedule.objects.filter(doctor_id=doctor_id)
        
        # Filter by date range if provided
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(date__gte=start_date)
        if end_date:
            queryset = queryset.filter(date__lte=end_date)
        
        return queryset.order_by('date', 'start_time')
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return DoctorScheduleCreateSerializer
        return DoctorScheduleSerializer


class DoctorReviewViewSet(ModelViewSet):
    """ViewSet for doctor reviews"""
    serializer_class = DoctorReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get reviews for specific doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        return DoctorReview.objects.filter(doctor_id=doctor_id, is_approved=True)
    
    def perform_create(self, serializer):
        """Create review for doctor"""
        doctor_id = self.kwargs.get('doctor_id')
        serializer.save(doctor_id=doctor_id, patient=self.request.user)


class DoctorSlotViewSet(ModelViewSet):
    """ViewSet for doctor slots (multiple slots per day, month view)"""
    permission_classes = [IsDoctorOrSuperAdmin]
    serializer_class = DoctorSlotSerializer

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return super().get_serializer(*args, **kwargs)

    def get_queryset(self):
        doctor_id = self.kwargs.get('doctor_id')
        user = self.request.user
        
        # Handle admin access - if admin is trying to access their own ID, return empty queryset
        # or allow them to access all slots (depending on business logic)
        if user.role == 'admin' and doctor_id == user.id:
            # Admin trying to access their own ID - this should probably be handled differently
            # For now, return empty queryset with a helpful message
            return DoctorSlot.objects.none()
        
        # Handle 'current' doctor_id for self-reference
        if doctor_id == 'current':
            doctor_id = self.request.user.id
        
        # For admins and superadmins, allow access to any doctor's slots
        if user.role in ['admin', 'superadmin']:
            # If doctor_id is provided and it's a valid doctor, filter by that doctor
            if doctor_id and doctor_id.startswith('DOC'):
                queryset = DoctorSlot.objects.filter(doctor_id=doctor_id)
            else:
                # If no valid doctor_id provided, return all slots (for admin overview)
                queryset = DoctorSlot.objects.all()
        else:
            # For doctors, only allow access to their own slots
            queryset = DoctorSlot.objects.filter(doctor_id=doctor_id)
        
        # Filter by specific date (highest priority)
        date_param = self.request.query_params.get('date')
        if date_param:
            queryset = queryset.filter(date=date_param)
        else:
            # Optional: filter by month/year if no specific date
            month = self.request.query_params.get('month')
            year = self.request.query_params.get('year')
            if month and year:
                queryset = queryset.filter(date__year=year, date__month=month)
        
        return queryset.order_by('date', 'start_time')

    def list(self, request, *args, **kwargs):
        """Override list method to handle admin access to their own ID"""
        user = request.user
        doctor_id = self.kwargs.get('doctor_id')
        
        # If admin is trying to access their own ID, return all doctor slots
        if user.role == 'admin' and doctor_id == user.id:
            # Get all doctor slots for admin overview
            queryset = DoctorSlot.objects.all()
            
            # Apply filters
            date_param = request.query_params.get('date')
            if date_param:
                queryset = queryset.filter(date=date_param)
            else:
                month = request.query_params.get('month')
                year = request.query_params.get('year')
                if month and year:
                    queryset = queryset.filter(date__year=year, date__month=month)
            
            queryset = queryset.order_by('date', 'start_time')
            
            # Serialize and return
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': f'All doctor slots retrieved for admin {user.name}',
                'timestamp': timezone.now().isoformat()
            })
        
        # Use default list behavior for other cases
        return super().list(request, *args, **kwargs)

    def perform_create(self, serializer):
        doctor_id = self.kwargs.get('doctor_id')
        # Handle 'current' doctor_id for self-reference
        if doctor_id == 'current':
            doctor_id = self.request.user.id
        serializer.save(doctor_id=doctor_id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                self.perform_create(serializer)
                headers = self.get_success_headers(serializer.data)
                return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
            except IntegrityError:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'DUPLICATE_SLOT',
                        'message': 'A slot with the same date, start time, and end time already exists for this doctor.'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid data provided',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def generate_slots(self, request, doctor_id=None):
        """Generate consultation slots from doctor availability"""
        serializer = DoctorSlotGenerationSerializer(data=request.data, context={'view': self})
        if serializer.is_valid():
            try:
                slots = serializer.create(serializer.validated_data)
                slot_serializer = DoctorSlotSerializer(slots, many=True)
                return Response({
                    'success': True,
                    'data': slot_serializer.data,
                    'message': f'Successfully generated {len(slots)} consultation slots',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'SLOT_GENERATION_ERROR',
                        'message': str(e)
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid data provided',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def available_slots(self, request, doctor_id=None):
        """Get available slots for a specific date"""
        date = request.query_params.get('date')
        clinic_id = request.query_params.get('clinic')
        
        if not date:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_DATE',
                    'message': 'Date parameter is required'
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
        
        queryset = self.get_queryset().filter(
            date=date_obj,
            is_available=True,
            is_booked=False
        )
        
        if clinic_id:
            queryset = queryset.filter(clinic_id=clinic_id)
        
        serializer = DoctorSlotSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': f'Available slots for {date}',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class DoctorSearchView(APIView):
    """Search doctors with advanced filters"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('query', OpenApiTypes.STR, description='Search query'),
            OpenApiParameter('specialization', OpenApiTypes.STR, description='Specialization filter'),
            OpenApiParameter('min_experience', OpenApiTypes.INT, description='Minimum experience years'),
            OpenApiParameter('max_experience', OpenApiTypes.INT, description='Maximum experience years'),
            OpenApiParameter('min_fee', OpenApiTypes.NUMBER, description='Minimum consultation fee'),
            OpenApiParameter('max_fee', OpenApiTypes.NUMBER, description='Maximum consultation fee'),
            OpenApiParameter('consultation_type', OpenApiTypes.STR, description='Consultation type'),
            OpenApiParameter('rating_min', OpenApiTypes.NUMBER, description='Minimum rating'),
            OpenApiParameter('is_verified', OpenApiTypes.BOOL, description='Verified doctors only'),
            OpenApiParameter('city', OpenApiTypes.STR, description='City filter'),
        ],
        responses={200: DoctorListSerializer(many=True)},
        description="Search doctors with advanced filters"
    )
    def get(self, request):
        """Search doctors with advanced filters"""
        serializer = DoctorSearchSerializer(data=request.query_params)
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
        queryset = DoctorProfile.objects.select_related('user').filter(is_active=True)
        
        # Apply search filters
        search_data = serializer.validated_data
        
        if search_data.get('query'):
            query = search_data['query']
            queryset = queryset.filter(
                Q(user__name__icontains=query) |
                Q(specialization__icontains=query) |
                Q(qualification__icontains=query) |
                Q(sub_specialization__icontains=query)
            )
        
        if search_data.get('specialization'):
            queryset = queryset.filter(specialization__icontains=search_data['specialization'])
        
        if search_data.get('sub_specialization'):
            queryset = queryset.filter(sub_specialization__icontains=search_data['sub_specialization'])
        
        if search_data.get('min_experience'):
            # Calculate based on experience records
            min_exp = search_data['min_experience']
            queryset = queryset.filter(experience_years__gte=min_exp)
        
        if search_data.get('max_experience'):
            max_exp = search_data['max_experience']
            queryset = queryset.filter(experience_years__lte=max_exp)
        
        if search_data.get('min_fee'):
            queryset = queryset.filter(consultation_fee__gte=search_data['min_fee'])
        
        if search_data.get('max_fee'):
            queryset = queryset.filter(consultation_fee__lte=search_data['max_fee'])
        
        if search_data.get('rating_min'):
            queryset = queryset.filter(rating__gte=search_data['rating_min'])
        
        if search_data.get('is_verified'):
            queryset = queryset.filter(is_verified=search_data['is_verified'])
        
        # Note: emergency_available field removed as it doesn't exist in the model
        
        if search_data.get('consultation_type'):
            consultation_type = search_data['consultation_type']
            if consultation_type == 'online':
                queryset = queryset.filter(is_online_consultation_available=True)
            elif consultation_type == 'in_person':
                queryset = queryset.filter(is_accepting_patients=True)
        
        if search_data.get('city'):
            queryset = queryset.filter(user__city__icontains=search_data['city'])
        
        if search_data.get('state'):
            queryset = queryset.filter(user__state__icontains=search_data['state'])
        
        # Paginate results
        paginator = DoctorPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = DoctorListSerializer(page, many=True)
            return paginator.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Search results retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = DoctorListSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Search results retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class DoctorStatsView(APIView):
    """Get doctor statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: DoctorStatsSerializer},
        description="Get doctor statistics and analytics"
    )
    def get(self, request):
        """Get doctor statistics"""
        
        user = request.user
        queryset = DoctorProfile.objects.select_related('user')
        
        # Check permissions
        if user.role not in ['admin', 'superadmin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Insufficient permissions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Calculate statistics
        total_doctors = DoctorProfile.objects.count()
        verified_doctors = DoctorProfile.objects.filter(is_verified=True).count()
        active_doctors = DoctorProfile.objects.filter(is_active=True).count()
        
        # New doctors this month
        current_month = timezone.now().month
        current_year = timezone.now().year
        new_this_month = DoctorProfile.objects.filter(
            created_at__year=current_year,
            created_at__month=current_month
        ).count()
        
        # Average rating
        avg_rating = DoctorProfile.objects.aggregate(
            avg_rating=Avg('rating')
        )['avg_rating'] or 0.0
        
        # Specialization distribution
        specialization_distribution = dict(
            DoctorProfile.objects.values('specialization').annotate(
                count=Count('specialization')
            ).values_list('specialization', 'count')
        )
        
        # Experience distribution
        experience_ranges = {
            '0-2': 0, '3-5': 0, '6-10': 0, '11-15': 0, '16-20': 0, '20+': 0
        }
        
        for doctor in DoctorProfile.objects.all():
            exp = doctor.experience_years or 0
            if exp <= 2:
                experience_ranges['0-2'] += 1
            elif exp <= 5:
                experience_ranges['3-5'] += 1
            elif exp <= 10:
                experience_ranges['6-10'] += 1
            elif exp <= 15:
                experience_ranges['11-15'] += 1
            elif exp <= 20:
                experience_ranges['16-20'] += 1
            else:
                experience_ranges['20+'] += 1
        
        # Average consultation fee
        avg_fee = DoctorProfile.objects.aggregate(
            avg_fee=Avg('consultation_fee')
        )['avg_fee'] or 0
        
        # Top rated doctors
        top_rated = list(
            DoctorProfile.objects.filter(
                rating__gte=4.0
            ).order_by('-rating')[:10].values(
                'user__name', 'specialization', 'rating'
            )
        )
        
        # Consultation stats
        from consultations.models import Consultation
        consultation_stats = {
            'total_consultations': Consultation.objects.count(),
            'avg_consultations_per_doctor': Consultation.objects.count() / max(total_doctors, 1),
            'consultation_completion_rate': 0  # Calculate based on your business logic
        }
        
        stats_data = {
            'total_doctors': total_doctors,
            'active_doctors': active_doctors,
            'new_this_month': new_this_month,
            'avg_rating': avg_rating,
            'verified_doctors': verified_doctors,
            'specialization_distribution': specialization_distribution,
            'experience_distribution': experience_ranges,
            'average_consultation_fee': avg_fee,
            'top_rated_doctors': top_rated,
            'consultation_stats': consultation_stats
        }
        
        serializer = DoctorStatsSerializer(stats_data)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Doctor statistics retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class SuperAdminDoctorManagementView(APIView):
    """SuperAdmin endpoints for doctor management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Allow admin and superadmin to access"""
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) not in ['admin', 'superadmin']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        parameters=[
            OpenApiParameter('is_active', OpenApiTypes.BOOL, description='Filter by active status (only True works since we use hard delete)'),
            OpenApiParameter('is_verified', OpenApiTypes.BOOL, description='Filter by verification status'),
            OpenApiParameter('specialization', OpenApiTypes.STR, description='Filter by specialization'),
            OpenApiParameter('search', OpenApiTypes.STR, description='Search by name or license number'),
        ],
        responses={200: DoctorListSerializer(many=True)},
        description="List all doctors (SuperAdmin only)"
    )
    def get(self, request):
        """List all doctors with filtering"""
        queryset = DoctorProfile.objects.select_related('user').all()
        
        # Apply filters
        is_active = request.query_params.get('is_active')
        if is_active is not None:
            # Note: Since we use hard delete, is_active=False will show no results
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        is_verified = request.query_params.get('is_verified')
        if is_verified is not None:
            queryset = queryset.filter(is_verified=is_verified.lower() == 'true')
        
        specialization = request.query_params.get('specialization')
        if specialization:
            queryset = queryset.filter(specialization=specialization)
        
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(user__name__icontains=search) |
                Q(license_number__icontains=search) |
                Q(specialization__icontains=search)
            )
        
        # Order the queryset to fix pagination warning
        queryset = queryset.order_by('-created_at', 'id')
        
        # Pagination
        paginator = DoctorPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = DoctorListSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = DoctorListSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Doctors retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        request={
            'phone': OpenApiTypes.STR,
            'name': OpenApiTypes.STR,
            'email': OpenApiTypes.STR,
            'profile_picture': OpenApiTypes.BINARY,
            'license_number': OpenApiTypes.STR,
            'qualification': OpenApiTypes.STR,
            'specialization': OpenApiTypes.STR,
            'sub_specialization': OpenApiTypes.STR,
            'consultation_fee': OpenApiTypes.NUMBER,
            'online_consultation_fee': OpenApiTypes.NUMBER,
            'experience_years': OpenApiTypes.INT,
            'clinic_name': OpenApiTypes.STR,
            'clinic_address': OpenApiTypes.STR,
            'bio': OpenApiTypes.STR,
            'languages_spoken': OpenApiTypes.STR,
            'consultation_duration': OpenApiTypes.INT,
            'is_online_consultation_available': OpenApiTypes.BOOL,
            'is_active': OpenApiTypes.BOOL,
            'date_of_birth': OpenApiTypes.STR,
            'date_of_anniversary': OpenApiTypes.STR,
        },
        responses={201: DoctorProfileSerializer},
        description="Create new doctor account and profile (SuperAdmin only)"
    )
    @transaction.atomic
    def post(self, request):
        """Create new doctor account and profile"""
        # Validate required fields
        required_fields = ['phone', 'name', 'license_number', 'qualification', 'specialization', 'consultation_fee']
        for field in required_fields:
            if field not in request.data:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MISSING_FIELD',
                        'message': f'Field "{field}" is required'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user already exists
        if User.objects.filter(phone=request.data['phone']).exists():
            return Response({
                'success': False,
                'error': {
                    'code': 'USER_EXISTS',
                    'message': 'User with this phone number already exists'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if license number already exists
        if DoctorProfile.objects.filter(license_number=request.data['license_number']).exists():
            return Response({
                'success': False,
                'error': {
                    'code': 'LICENSE_EXISTS',
                    'message': 'Doctor with this license number already exists'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Create user account
            import secrets
            password = secrets.token_urlsafe(8)
            
            user_data = {
                'phone': request.data['phone'],
                'name': request.data['name'],
                'email': request.data.get('email', ''),
                'role': 'doctor',
                'is_verified': True,  # SuperAdmin-created doctors are pre-verified
            }
            
            # Handle profile picture if provided
            if 'profile_picture' in request.FILES:
                user_data['profile_picture'] = request.FILES['profile_picture']
            
            user = User.objects.create_user(**user_data)
            user.set_password(password)
            user.save()
            
            # Helper function to convert string boolean to actual boolean
            def parse_boolean(value):
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on']
                return bool(value)
            
            # Helper function to parse JSON strings
            def parse_json_field(value):
                if isinstance(value, (list, dict)):
                    return value
                if isinstance(value, str):
                    try:
                        import json
                        return json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        return []
                return []
            
            # Create doctor profile
            profile_data = {
                'user': user,
                'license_number': request.data['license_number'],
                'qualification': request.data['qualification'],
                'specialization': request.data['specialization'],
                'sub_specialization': request.data.get('sub_specialization', ''),
                'consultation_fee': request.data['consultation_fee'],
                'online_consultation_fee': request.data.get('online_consultation_fee', request.data['consultation_fee']),
                'experience_years': request.data.get('experience_years', 0),
                'clinic_name': request.data.get('clinic_name', ''),
                'clinic_address': request.data.get('clinic_address', ''),
                'bio': request.data.get('bio', ''),
                'languages_spoken': parse_json_field(request.data.get('languages_spoken', [])),
                'consultation_duration': request.data.get('consultation_duration', 5),
                'is_online_consultation_available': parse_boolean(request.data.get('is_online_consultation_available', True)),
                'is_verified': True,  # SuperAdmin-created profiles are pre-verified
                'is_active': parse_boolean(request.data.get('is_active', True)),
                'is_accepting_patients': True,
                'date_of_birth': request.data.get('date_of_birth'),
                'date_of_anniversary': request.data.get('date_of_anniversary'),
            }
            
            doctor_profile = DoctorProfile.objects.create(**profile_data)
            
            serializer = DoctorProfileSerializer(doctor_profile)
            return Response({
                'success': True,
                'data': {
                    'doctor_profile': serializer.data,
                    'user_account': {
                        'user_id': user.id,
                        'phone': user.phone,
                        'name': user.name,
                        'email': user.email,
                        'role': user.role,
                        'password': password
                    }
                },
                'message': 'Doctor account and profile created successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CREATION_ERROR',
                    'message': f'Error creating doctor: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SuperAdminDoctorDetailView(APIView):
    """SuperAdmin endpoints for individual doctor management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Allow admin and superadmin to access"""
        if not self.request.user.is_authenticated:
            return [permissions.IsAdminUser()]
        
        user_role = getattr(self.request.user, 'role', None)
        if user_role in ['admin', 'superadmin']:
            return [permissions.IsAuthenticated()]
        else:
            return [permissions.IsAdminUser()]
    
    @extend_schema(
        responses={200: DoctorProfileSerializer},
        description="Get doctor details by ID (SuperAdmin only)"
    )
    def get(self, request, doctor_id):
        """Get doctor details by ID"""
        try:
            # doctor_id is actually the User ID (e.g., DOC018)
            doctor = DoctorProfile.objects.select_related('user').get(user__id=doctor_id)
            serializer = DoctorProfileSerializer(doctor)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Doctor details retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        except DoctorProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'DOCTOR_NOT_FOUND',
                    'message': f'Doctor with User ID {doctor_id} not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        request={
            'name': OpenApiTypes.STR,
            'phone': OpenApiTypes.STR,
            'email': OpenApiTypes.STR,
            'profile_picture': OpenApiTypes.BINARY,
            'license_number': OpenApiTypes.STR,
            'qualification': OpenApiTypes.STR,
            'specialization': OpenApiTypes.STR,
            'sub_specialization': OpenApiTypes.STR,
            'consultation_fee': OpenApiTypes.NUMBER,
            'online_consultation_fee': OpenApiTypes.NUMBER,
            'experience_years': OpenApiTypes.INT,
            'clinic_name': OpenApiTypes.STR,
            'clinic_address': OpenApiTypes.STR,
            'bio': OpenApiTypes.STR,
            'languages_spoken': OpenApiTypes.STR,
            'consultation_duration': OpenApiTypes.INT,
            'is_online_consultation_available': OpenApiTypes.BOOL,
            'is_active': OpenApiTypes.BOOL,
            'date_of_birth': OpenApiTypes.STR,
            'date_of_anniversary': OpenApiTypes.STR,
        },
        responses={200: DoctorProfileSerializer},
        description="Update doctor profile (SuperAdmin only)"
    )
    def put(self, request, doctor_id):
        """Update doctor profile"""
        try:
            # doctor_id is actually the User ID (e.g., DOC018)
            doctor = DoctorProfile.objects.select_related('user').get(user__id=doctor_id)
            
            # Update user fields if present in request
            user = doctor.user
            user_updated = False
            
            if 'name' in request.data:
                user.name = request.data['name']
                user_updated = True
            if 'phone' in request.data:
                user.phone = request.data['phone']
                user_updated = True
            if 'email' in request.data:
                user.email = request.data['email']
                user_updated = True
            
            # Handle profile picture update
            if 'profile_picture' in request.FILES:
                user.profile_picture = request.FILES['profile_picture']
                user_updated = True
            
            if user_updated:
                user.save()
            
            # Helper function to parse JSON strings
            def parse_json_field(value):
                if isinstance(value, (list, dict)):
                    return value
                if isinstance(value, str):
                    try:
                        import json
                        return json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        return []
                return []
            
            # Helper function to convert string boolean to actual boolean
            def parse_boolean(value):
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on']
                return bool(value)
            
            # Update doctor profile fields manually
            if 'license_number' in request.data:
                doctor.license_number = request.data['license_number']
            if 'qualification' in request.data:
                doctor.qualification = request.data['qualification']
            if 'specialization' in request.data:
                doctor.specialization = request.data['specialization']
            if 'sub_specialization' in request.data:
                doctor.sub_specialization = request.data['sub_specialization']
            if 'consultation_fee' in request.data:
                doctor.consultation_fee = request.data['consultation_fee']
            if 'online_consultation_fee' in request.data:
                doctor.online_consultation_fee = request.data['online_consultation_fee']
            if 'experience_years' in request.data:
                doctor.experience_years = request.data['experience_years']
            if 'clinic_name' in request.data:
                doctor.clinic_name = request.data['clinic_name']
            if 'clinic_address' in request.data:
                doctor.clinic_address = request.data['clinic_address']
            if 'bio' in request.data:
                doctor.bio = request.data['bio']
            if 'languages_spoken' in request.data:
                doctor.languages_spoken = parse_json_field(request.data['languages_spoken'])
            if 'consultation_duration' in request.data:
                doctor.consultation_duration = request.data['consultation_duration']
            if 'is_online_consultation_available' in request.data:
                doctor.is_online_consultation_available = parse_boolean(request.data['is_online_consultation_available'])
            if 'is_active' in request.data:
                doctor.is_active = parse_boolean(request.data['is_active'])
            if 'date_of_birth' in request.data:
                doctor.date_of_birth = request.data['date_of_birth']
            if 'date_of_anniversary' in request.data:
                doctor.date_of_anniversary = request.data['date_of_anniversary']
            
            doctor.save()
            
            serializer = DoctorProfileSerializer(doctor)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Doctor profile updated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except DoctorProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'DOCTOR_NOT_FOUND',
                    'message': 'Doctor not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        responses={200: dict},
        description="Delete doctor (SuperAdmin only)"
    )
    def delete(self, request, doctor_id):
        """Delete doctor"""
        try:
            # doctor_id is actually the User ID (e.g., DOC018)
            doctor = DoctorProfile.objects.get(user__id=doctor_id)
            user = doctor.user
            
            # Hard delete - permanently remove the doctor profile and user account
            doctor.delete()
            user.delete()
            
            return Response({
                'success': True,
                'data': {
                    'doctor_id': doctor_id,
                    'user_id': user.id,
                    'status': 'deleted'
                },
                'message': 'Doctor deleted successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except DoctorProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'DOCTOR_NOT_FOUND',
                    'message': f'Doctor with User ID {doctor_id} not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)


class DoctorStatusListView(APIView):
    """View for listing all doctor statuses (SuperAdmin only)"""
    
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSuperAdmin]
    
    @extend_schema(
        summary="Get all doctor statuses",
        description="Retrieve real-time status of all doctors",
        responses={200: DoctorStatusListSerializer(many=True)},
        tags=["Doctor Status"]
    )
    def get(self, request):
        try:
            # Get all doctor statuses with doctor info
            statuses = DoctorStatus.objects.select_related('doctor', 'doctor__user').all()
            
            # Apply filters if provided
            status_filter = request.query_params.get('status')
            if status_filter:
                statuses = statuses.filter(current_status=status_filter)
            
            online_filter = request.query_params.get('online')
            if online_filter is not None:
                is_online = online_filter.lower() == 'true'
                statuses = statuses.filter(is_online=is_online)
            
            available_filter = request.query_params.get('available')
            if available_filter is not None:
                is_available = available_filter.lower() == 'true'
                statuses = statuses.filter(is_available=is_available)
            
            # Order by last activity (most recent first)
            statuses = statuses.order_by('-last_activity')
            
            serializer = DoctorStatusListSerializer(statuses, many=True)
            
            return Response({
                'status': 'success',
                'message': 'Doctor statuses retrieved successfully',
                'data': serializer.data,
                'count': len(serializer.data),
                'online_count': statuses.filter(is_online=True).count(),
                'available_count': statuses.filter(is_available=True).count(),
                'consulting_count': statuses.filter(current_status='consulting').count()
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to retrieve doctor statuses: {str(e)}'
            }, status=500)


class DoctorStatusDetailView(APIView):
    """View for individual doctor status details"""
    
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSuperAdmin]
    
    @extend_schema(
        summary="Get doctor status details",
        description="Retrieve detailed status information for a specific doctor",
        responses={200: DoctorStatusSerializer},
        tags=["Doctor Status"]
    )
    def get(self, request, doctor_id):
        try:
            # Get doctor status
            try:
                status = DoctorStatus.objects.select_related(
                    'doctor', 'doctor__user', 'current_consultation', 'current_consultation__patient'
                ).get(doctor_id=doctor_id)
            except DoctorStatus.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Doctor status not found'
                }, status=404)
            
            serializer = DoctorStatusSerializer(status)
            
            return Response({
                'status': 'success',
                'message': 'Doctor status retrieved successfully',
                'data': serializer.data
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to retrieve doctor status: {str(e)}'
            }, status=500)


class DoctorStatusUpdateView(APIView):
    """View for doctors to update their own status"""
    
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Update doctor status",
        description="Update current status, availability, and status note",
        request=DoctorStatusUpdateSerializer,
        responses={200: DoctorStatusSerializer},
        tags=["Doctor Status"]
    )
    def put(self, request):
        try:
            # Get doctor's status
            try:
                status = DoctorStatus.objects.get(doctor=request.user.doctor)
            except DoctorStatus.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Doctor status not found'
                }, status=404)
            
            serializer = DoctorStatusUpdateSerializer(status, data=request.data, partial=True, context={'request': request})
            
            if serializer.is_valid():
                serializer.save()
                
                # Update activity timestamp
                status.update_activity()
                
                # Return updated status
                full_serializer = DoctorStatusSerializer(status)
                
                # Broadcast the update to all connected WebSocket clients
                broadcast_doctor_status_update(full_serializer.data)
                
                return Response({
                    'status': 'success',
                    'message': 'Status updated successfully',
                    'data': full_serializer.data
                })
            else:
                return Response({
                    'status': 'error',
                    'message': 'Invalid data provided',
                    'errors': serializer.errors
                }, status=400)
                
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to update status: {str(e)}'
            }, status=500)


class DoctorStatusStatsView(APIView):
    """View for getting doctor status statistics"""
    
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSuperAdmin]
    
    @extend_schema(
        summary="Get doctor status statistics",
        description="Retrieve statistics about doctor statuses",
        responses={200: None},
        tags=["Doctor Status"]
    )
    def get(self, request):
        try:
            total_doctors = DoctorStatus.objects.count()
            online_doctors = DoctorStatus.objects.filter(is_online=True).count()
            available_doctors = DoctorStatus.objects.filter(is_available=True).count()
            consulting_doctors = DoctorStatus.objects.filter(current_status='consulting').count()
            away_doctors = DoctorStatus.objects.filter(current_status='away').count()
            offline_doctors = DoctorStatus.objects.filter(current_status='offline').count()
            
            # Status breakdown
            status_breakdown = {}
            for status_choice in DoctorStatus.STATUS_CHOICES:
                status_breakdown[status_choice[0]] = DoctorStatus.objects.filter(
                    current_status=status_choice[0]
                ).count()
            
            # Recent activity (doctors active in last 24 hours)
            from datetime import timedelta
            yesterday = timezone.now() - timedelta(days=1)
            recent_activity = DoctorStatus.objects.filter(
                last_activity__gte=yesterday
            ).count()
            
            stats = {
                'total_doctors': total_doctors,
                'online_doctors': online_doctors,
                'available_doctors': available_doctors,
                'consulting_doctors': consulting_doctors,
                'away_doctors': away_doctors,
                'offline_doctors': offline_doctors,
                'recent_activity': recent_activity,
                'status_breakdown': status_breakdown,
                'online_percentage': round((online_doctors / total_doctors * 100) if total_doctors > 0 else 0, 1),
                'available_percentage': round((available_doctors / total_doctors * 100) if total_doctors > 0 else 0, 1)
            }
            
            return Response({
                'status': 'success',
                'message': 'Doctor status statistics retrieved successfully',
                'data': stats
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to retrieve statistics: {str(e)}'
            }, status=500)


class DoctorStatusOfflineView(APIView):
    """View for doctors to mark themselves as offline"""
    
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Mark doctor as offline",
        description="Mark the current doctor as offline (useful when closing browser/tab)",
        responses={200: dict},
        tags=["Doctor Status"]
    )
    def post(self, request):
        try:
            # Get doctor's status
            try:
                status = DoctorStatus.objects.get(doctor=request.user.doctor)
            except DoctorStatus.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Doctor status not found'
                }, status=404)
            
            # Mark as offline
            status.is_online = False
            status.is_logged_in = False
            status.current_status = 'offline'
            status.last_logout = timezone.now()
            status.last_activity = timezone.now()
            status.save()
            
            # Broadcast the update
            broadcast_doctor_status_update(status)
            
            return Response({
                'status': 'success',
                'message': 'Marked as offline successfully'
            })
                
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to mark as offline: {str(e)}'
            }, status=500)


def broadcast_doctor_status_update(status_data):
    """Broadcast doctor status update to all connected WebSocket clients"""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "doctor_status_updates",
        {
            "type": "status_update",
            "data": status_data
        }
    )

def broadcast_notification(user_id, notification_data):
    """Broadcast notification to specific user"""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"notifications_{user_id}",
        {
            "type": "notification_message",
            "data": notification_data
        }
    )

def broadcast_consultation_update(consultation_data):
    """Broadcast consultation update to all connected clients"""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "consultation_updates",
        {
            "type": "consultation_update",
            "data": consultation_data
        }
    )


@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_superadmin_doctor_detail(request, doctor_id):
    """Test endpoint to view superadmin doctor details without authentication (development only)"""
    try:
        # doctor_id is actually the User ID (e.g., DOC018)
        doctor = DoctorProfile.objects.get(user__id=doctor_id)
        serializer = DoctorProfileSerializer(doctor)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'SuperAdmin doctor details retrieved successfully (test endpoint)',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    except DoctorProfile.DoesNotExist:
        return Response({
            'success': False,
            'error': {
                'code': 'DOCTOR_NOT_FOUND',
                'message': f'Doctor with User ID {doctor_id} not found'
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

@api_view(['GET'])
@permission_classes([])  # No authentication required for testing
def test_doctor_detail(request, doctor_id):
    """Test endpoint to view doctor details without authentication (development only)"""
    try:
        # doctor_id is actually the User ID (e.g., DOC018)
        doctor = DoctorProfile.objects.get(user__id=doctor_id)
        serializer = DoctorProfileSerializer(doctor)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Doctor profile retrieved successfully (test endpoint)',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    except DoctorProfile.DoesNotExist:
        return Response({
            'success': False,
            'error': {
                'code': 'DOCTOR_NOT_FOUND',
                'message': f'Doctor with User ID {doctor_id} not found'
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

class PublicDoctorListView(APIView):
    """Public endpoint for listing doctors (no authentication required)"""
    permission_classes = [permissions.AllowAny]
    pagination_class = DoctorPagination
    
    @extend_schema(
        parameters=[
            OpenApiParameter('search', OpenApiTypes.STR, description='Search by doctor name or specialization'),
            OpenApiParameter('specialization', OpenApiTypes.STR, description='Filter by specialization'),
            OpenApiParameter('pincode', OpenApiTypes.STR, description='Filter by pincode'),
            OpenApiParameter('city', OpenApiTypes.STR, description='Filter by city'),
            OpenApiParameter('min_experience', OpenApiTypes.INT, description='Minimum experience years'),
            OpenApiParameter('max_experience', OpenApiTypes.INT, description='Maximum experience years'),
            OpenApiParameter('min_fee', OpenApiTypes.NUMBER, description='Minimum consultation fee'),
            OpenApiParameter('max_fee', OpenApiTypes.NUMBER, description='Maximum consultation fee'),
            OpenApiParameter('rating_min', OpenApiTypes.NUMBER, description='Minimum rating'),
            OpenApiParameter('consultation_type', OpenApiTypes.STR, description='Consultation type: in_person, online, both'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Items per page'),
            OpenApiParameter('ordering', OpenApiTypes.STR, description='Order by: rating, experience, fee, name'),
        ],
        responses={200: PublicDoctorListSerializer(many=True)},
        description="Public endpoint to list verified and active doctors with filtering"
    )
    def get(self, request):
        """List public doctors with filtering and pagination"""
        try:
            # Base queryset - only verified and active doctors
            queryset = DoctorProfile.objects.select_related('user').filter(
                is_verified=True, 
                is_active=True
            )
            
            # Apply filters
            search = request.query_params.get('search', '')
            if search:
                queryset = queryset.filter(
                    Q(user__name__icontains=search) |
                    Q(specialization__icontains=search) |
                    Q(qualification__icontains=search)
                )
            
            specialization = request.query_params.get('specialization', '')
            if specialization:
                queryset = queryset.filter(specialization__icontains=specialization)
            
            pincode = request.query_params.get('pincode', '')
            if pincode:
                queryset = queryset.filter(clinic_address__icontains=pincode)
            
            city = request.query_params.get('city', '')
            if city:
                queryset = queryset.filter(clinic_address__icontains=city)
            
            min_experience = request.query_params.get('min_experience')
            if min_experience:
                queryset = queryset.filter(experience_years__gte=int(min_experience))
            
            max_experience = request.query_params.get('max_experience')
            if max_experience:
                queryset = queryset.filter(experience_years__lte=int(max_experience))
            
            min_fee = request.query_params.get('min_fee')
            if min_fee:
                queryset = queryset.filter(consultation_fee__gte=float(min_fee))
            
            max_fee = request.query_params.get('max_fee')
            if max_fee:
                queryset = queryset.filter(consultation_fee__lte=float(max_fee))
            
            rating_min = request.query_params.get('rating_min')
            if rating_min:
                queryset = queryset.filter(rating__gte=float(rating_min))
            
            consultation_type = request.query_params.get('consultation_type')
            if consultation_type:
                if consultation_type == 'online':
                    queryset = queryset.filter(is_online_consultation_available=True)
                elif consultation_type == 'in_person':
                    queryset = queryset.filter(is_online_consultation_available=False)
                # 'both' means no filter applied
            
            # Apply ordering
            ordering = request.query_params.get('ordering', 'rating')
            if ordering == 'rating':
                queryset = queryset.order_by('-rating', '-total_reviews')
            elif ordering == 'experience':
                queryset = queryset.order_by('-experience_years')
            elif ordering == 'fee':
                queryset = queryset.order_by('consultation_fee')
            elif ordering == 'name':
                queryset = queryset.order_by('user__name')
            else:
                queryset = queryset.order_by('-rating', '-total_reviews')
            
            # Apply pagination
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            if page is not None:
                serializer = PublicDoctorListSerializer(page, many=True)
                return paginator.get_paginated_response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'Doctors retrieved successfully',
                    'timestamp': timezone.now().isoformat()
                })
            
            # If no pagination
            serializer = PublicDoctorListSerializer(queryset, many=True)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Doctors retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'FETCH_ERROR',
                    'message': f'Failed to fetch doctors: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminSlotsView(APIView):
    """View for admins to access all doctor slots"""
    permission_classes = [IsAdminOrSuperAdmin]
    
    def get(self, request):
        """Get all doctor slots with optional filtering"""
        try:
            # Get all doctor slots
            queryset = DoctorSlot.objects.select_related('doctor').all()
            
            # Apply filters
            date_param = request.query_params.get('date')
            month = request.query_params.get('month')
            year = request.query_params.get('year')
            doctor_id = request.query_params.get('doctor_id')
            
            if date_param:
                queryset = queryset.filter(date=date_param)
            elif month and year:
                queryset = queryset.filter(date__year=year, date__month=month)
            
            if doctor_id:
                queryset = queryset.filter(doctor_id=doctor_id)
            
            # Order by date and start time
            queryset = queryset.order_by('date', 'start_time')
            
            # Serialize the data
            serializer = DoctorSlotSerializer(queryset, many=True)
            
            return Response({
                'success': True,
                'data': serializer.data,
                'message': f'All doctor slots retrieved for admin {request.user.name}',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'FETCH_ERROR',
                    'message': f'Failed to fetch doctor slots: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

