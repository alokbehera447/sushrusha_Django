from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django.utils import timezone
from django.contrib.auth import update_session_auth_hash
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from django.db.models import Q
from django.db.models import Sum
from datetime import timedelta
import threading

# In-memory storage for OTP (fallback for testing)
_otp_storage = {}
_otp_storage_lock = threading.Lock()

from .models import User, UserSession
from .serializers import (
    SendOTPSerializer, VerifyOTPSerializer, UserProfileSerializer,
    UpdateProfileSerializer, AdminUpdateUserSerializer, RefreshTokenSerializer, LogoutSerializer,
    ChangePasswordSerializer, UserSessionSerializer
)

class SendOTPView(APIView):
    """Send OTP to user's phone number"""
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        request=SendOTPSerializer,
        responses={200: dict, 400: dict},
        description="Send OTP to user's phone number for authentication"
    )
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            result = serializer.save()
            return Response({
                'success': True,
                'data': {
                    'phone': result['phone'],
                    'expires_in': result['expires_in']
                },
                'message': result['message'],
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid phone number format',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """Verify OTP and login user"""
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        request=VerifyOTPSerializer,
        responses={200: dict, 401: dict},
        description="Verify OTP and authenticate user, returns JWT tokens"
    )
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            is_new_user = serializer.validated_data['is_new_user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Create user session
            device_info = request.META.get('HTTP_USER_AGENT', '')[:255]
            ip_address = self.get_client_ip(request)
            
            UserSession.objects.create(
                user=user,
                refresh_token=str(refresh),
                device_info=device_info,
                ip_address=ip_address
            )
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Update doctor status if user is a doctor
            if user.role == 'doctor':
                try:
                    from doctors.models import DoctorProfile, DoctorStatus
                    doctor_profile = DoctorProfile.objects.get(user=user)
                    doctor_status, created = DoctorStatus.objects.get_or_create(
                        doctor=doctor_profile,
                        defaults={
                            'is_online': True,
                            'is_logged_in': True,
                            'is_available': True,
                            'current_status': 'available',
                            'last_login': timezone.now(),
                            'last_activity': timezone.now(),
                        }
                    )
                    
                    if not created:
                        # Update existing status
                        doctor_status.is_online = True
                        doctor_status.is_logged_in = True
                        doctor_status.is_available = True
                        doctor_status.current_status = 'available'
                        doctor_status.last_login = timezone.now()
                        doctor_status.last_activity = timezone.now()
                        doctor_status.save()
                        
                except DoctorProfile.DoesNotExist:
                    # Doctor profile doesn't exist yet, skip
                    pass
            
            # Prepare user data based on role
            user_data = {
                'id': user.id,
                'phone': user.phone,
                'role': user.role,
                'name': user.name,
                'profile': self.get_profile_data(user)
            }
            
            # Determine message based on whether it's a new user or login
            message = 'Registration successful' if is_new_user else 'Login successful'
            
            return Response({
                'success': True,
                'data': {
                    'access': str(access_token),
                    'refresh': str(refresh),
                    'user': user_data
                },
                'message': message,
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'INVALID_OTP',
                'message': 'Invalid or expired OTP',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_profile_data(self, user):
        """Get profile data based on user role"""
        if user.role == 'patient':
            return {
                'date_of_birth': user.date_of_birth,
                'gender': user.gender,
                'address': {
                    'street': user.street,
                    'city': user.city,
                    'state': user.state,
                    'pincode': user.pincode
                },
                'emergency_contact': {
                    'name': user.emergency_contact_name,
                    'phone': user.emergency_contact_phone,
                    'relationship': user.emergency_contact_relationship
                },
                'blood_group': user.blood_group,
                'allergies': user.allergies
            }
        elif user.role == 'doctor':
            doctor_profile = getattr(user, 'doctor_profile', None)
            if doctor_profile:
                return {
                    'license_number': doctor_profile.license_number,
                    'qualification': doctor_profile.qualification,
                    'specialization': doctor_profile.specialization,
                    'experience_years': doctor_profile.experience_years,
                    'consultation_fee': doctor_profile.consultation_fee,
                    'rating': doctor_profile.rating,
                    'total_consultations': doctor_profile.total_consultations
                }
        return {}


class CustomTokenRefreshView(TokenRefreshView):
    """Custom token refresh view with proper response format"""
    
    @extend_schema(
        request=RefreshTokenSerializer,
        responses={200: dict, 401: dict},
        description="Refresh access token using refresh token"
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            return Response({
                'success': True,
                'data': {
                    'access': response.data['access']
                },
                'message': 'Token refreshed successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'INVALID_REFRESH_TOKEN',
                'message': 'Invalid or expired refresh token'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_401_UNAUTHORIZED)


class ProfileView(APIView):
    """Get and update user profile"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: UserProfileSerializer},
        description="Get current user's profile information"
    )
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Profile fetched successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        request=UpdateProfileSerializer,
        responses={200: UserProfileSerializer},
        description="Update current user's profile information"
    )
    def put(self, request):
        serializer = UpdateProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            profile_serializer = UserProfileSerializer(request.user)
            return Response({
                'success': True,
                'data': profile_serializer.data,
                'message': 'Profile updated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid data provided',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """Logout user by blacklisting refresh token"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        request=LogoutSerializer,
        responses={200: dict},
        description="Logout user by invalidating refresh token"
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            
            # Deactivate user session
            refresh_token = request.data.get('refresh')
            UserSession.objects.filter(
                user=request.user,
                refresh_token=refresh_token
            ).update(is_active=False)
            
            # Update doctor status if user is a doctor
            if request.user.role == 'doctor':
                try:
                    from doctors.models import DoctorProfile, DoctorStatus
                    doctor_profile = DoctorProfile.objects.get(user=request.user)
                    doctor_status = DoctorStatus.objects.get(doctor=doctor_profile)
                    doctor_status.is_online = False
                    doctor_status.is_logged_in = False
                    doctor_status.current_status = 'offline'
                    doctor_status.last_logout = timezone.now()
                    doctor_status.last_activity = timezone.now()
                    doctor_status.save()
                        
                except (DoctorProfile.DoesNotExist, DoctorStatus.DoesNotExist):
                    # Doctor profile or status doesn't exist, skip
                    pass
            
            return Response({
                'success': True,
                'message': 'Logged out successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'INVALID_TOKEN',
                'message': 'Invalid refresh token',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """Change user password"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        request=ChangePasswordSerializer,
        responses={200: dict, 400: dict},
        description="Change user password"
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Update session auth hash to prevent logout
            update_session_auth_hash(request, user)
            
            # Invalidate all other sessions
            UserSession.objects.filter(user=user).update(is_active=False)
            
            return Response({
                'success': True,
                'message': 'Password changed successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid data provided',
                'details': serializer.errors
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)


class UserSessionsView(APIView):
    """Manage user sessions"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: UserSessionSerializer(many=True)},
        description="Get user's active sessions"
    )
    def get(self, request):
        sessions = UserSession.objects.filter(user=request.user, is_active=True)
        serializer = UserSessionSerializer(sessions, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Sessions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @extend_schema(
        request={'session_id': OpenApiTypes.STR},
        responses={200: dict},
        description="Terminate a specific session"
    )
    def delete(self, request):
        session_id = request.data.get('session_id')
        if session_id:
            UserSession.objects.filter(
                user=request.user,
                id=session_id
            ).update(is_active=False)
            
            return Response({
                'success': True,
                'message': 'Session terminated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'error': {
                'code': 'MISSING_SESSION_ID',
                'message': 'Session ID is required'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)


class AdminUserManagementView(APIView):
    """Admin endpoints for user management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Only admin and superadmin can access"""
        # Check if user is authenticated and has the required role
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) not in ['admin', 'superadmin']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        request={
            'phone': OpenApiTypes.STR,
            'name': OpenApiTypes.STR,
            'email': OpenApiTypes.STR,
            'role': OpenApiTypes.STR,
            'password': OpenApiTypes.STR,
        },
        responses={201: dict, 400: dict, 403: dict},
        description="Create new user account (Admin only)"
    )
    def post(self, request):
        """Create new user account"""
        # Validate required fields
        required_fields = ['phone', 'name', 'role']
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
        
        # Validate role
        valid_roles = ['patient', 'doctor', 'admin']
        if request.data['role'] not in valid_roles:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_ROLE',
                    'message': f'Role must be one of: {", ".join(valid_roles)}'
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
        
        try:
            # Create user
            user_data = {
                'phone': request.data['phone'],
                'name': request.data['name'],
                'role': request.data['role'],
                'email': request.data.get('email', ''),
                'is_verified': True,  # Admin-created users are pre-verified
            }
            
            # Add additional user fields if provided
            if 'date_of_birth' in request.data:
                user_data['date_of_birth'] = request.data['date_of_birth']
            if 'gender' in request.data:
                user_data['gender'] = request.data['gender']
            if 'blood_group' in request.data:
                user_data['blood_group'] = request.data['blood_group']
            if 'allergies' in request.data:
                user_data['allergies'] = request.data['allergies']
            if 'medical_history' in request.data:
                user_data['medical_history'] = request.data['medical_history']
            if 'street' in request.data:
                user_data['street'] = request.data['street']
            if 'city' in request.data:
                user_data['city'] = request.data['city']
            if 'state' in request.data:
                user_data['state'] = request.data['state']
            if 'pincode' in request.data:
                user_data['pincode'] = request.data['pincode']
            if 'country' in request.data:
                user_data['country'] = request.data['country']
            if 'emergency_contact_name' in request.data:
                user_data['emergency_contact_name'] = request.data['emergency_contact_name']
            if 'emergency_contact_phone' in request.data:
                user_data['emergency_contact_phone'] = request.data['emergency_contact_phone']
            if 'emergency_contact_relationship' in request.data:
                user_data['emergency_contact_relationship'] = request.data['emergency_contact_relationship']
            
            # Set password if provided, otherwise generate random password
            password = request.data.get('password')
            if not password:
                import secrets
                password = secrets.token_urlsafe(8)
            
            user = User.objects.create_user(**user_data)
            user.set_password(password)
            user.save()
            
            # Create patient profile if role is patient
            patient_profile = None
            if user.role == 'patient':
                from patients.models import PatientProfile
                
                patient_data = {
                    'user': user,
                    'blood_group': request.data.get('blood_group', ''),
                    'allergies': request.data.get('allergies', ''),
                    'chronic_conditions': request.data.get('chronic_conditions', []),
                    'current_medications': request.data.get('current_medications', []),
                    'insurance_provider': request.data.get('insurance_provider', ''),
                    'insurance_policy_number': request.data.get('insurance_policy_number', ''),
                    'insurance_expiry': request.data.get('insurance_expiry'),
                    'preferred_language': request.data.get('preferred_language', 'English'),
                }
                
                patient_profile = PatientProfile.objects.create(**patient_data)
                
                # Assign to clinic if created by admin (for deployed server compatibility)
                try:
                    if request.user.is_authenticated and request.user.role == 'admin':
                        admin_clinic = getattr(request.user, 'administered_clinic', None)
                        if admin_clinic:
                            # Create ClinicPatient record
                            from eclinic.models import ClinicPatient
                            ClinicPatient.objects.create(
                                patient=user,
                                clinic=admin_clinic,
                                registration_source='admin_created',
                                is_active=True
                            )
                except Exception as e:
                    print(f"Error creating ClinicPatient: {e}")
            
            return Response({
                'success': True,
                'data': {
                    'user_id': user.id,
                    'phone': user.phone,
                    'name': user.name,
                    'role': user.role,
                    'email': user.email,
                    'password': password if not request.data.get('password') else '***',
                    'patient_profile': patient_profile.id if patient_profile else None
                },
                'message': f'{user.get_role_display()} account created successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CREATION_ERROR',
                    'message': f'Error creating user: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        responses={200: dict},
        description="List all users (Admin only)"
    )
    def get(self, request):
        """List all users"""
        # Check if this is a request for admin list specifically
        if request.query_params.get('type') == 'admins':
            return self.get_admin_list(request)
        
        role_filter = request.query_params.get('role')
        search_query = request.query_params.get('search')
        
        queryset = User.objects.all()
        
        # Apply role filter
        if role_filter:
            queryset = queryset.filter(role=role_filter)
        
        # Apply search filter
        if search_query:
            queryset = queryset.filter(
                Q(name__icontains=search_query) |
                Q(phone__icontains=search_query) |
                Q(email__icontains=search_query)
            )
        
        # Paginate results
        # The original code had pagination here, but UserPagination was removed.
        # Assuming the intent was to return all users if no pagination is applied.
        # For now, we'll return all users.
        serializer = UserProfileSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Users retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    def get_admin_list(self, request):
        """Get all admin users for e-clinic assignment"""
        if request.user.role != 'superadmin':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only SuperAdmin can access admin list'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        admins = User.objects.filter(role='admin', is_active=True).order_by('name')
        serializer = UserProfileSerializer(admins, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Admin list retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class AdminUserDetailView(APIView):
    """Admin endpoints for specific user management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Only admin and superadmin can access"""
        # Check if user is authenticated and has the required role
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) not in ['admin', 'superadmin']:
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        responses={200: dict, 404: dict},
        description="Get specific user details (Admin only)"
    )
    def get(self, request, user_id):
        """Get specific user details"""
        try:
            user = User.objects.get(id=user_id)
            serializer = UserProfileSerializer(user)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'User details retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        request=AdminUpdateUserSerializer,
        responses={200: dict, 400: dict, 404: dict},
        description="Update user details (Admin only)"
    )
    def put(self, request, user_id):
        """Update user details"""
        try:
            user = User.objects.get(id=user_id)
            serializer = AdminUpdateUserSerializer(user, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'User updated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            
            return Response({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Invalid data provided',
                    'details': serializer.errors
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        responses={200: dict, 404: dict},
        description="Delete user account (Admin only)"
    )
    def delete(self, request, user_id):
        """Delete user account"""
        try:
            user = User.objects.get(id=user_id)
            
            # Prevent admin from deleting themselves
            if user == request.user:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'SELF_DELETE',
                        'message': 'Cannot delete your own account'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.delete()
            return Response({
                'success': True,
                'message': 'User deleted successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)


class AdminManagementView(APIView):
    """Comprehensive admin account management for SuperAdmin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Only superadmin can access admin management"""
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) != 'superadmin':
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        request={
            'phone': OpenApiTypes.STR,
            'name': OpenApiTypes.STR,
            'email': OpenApiTypes.STR,
            'password': OpenApiTypes.STR,
            'is_active': OpenApiTypes.BOOL,
            'permissions': OpenApiTypes.OBJECT,
        },
        responses={201: dict, 400: dict, 403: dict},
        description="Create new admin account (SuperAdmin only)"
    )
    def post(self, request):
        """Create new admin account"""
        # Validate required fields
        required_fields = ['phone', 'name']
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
        
        try:
            # Create admin user
            user_data = {
                'phone': request.data['phone'],
                'name': request.data['name'],
                'role': 'admin',  # Always create as admin
                'email': request.data.get('email', ''),
                'is_verified': True,  # Admin-created users are pre-verified
                'is_active': request.data.get('is_active', True),
            }
            
            # Set password if provided, otherwise generate random password
            password = request.data.get('password')
            if not password:
                import secrets
                password = secrets.token_urlsafe(8)
            
            user = User.objects.create_user(**user_data)
            user.set_password(password)
            user.save()
            
            return Response({
                'success': True,
                'data': {
                    'user_id': user.id,
                    'phone': user.phone,
                    'name': user.name,
                    'role': user.role,
                    'email': user.email,
                    'is_active': user.is_active,
                    'password': password if not request.data.get('password') else '***',
                    'date_joined': user.date_joined.isoformat()
                },
                'message': 'Admin account created successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CREATION_ERROR',
                    'message': f'Error creating admin: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        parameters=[
            OpenApiParameter('search', OpenApiTypes.STR, description='Search by name, phone, or email'),
            OpenApiParameter('status', OpenApiTypes.STR, description='Filter by status: active, all (inactive removed since we use hard delete)'),
            OpenApiParameter('sort_by', OpenApiTypes.STR, description='Sort by: name, date_joined, last_login'),
            OpenApiParameter('sort_order', OpenApiTypes.STR, description='Sort order: asc, desc'),
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number'),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Items per page'),
        ],
        responses={200: dict},
        description="List all admin accounts with search and filters (SuperAdmin only)"
    )
    def get(self, request):
        """List all admin accounts with search and filters"""
        # Get query parameters
        search_query = request.query_params.get('search', '')
        status_filter = request.query_params.get('status', 'all')
        sort_by = request.query_params.get('sort_by', 'date_joined')
        sort_order = request.query_params.get('sort_order', 'desc')
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        
        # Build queryset
        queryset = User.objects.filter(role='admin')
        
        # Apply status filter (only active since we use hard delete now)
        if status_filter == 'active':
            queryset = queryset.filter(is_active=True)
        # Note: 'inactive' filter removed since we now use hard delete
        
        # Apply search filter
        if search_query:
            queryset = queryset.filter(
                Q(name__icontains=search_query) |
                Q(phone__icontains=search_query) |
                Q(email__icontains=search_query)
            )
        
        # Apply sorting
        if sort_by in ['name', 'date_joined', 'last_login']:
            order_field = sort_by
            if sort_order == 'desc':
                order_field = f'-{order_field}'
            queryset = queryset.order_by(order_field)
        else:
            queryset = queryset.order_by('-date_joined')
        
        # Pagination
        total_count = queryset.count()
        start = (page - 1) * page_size
        end = start + page_size
        admins = queryset[start:end]
        
        # Serialize data
        admin_data = []
        for admin in admins:
            admin_data.append({
                'id': admin.id,
                'name': admin.name,
                'phone': admin.phone,
                'email': admin.email,
                'is_active': admin.is_active,
                'is_verified': admin.is_verified,
                'date_joined': admin.date_joined.isoformat(),
                'last_login': admin.last_login.isoformat() if admin.last_login else None,
                'profile_picture': admin.profile_picture.url if admin.profile_picture else None,
            })
        
        return Response({
            'success': True,
            'data': {
                'admins': admin_data,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_count': total_count,
                    'total_pages': (total_count + page_size - 1) // page_size,
                    'has_next': end < total_count,
                    'has_previous': page > 1
                }
            },
            'message': 'Admin accounts retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class AdminDetailView(APIView):
    """Admin account detail management for SuperAdmin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Only superadmin can access admin management"""
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) != 'superadmin':
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        responses={200: dict, 404: dict},
        description="Get specific admin account details (SuperAdmin only)"
    )
    def get(self, request, admin_id):
        """Get specific admin account details"""
        try:
            admin = User.objects.get(id=admin_id, role='admin')
            
            # Get additional statistics for this admin
            from consultations.models import Consultation
            from payments.models import Payment
            
            # Admin performance metrics
            total_consultations_managed = Consultation.objects.filter(
                created_by=admin
            ).count()
            
            total_revenue_managed = Payment.objects.filter(
                status='completed',
                consultation__created_by=admin
            ).aggregate(total=Sum('amount'))['total'] or 0
            
            # Recent activity
            from analytics.models import UserActivityLog
            recent_activity = UserActivityLog.objects.filter(
                user=admin
            ).order_by('-timestamp')[:10]
            
            admin_data = {
                'id': admin.id,
                'name': admin.name,
                'phone': admin.phone,
                'email': admin.email,
                'is_active': admin.is_active,
                'is_verified': admin.is_verified,
                'date_joined': admin.date_joined.isoformat(),
                'last_login': admin.last_login.isoformat() if admin.last_login else None,
                'profile_picture': admin.profile_picture.url if admin.profile_picture else None,
                'address': {
                    'street': admin.street,
                    'city': admin.city,
                    'state': admin.state,
                    'pincode': admin.pincode,
                    'country': admin.country,
                },
                'performance_metrics': {
                    'total_consultations_managed': total_consultations_managed,
                    'total_revenue_managed': float(total_revenue_managed),
                    'last_activity': recent_activity[0].timestamp.isoformat() if recent_activity else None,
                },
                'recent_activity': [
                    {
                        'activity_type': activity.activity_type,
                        'description': activity.description,
                        'timestamp': activity.timestamp.isoformat()
                    } for activity in recent_activity
                ]
            }
            
            return Response({
                'success': True,
                'data': admin_data,
                'message': 'Admin details retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'ADMIN_NOT_FOUND',
                    'message': 'Admin account not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        request={
            'name': OpenApiTypes.STR,
            'email': OpenApiTypes.STR,
            'is_active': OpenApiTypes.BOOL,
            'street': OpenApiTypes.STR,
            'city': OpenApiTypes.STR,
            'state': OpenApiTypes.STR,
            'pincode': OpenApiTypes.STR,
            'country': OpenApiTypes.STR,
        },
        responses={200: dict, 400: dict, 404: dict},
        description="Update admin account details (SuperAdmin only)"
    )
    def put(self, request, admin_id):
        """Update admin account details"""
        try:
            admin = User.objects.get(id=admin_id, role='admin')
            print(f"Updating admin: {admin.id}, current email: {admin.email}")
            print(f"Request data: {request.data}")
            
            serializer = UpdateProfileSerializer(admin, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                
                return Response({
                    'success': True,
                    'data': serializer.data,
                    'message': 'Admin account updated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            
            print(f"Validation errors: {serializer.errors}")
            return Response({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Invalid data provided',
                    'details': serializer.errors
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'ADMIN_NOT_FOUND',
                    'message': 'Admin account not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        responses={200: dict, 404: dict},
        description="Delete admin account (SuperAdmin only)"
    )
    def delete(self, request, admin_id):
        """Delete admin account"""
        try:
            admin = User.objects.get(id=admin_id, role='admin')
            
            # Prevent deletion of the current user
            if admin == request.user:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'SELF_DELETION',
                        'message': 'Cannot delete your own account'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Hard delete - permanently remove the admin account
            admin.delete()
            
            return Response({
                'success': True,
                'message': 'Admin account deleted successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'ADMIN_NOT_FOUND',
                    'message': 'Admin account not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)


class AdminStatsView(APIView):
    """Admin statistics and analytics for SuperAdmin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Only superadmin can access admin statistics"""
        if not self.request.user.is_authenticated or getattr(self.request.user, 'role', None) != 'superadmin':
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    @extend_schema(
        responses={200: dict},
        description="Get admin statistics and analytics (SuperAdmin only)"
    )
    def get(self, request):
        """Get admin statistics and analytics"""
        today = timezone.now().date()
        this_month_start = today.replace(day=1)
        last_month_start = (this_month_start - timedelta(days=1)).replace(day=1)
        
        # Calculate admin statistics
        total_admins = User.objects.filter(role='admin').count()
        active_admins = User.objects.filter(role='admin', is_active=True).count()
        new_this_month = User.objects.filter(
            role='admin',
            date_joined__gte=this_month_start
        ).count()
        
        # Calculate changes from last month
        last_month_admins = User.objects.filter(
            role='admin',
            date_joined__gte=last_month_start,
            date_joined__lt=this_month_start
        ).count()
        
        # Calculate performance metrics (simplified for now)
        # Since consultations don't have a created_by field, we'll use basic metrics
        admin_performance = []
        admins = User.objects.filter(role='admin', is_active=True)
        
        for admin in admins:
            # For now, use a simple performance score based on account age and activity
            days_since_joined = (timezone.now().date() - admin.date_joined.date()).days
            activity_score = min(100, max(0, 50 + (days_since_joined * 0.5)))  # Basic scoring
            
            admin_performance.append({
                'admin_id': admin.id,
                'admin_name': admin.name,
                'days_active': days_since_joined,
                'performance_score': round(activity_score, 1)
            })
        
        # Calculate average performance
        avg_performance = 0
        if admin_performance:
            avg_performance = sum(p['performance_score'] for p in admin_performance) / len(admin_performance)
        
        # Calculate growth rates
        total_admins_last_month = User.objects.filter(
            role='admin',
            date_joined__lt=this_month_start
        ).count()
        
        admin_growth_rate = 0
        if total_admins_last_month > 0:
            admin_growth_rate = ((total_admins - total_admins_last_month) / total_admins_last_month) * 100
        
        active_growth_rate = 0
        active_admins_last_month = User.objects.filter(
            role='admin',
            is_active=True,
            date_joined__lt=this_month_start
        ).count()
        
        if active_admins_last_month > 0:
            active_growth_rate = ((active_admins - active_admins_last_month) / active_admins_last_month) * 100
        
        new_month_growth_rate = 0
        if last_month_admins > 0:
            new_month_growth_rate = ((new_this_month - last_month_admins) / last_month_admins) * 100
        
        stats_data = {
            'total_admins': {
                'value': total_admins,
                'change': f"{'+' if admin_growth_rate >= 0 else ''}{admin_growth_rate:.1f}% from last month"
            },
            'active_admins': {
                'value': active_admins,
                'change': f"{'+' if active_growth_rate >= 0 else ''}{active_growth_rate:.1f}% from last month"
            },
            'new_this_month': {
                'value': new_this_month,
                'change': f"{'+' if new_month_growth_rate >= 0 else ''}{new_month_growth_rate:.1f}% from last month"
            },
            'avg_performance': {
                'value': f"{avg_performance:.1f}%",
                'change': '+0% from last month'  # Could calculate this if needed
            },
            'admin_performance': admin_performance,
            'top_performers': sorted(admin_performance, key=lambda x: x['performance_score'], reverse=True)[:5]
        }
        
        return Response({
            'success': True,
            'data': stats_data,
            'message': 'Admin statistics retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class AdminAccessOTPView(APIView):
    """Send and verify OTP for admin access to sensitive patient data"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'action': {
                        'type': 'string',
                        'enum': ['send', 'verify'],
                        'description': 'Action to perform: send OTP or verify OTP'
                    },
                    'patient_id': {
                        'type': 'string',
                        'description': 'Patient ID for which access is requested'
                    },
                    'otp': {
                        'type': 'string',
                        'description': '6-digit OTP code (required for verify action)'
                    }
                },
                'required': ['action', 'patient_id']
            }
        },
        responses={
            200: {
                'description': 'OTP sent successfully or verified successfully',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'success': {'type': 'boolean'},
                                'data': {'type': 'object'},
                                'message': {'type': 'string'},
                                'timestamp': {'type': 'string'}
                            }
                        }
                    }
                }
            },
            400: {
                'description': 'Invalid request or OTP verification failed',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'success': {'type': 'boolean'},
                                'error': {'type': 'object'},
                                'timestamp': {'type': 'string'}
                            }
                        }
                    }
                }
            }
        },
        description="Send or verify OTP for admin access to sensitive patient medical records"
    )
    def post(self, request):
        action = request.data.get('action')
        patient_id = request.data.get('patient_id')
        
        # Validate admin role
        if request.user.role not in ['admin', 'superadmin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'ACCESS_DENIED',
                    'message': 'Only admins can access patient medical records'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validate patient_id
        if not patient_id:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_PATIENT_ID',
                    'message': 'Patient ID is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if patient exists
        try:
            from patients.models import PatientProfile
            # Convert patient_id to string if it's a number
            patient_id_str = str(patient_id)
            patient = PatientProfile.objects.get(id=patient_id_str)
        except PatientProfile.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'PATIENT_NOT_FOUND',
                    'message': 'Patient not found'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)
        
        if action == 'send':
            return self.send_admin_otp(request, patient)
        elif action == 'verify':
            return self.verify_admin_otp(request, patient)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_ACTION',
                    'message': 'Action must be either "send" or "verify"'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def send_admin_otp(self, request, patient):
        """Send OTP to admin for patient access"""
        try:
            # Generate OTP
            otp_code = '123456'  # For testing - replace with actual OTP generation
            
            # Store OTP data
            otp_data = {
                'otp': otp_code,
                'admin_id': request.user.id,
                'patient_id': patient.id,
                'created_at': timezone.now().isoformat(),
                'expires_at': (timezone.now() + timedelta(minutes=10)).isoformat()
            }
            
            # Store OTP in session
            request.session[f'admin_otp_{patient.id}'] = otp_data
            request.session.modified = True
            request.session.save()
            
            # Also store in memory as fallback
            with _otp_storage_lock:
                _otp_storage[f'admin_otp_{patient.id}'] = otp_data
            
            # Debug: Print session data
            print(f"DEBUG: Stored OTP for patient {patient.id}: {request.session.get(f'admin_otp_{patient.id}')}")
            print(f"DEBUG: Memory storage keys: {list(_otp_storage.keys())}")
            
            # In production, send OTP via SMS/Email
            # For now, we'll just return it in the response for testing
            
            return Response({
                'success': True,
                'data': {
                    'patient_id': patient.id,
                    'patient_name': patient.user.name,
                    'expires_in': 600,  # 10 minutes
                    'otp_code': otp_code  # Remove this in production
                },
                'message': f'OTP sent to admin for accessing {patient.user.name}\'s medical records',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f"DEBUG: Error sending OTP: {e}")
            return Response({
                'success': False,
                'error': {
                    'code': 'OTP_SEND_FAILED',
                    'message': 'Failed to send OTP'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def verify_admin_otp(self, request, patient):
        """Verify OTP for admin access"""
        otp = request.data.get('otp')
        
        if not otp:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_OTP',
                    'message': 'OTP is required for verification'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Debug: Print all session keys
        print(f"DEBUG: All session keys: {list(request.session.keys())}")
        print(f"DEBUG: Looking for key: admin_otp_{patient.id}")
        
        # Get stored OTP from session first
        stored_otp_data = request.session.get(f'admin_otp_{patient.id}')
        print(f"DEBUG: Session OTP data: {stored_otp_data}")
        
        # If not in session, try memory storage
        if not stored_otp_data:
            with _otp_storage_lock:
                stored_otp_data = _otp_storage.get(f'admin_otp_{patient.id}')
            print(f"DEBUG: Memory OTP data: {stored_otp_data}")
        
        if not stored_otp_data:
            return Response({
                'success': False,
                'error': {
                    'code': 'OTP_NOT_FOUND',
                    'message': 'No OTP found. Please request a new OTP.'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if OTP is expired
        expires_at = timezone.datetime.fromisoformat(stored_otp_data['expires_at'].replace('Z', '+00:00'))
        if timezone.now() > expires_at:
            # Remove expired OTP from both session and memory
            if f'admin_otp_{patient.id}' in request.session:
                del request.session[f'admin_otp_{patient.id}']
                request.session.modified = True
            
            with _otp_storage_lock:
                if f'admin_otp_{patient.id}' in _otp_storage:
                    del _otp_storage[f'admin_otp_{patient.id}']
            
            return Response({
                'success': False,
                'error': {
                    'code': 'OTP_EXPIRED',
                    'message': 'OTP has expired. Please request a new OTP.'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if OTP matches
        if stored_otp_data['otp'] != otp:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_OTP',
                    'message': 'Invalid OTP. Please try again.'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # OTP is valid - remove it from session and memory, then grant access
        if f'admin_otp_{patient.id}' in request.session:
            del request.session[f'admin_otp_{patient.id}']
            request.session.modified = True
        
        with _otp_storage_lock:
            if f'admin_otp_{patient.id}' in _otp_storage:
                del _otp_storage[f'admin_otp_{patient.id}']
        
        # Log the access for audit purposes
        try:
            from patients.models import PatientAccessLog
            PatientAccessLog.objects.create(
                patient=patient,
                admin=request.user,
                access_type='medical_records',
                timestamp=timezone.now(),
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
        except Exception as e:
            # Log error but don't fail the request
            print(f"Failed to log patient access: {e}")
        
        return Response({
            'success': True,
            'data': {
                'patient_id': patient.id,
                'patient_name': patient.user.name,
                'access_granted': True,
                'access_type': 'medical_records',
                'expires_at': (timezone.now() + timedelta(hours=1)).isoformat()
            },
            'message': f'Access granted to {patient.user.name}\'s medical records',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def health_check(request):
    """Health check endpoint"""
    return Response({
        'success': True,
        'message': 'Authentication service is healthy',
        'timestamp': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def account_type_lookup(request):
    """Lookup account type (role) by mobile number"""
    phone = request.query_params.get('phone', '').strip()
    if not phone:
        return Response({
            'success': False,
            'error': {
                'code': 'MISSING_PHONE',
                'message': 'Phone number is required.'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)

    # Normalize phone number (add country code if needed)
    phone_digits = ''.join(filter(str.isdigit, phone))
    if not phone_digits.startswith('91') and len(phone_digits) == 10:
        phone_digits = '91' + phone_digits
    if not phone_digits.startswith('+'):
        phone_digits = '+' + phone_digits

    user = User.objects.filter(phone=phone_digits).first()
    if user:
        return Response({
            'success': True,
            'data': {
                'phone': user.phone,
                'role': user.role,
                'name': user.name
            },
            'message': f'Account found for {user.phone}',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'success': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'No account found for this phone number.'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_404_NOT_FOUND)

