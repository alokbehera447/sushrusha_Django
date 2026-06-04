from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.db import models
from django.utils import timezone
from django.http import HttpResponse, Http404
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes
from .models import Prescription, PrescriptionMedication, PrescriptionVitalSigns, PrescriptionPDF, InvestigationCategory, InvestigationTest, PrescriptionInvestigation, PrescriptionImage
from .serializers import (
    PrescriptionSerializer, PrescriptionCreateSerializer, PrescriptionUpdateSerializer,
    PrescriptionListSerializer, PrescriptionDetailSerializer, PrescriptionMedicationSerializer,
    PrescriptionVitalSignsSerializer, InvestigationCategorySerializer, InvestigationTestSerializer, PrescriptionInvestigationSerializer
)
from .enhanced_pdf_generator import generate_prescription_pdf, generate_mobile_prescription_pdf
from utils.signed_urls import generate_signed_url
import os

class PrescriptionPagination(PageNumberPagination):
    """Custom pagination for prescription lists"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class IsDoctorOrPatientOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        # Allow public access to verification endpoint
        if view.action == 'verify_prescription':
            return True
        # Allow all authenticated users to create and update prescriptions
        if request.method in ['POST', 'PUT', 'PATCH']:
            return request.user.is_authenticated
        return True
    
    def has_object_permission(self, request, view, obj):
        # Allow public access to verification endpoint
        if view.action == 'verify_prescription':
            return True
        # Admin and SuperAdmin can do anything
        if request.user.role in ['admin', 'superadmin']:
            return True
        # Doctor can edit/view, patient can view
        if request.user == obj.doctor:
            return True
        if request.method in permissions.SAFE_METHODS and request.user == obj.patient:
            return True
        return False

class PrescriptionViewSet(viewsets.ModelViewSet):
    """Enhanced ViewSet for prescription management"""
    permission_classes = [permissions.IsAuthenticated, IsDoctorOrPatientOrAdmin]
    pagination_class = PrescriptionPagination
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return PrescriptionCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return PrescriptionUpdateSerializer
        elif self.action == 'list':
            return PrescriptionListSerializer
        elif self.action == 'retrieve':
            return PrescriptionDetailSerializer
        return PrescriptionSerializer

    def get_queryset(self):
        """Filter queryset based on user role"""
        user = self.request.user
        queryset = Prescription.objects.select_related(
            'doctor', 'patient', 'consultation'
        ).prefetch_related('medications', 'vital_signs')
        
        if user.role == 'superadmin':
            # SuperAdmin can see all prescriptions
            return queryset
        elif user.role == 'admin':
            # Admin can see prescriptions for their clinic
            try:
                assigned_clinic = user.administered_clinic
                return queryset.filter(consultation__clinic=assigned_clinic)
            except:
                return queryset.none()
        elif user.role == 'doctor':
            # Doctors can see prescriptions they created
            return queryset.filter(doctor=user)
        elif user.role == 'patient':
            # Patients can see their own prescriptions
            return queryset.filter(patient=user)
        
        return queryset.none()

    @extend_schema(
        responses={200: PrescriptionDetailSerializer},
        description="Get prescription by ID"
    )
    def retrieve(self, request, pk=None):
        """Get prescription by ID"""
        prescription = self.get_object()
        serializer = self.get_serializer(prescription)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Prescription retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @extend_schema(
        responses={200: PrescriptionListSerializer(many=True)},
        description="List all prescriptions with pagination and filtering"
    )
    def list(self, request):
        """List prescriptions with pagination and filtering"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Prescriptions retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Prescriptions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @extend_schema(
        request=PrescriptionCreateSerializer,
        responses={201: PrescriptionSerializer},
        description="Create prescription"
    )
    def create(self, request):
        """Create prescription or update if exists"""
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            # Check if prescription already exists for this consultation-patient combination
            consultation_id = request.data.get('consultation')
            patient_id = request.data.get('patient')
            user = request.user
            
            if consultation_id and patient_id:
                try:
                    # Superadmin/admin can find prescriptions regardless of who wrote them
                    if user.role in ['superadmin', 'admin']:
                        existing_prescription = Prescription.objects.get(
                            consultation_id=consultation_id,
                            patient_id=patient_id
                        )
                    else:
                        existing_prescription = Prescription.objects.get(
                            consultation_id=consultation_id,
                            doctor=request.user,
                            patient_id=patient_id
                        )
                    # Update existing prescription
                    update_serializer = PrescriptionUpdateSerializer(
                        existing_prescription, 
                        data=request.data, 
                        partial=True,
                        context={'request': request}
                    )
                    if update_serializer.is_valid():
                        prescription = update_serializer.save()
                        response_serializer = PrescriptionDetailSerializer(prescription)
                        return Response({
                            'success': True,
                            'data': response_serializer.data,
                            'message': 'Prescription updated successfully',
                            'timestamp': timezone.now().isoformat()
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                            'success': False,
                            'error': {
                                'code': 'VALIDATION_ERROR',
                                'message': 'Invalid data provided',
                                'details': update_serializer.errors
                            },
                            'timestamp': timezone.now().isoformat()
                        }, status=status.HTTP_400_BAD_REQUEST)
                except Prescription.DoesNotExist:
                    # Create new prescription — for superadmin/admin, set doctor to the consultation's doctor
                    if user.role in ['superadmin', 'admin']:
                        from consultations.models import Consultation as ConsultationModel
                        try:
                            consultation_obj = ConsultationModel.objects.get(id=consultation_id)
                            serializer.context['override_doctor'] = consultation_obj.doctor
                        except ConsultationModel.DoesNotExist:
                            pass
                    prescription = serializer.save()
                    response_serializer = PrescriptionDetailSerializer(prescription)
                    return Response({
                        'success': True,
                        'data': response_serializer.data,
                        'message': 'Prescription created successfully',
                        'timestamp': timezone.now().isoformat()
                    }, status=status.HTTP_201_CREATED)
            else:
                # Create new prescription without consultation/patient check
                prescription = serializer.save()
                response_serializer = PrescriptionDetailSerializer(prescription)
                return Response({
                    'success': True,
                    'data': response_serializer.data,
                    'message': 'Prescription created successfully',
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
        request=PrescriptionUpdateSerializer,
        responses={200: PrescriptionSerializer},
        description="Update prescription"
    )
    def update(self, request, pk=None):
        """Update prescription"""
        prescription = self.get_object()
        serializer = self.get_serializer(prescription, data=request.data, partial=False)
        if serializer.is_valid():
            prescription = serializer.save()
            response_serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Prescription updated successfully',
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

    @extend_schema(
        request=PrescriptionUpdateSerializer,
        responses={200: PrescriptionSerializer},
        description="Partially update prescription"
    )
    def partial_update(self, request, pk=None):
        """Partially update prescription"""
        prescription = self.get_object()
        serializer = self.get_serializer(prescription, data=request.data, partial=True)
        if serializer.is_valid():
            prescription = serializer.save()
            response_serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Prescription updated successfully',
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

    @action(detail=False, methods=['get'], url_path='consultation/(?P<consultation_id>[^/.]+)')
    def by_consultation(self, request, consultation_id=None):
        """Get prescription for a specific consultation"""
        try:
            user = request.user
            # Superadmin and admin can access any prescription for this consultation
            if user.role in ['superadmin', 'admin']:
                prescription = Prescription.objects.get(
                    consultation_id=consultation_id
                )
            else:
                prescription = Prescription.objects.get(
                    consultation_id=consultation_id,
                    doctor=request.user
                )
            serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': serializer.data,
                'message': 'Prescription retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        except Prescription.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'NOT_FOUND',
                    'message': 'Prescription not found for this consultation'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], url_path='patient/(?P<patient_id>[^/.]+)')
    def by_patient(self, request, patient_id=None):
        """List all prescriptions for a given patient"""
        prescriptions = self.get_queryset().filter(patient_id=patient_id)
        page = self.paginate_queryset(prescriptions)
        
        if page is not None:
            serializer = PrescriptionListSerializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Patient prescriptions retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = PrescriptionListSerializer(prescriptions, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Patient prescriptions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def finalize(self, request, pk=None):
        """Finalize a prescription and generate PDF"""
        prescription = self.get_object()
        
        # Only allow finalization if user is the doctor who created it OR admin/superadmin
        if request.user != prescription.doctor and request.user.role not in ['superadmin', 'admin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only the prescribing doctor can finalize prescriptions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Update prescription with any final changes
            if request.data:
                serializer = PrescriptionUpdateSerializer(
                    prescription, 
                    data=request.data, 
                    partial=True,
                    context={'request': request}
                )
                if serializer.is_valid():
                    prescription = serializer.save()
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
            
            # Finalize the prescription
            prescription.is_draft = False
            prescription.is_finalized = True
            prescription.save()
            
            # Get header and footer images (use default paths or from request)
            header_image_path = None
            footer_image_path = None
            
            # Check for existing header/footer files
            default_header = os.path.join(settings.MEDIA_ROOT, 'prescription_headers', 'test_prescription_header.png')
            default_footer = os.path.join(settings.MEDIA_ROOT, 'prescription_footers', 'test_prescription_footer.png')
            
            if os.path.exists(default_header):
                header_image_path = default_header
            if os.path.exists(default_footer):
                footer_image_path = default_footer
            
            # Generate PDF
            pdf_instance = generate_prescription_pdf(
                prescription=prescription,
                user=request.user,
                header_image_path=header_image_path,
                footer_image_path=footer_image_path
            )
            
            # Generate signed URL for the PDF file
            pdf_url = None
            if pdf_instance.pdf_file:
                try:
                    # Get the file key from the file path and ensure it includes AWS_LOCATION
                    file_key = str(pdf_instance.pdf_file)
                    aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                    if not file_key.startswith(f"{aws_location}/"):
                        file_key = f"{aws_location}/{file_key}"
                    
                    # Add a small delay to allow the signal to upload the file to DigitalOcean Spaces
                    import time
                    time.sleep(2)
                    
                    # Generate signed URL - the signal should have uploaded the file by now
                    pdf_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                    print(f"✅ Generated signed URL for PDF: {file_key}")
                        
                except Exception as e:
                    print(f"Error generating signed URL for PDF: {e}")
                    # Fallback to direct URL if signed URL generation fails
                    pdf_url = pdf_instance.pdf_file.url if pdf_instance.pdf_file else None
            
            # Return response with PDF information
            serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': {
                    'prescription': serializer.data,
                    'pdf': {
                        'id': pdf_instance.id,
                        'version': pdf_instance.version_number,
                        'url': pdf_url,
                        'generated_at': pdf_instance.generated_at.isoformat()
                    }
                },
                'message': 'Prescription finalized and PDF generated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f"Error finalizing prescription: {e}")
            return Response({
                'success': False,
                'error': {
                    'code': 'INTERNAL_ERROR',
                    'message': 'Error finalizing prescription and generating PDF'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'])
    def save_draft(self, request, pk=None):
        """Save prescription as draft with all data"""
        prescription = self.get_object()
        
        # Only allow save if user is the doctor who created it OR admin/superadmin
        if request.user != prescription.doctor and request.user.role not in ['superadmin', 'admin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only the prescribing doctor can save prescriptions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update prescription data with request data
        serializer = PrescriptionUpdateSerializer(
            prescription, 
            data=request.data, 
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            # Save the prescription data and ensure it's marked as draft
            prescription = serializer.save(is_draft=True, is_finalized=False)
            
            # Return the updated prescription data
            response_serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Prescription saved as draft successfully',
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

    @action(detail=False, methods=['get'])
    def drafts(self, request):
        """Get all draft prescriptions for the current user"""
        drafts = self.get_queryset().filter(is_draft=True)
        page = self.paginate_queryset(drafts)
        
        if page is not None:
            serializer = PrescriptionListSerializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Draft prescriptions retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = PrescriptionListSerializer(drafts, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Draft prescriptions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def finalized(self, request):
        """Get all finalized prescriptions for the current user"""
        finalized = self.get_queryset().filter(is_finalized=True)
        page = self.paginate_queryset(finalized)
        
        if page is not None:
            serializer = PrescriptionListSerializer(page, many=True)
            return self.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Finalized prescriptions retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = PrescriptionListSerializer(finalized, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Finalized prescriptions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='auto-save')
    def auto_save(self, request, pk=None):
        """Auto-save prescription data - used for draft auto-saving"""
        prescription = self.get_object()
        
        # Only allow auto-save if user is the doctor who created it OR admin/superadmin
        if request.user != prescription.doctor and request.user.role not in ['superadmin', 'admin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only the prescribing doctor can auto-save'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Update prescription data
        serializer = PrescriptionUpdateSerializer(
            prescription, 
            data=request.data, 
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            # Ensure it remains as draft during auto-save
            prescription = serializer.save(is_draft=True, is_finalized=False)
            
            # Return the updated prescription data
            response_serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': response_serializer.data,
                'message': 'Prescription auto-saved successfully',
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

    @action(detail=True, methods=['post'], url_path='finalize-and-generate-pdf')
    def finalize_and_generate_pdf(self, request, pk=None):
        """Finalize prescription and generate PDF with versioning"""
        prescription = self.get_object()
        
        # Only allow finalization if user is the doctor who created it OR admin/superadmin
        if request.user != prescription.doctor and request.user.role not in ['superadmin', 'admin']:
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only the prescribing doctor can finalize prescriptions'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Update prescription with any final changes
            if request.data:
                serializer = PrescriptionUpdateSerializer(
                    prescription, 
                    data=request.data, 
                    partial=True,
                    context={'request': request}
                )
                if serializer.is_valid():
                    prescription = serializer.save()
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
            
            # Finalize the prescription
            prescription.is_draft = False
            prescription.is_finalized = True
            prescription.save()
            
            # Get header and footer images (use default paths or from request)
            header_image_path = None
            footer_image_path = None
            
            # Check for existing header/footer files
            default_header = os.path.join(settings.MEDIA_ROOT, 'prescription_headers', 'test_prescription_header.png')
            default_footer = os.path.join(settings.MEDIA_ROOT, 'prescription_footers', 'test_prescription_footer.png')
            
            if os.path.exists(default_header):
                header_image_path = default_header
            if os.path.exists(default_footer):
                footer_image_path = default_footer
            
            # Generate PDF
            pdf_instance = generate_prescription_pdf(
                prescription=prescription,
                user=request.user,
                header_image_path=header_image_path,
                footer_image_path=footer_image_path
            )
            
            # Generate signed URL for the PDF file
            pdf_url = None
            if pdf_instance.pdf_file:
                try:
                    # Get the file key from the file path and ensure it includes AWS_LOCATION
                    file_key = str(pdf_instance.pdf_file)
                    aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                    if not file_key.startswith(f"{aws_location}/"):
                        file_key = f"{aws_location}/{file_key}"
                    
                    # Add a small delay to allow the signal to upload the file to DigitalOcean Spaces
                    import time
                    time.sleep(2)
                    
                    # Generate signed URL - the signal should have uploaded the file by now
                    pdf_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                    print(f"✅ Generated signed URL for PDF: {file_key}")
                        
                except Exception as e:
                    print(f"Error generating signed URL for PDF: {e}")
                    # Fallback to direct URL if signed URL generation fails
                    pdf_url = pdf_instance.pdf_file.url if pdf_instance.pdf_file else None
            
            # Return response with PDF information
            serializer = PrescriptionDetailSerializer(prescription)
            return Response({
                'success': True,
                'data': {
                    'prescription': serializer.data,
                    'pdf': {
                        'id': pdf_instance.id,
                        'version': pdf_instance.version_number,
                        'url': pdf_url,
                        'generated_at': pdf_instance.generated_at.isoformat()
                    }
                },
                'message': 'Prescription finalized and PDF generated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'PDF_GENERATION_ERROR',
                    'message': f'Failed to generate PDF: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'], url_path='pdf-versions')
    def pdf_versions(self, request, pk=None):
        """Get all PDF versions for a prescription"""
        prescription = self.get_object()
        
        pdf_versions = PrescriptionPDF.objects.filter(
            prescription=prescription
        ).order_by('-version_number')
        
        versions_data = []
        for pdf in pdf_versions:
            # Generate signed URL for each PDF file
            file_url = None
            if pdf.pdf_file:
                try:
                    file_key = str(pdf.pdf_file)
                    aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                    if not file_key.startswith(f"{aws_location}/"):
                        file_key = f"{aws_location}/{file_key}"
                    file_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                except Exception as e:
                    print(f"Error generating signed URL for PDF version: {e}")
                    file_url = pdf.pdf_file.url if pdf.pdf_file else None
            
            versions_data.append({
                'id': pdf.id,
                'version': pdf.version_number,
                'is_current': pdf.is_current,
                'generated_at': pdf.generated_at.isoformat(),
                'generated_by': {
                    'id': pdf.generated_by.id,
                    'name': pdf.generated_by.name
                },
                'file_url': file_url,
                'file_size': pdf.file_size
            })
        
        return Response({
            'success': True,
            'data': {
                'prescription_id': prescription.id,
                'total_versions': len(versions_data),
                'versions': versions_data
            },
            'message': 'PDF versions retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='pdf/(?P<version>[^/.]+)')
    def download_pdf(self, request, pk=None, version=None):
        """Download a specific version of prescription PDF"""
        prescription = self.get_object()
        
        try:
            if version == 'latest':
                pdf_instance = PrescriptionPDF.objects.filter(
                    prescription=prescription,
                    is_current=True
                ).first()
            else:
                pdf_instance = PrescriptionPDF.objects.get(
                    prescription=prescription,
                    version_number=int(version)
                )
            
            if not pdf_instance or not pdf_instance.pdf_file:
                raise Http404("PDF not found")
            
            # Check permissions
            user = request.user
            print(f"DEBUG: User ID: {user.id}, Role: {user.role}, Phone: {user.phone}")
            print(f"DEBUG: Prescription doctor: {prescription.doctor.id}, patient: {prescription.patient.id}")
            print(f"DEBUG: User == doctor: {user == prescription.doctor}")
            print(f"DEBUG: User == patient: {user == prescription.patient}")
            print(f"DEBUG: User role in admin/superadmin: {user.role in ['admin', 'superadmin']}")
            
            if not (user == prescription.doctor or 
                   user == prescription.patient or 
                   user.role in ['admin', 'superadmin']):
                return Response({
                    'success': False,
                    'error': {
                        'code': 'PERMISSION_DENIED',
                        'message': f'You do not have permission to access this PDF. User role: {user.role}'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Generate signed URL for the PDF file
            try:
                file_key = str(pdf_instance.pdf_file)
                aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                if not file_key.startswith(f"{aws_location}/"):
                    file_key = f"{aws_location}/{file_key}"
                signed_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                
                # Redirect to signed URL instead of serving file directly
                response = Response({
                    'success': True,
                    'data': {
                        'download_url': signed_url,
                        'filename': f"prescription_{prescription.id}_v{pdf_instance.version_number}.pdf"
                    },
                    'message': 'PDF download URL generated successfully',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
                
                # Add headers for direct download
                response['Content-Disposition'] = f'attachment; filename="prescription_{prescription.id}_v{pdf_instance.version_number}.pdf"'
                return response
                
            except Exception as e:
                print(f"Error generating signed URL for download: {e}")
                # Fallback to direct file serving
                response = HttpResponse(
                    pdf_instance.pdf_file.read(),
                    content_type='application/pdf'
                )
                response['Content-Disposition'] = f'inline; filename="prescription_{prescription.id}_v{pdf_instance.version_number}.pdf"'
                return response
            
        except (PrescriptionPDF.DoesNotExist, ValueError):
            raise Http404("PDF version not found")

    @action(detail=False, methods=['get'], url_path='patient/(?P<patient_id>[^/.]+)/pdfs')
    def patient_pdfs(self, request, patient_id=None):
        """Get all prescription PDFs for a specific patient"""
        # Check permissions
        user = request.user
        if not (user.role in ['admin', 'superadmin'] or 
               (user.role == 'patient' and str(user.id) == patient_id) or
               user.role == 'doctor'):
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'You do not have permission to access these PDFs'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get all prescription PDFs for the patient
        pdf_instances = PrescriptionPDF.objects.filter(
            prescription__patient_id=patient_id,
            is_current=True  # Only get current versions
        ).select_related('prescription', 'generated_by').order_by('-generated_at')
        
        pdfs_data = []
        for pdf in pdf_instances:
            # Generate signed URL for each PDF file
            file_url = None
            if pdf.pdf_file:
                try:
                    file_key = str(pdf.pdf_file)
                    aws_location = getattr(settings, 'AWS_LOCATION', 'edrcontainer1')
                    if not file_key.startswith(f"{aws_location}/"):
                        file_key = f"{aws_location}/{file_key}"
                    file_url = generate_signed_url(file_key, expiration=3600)  # 1 hour expiration
                except Exception as e:
                    print(f"Error generating signed URL for patient PDF: {e}")
                    file_url = pdf.pdf_file.url if pdf.pdf_file else None
            
            pdfs_data.append({
                'id': pdf.id,
                'prescription_id': pdf.prescription.id,
                'consultation_id': pdf.prescription.consultation.id if pdf.prescription.consultation else None,
                'version': pdf.version_number,
                'generated_at': pdf.generated_at.isoformat(),
                'generated_by': {
                    'id': pdf.generated_by.id,
                    'name': pdf.generated_by.name
                },
                'file_url': file_url,
                'file_size': pdf.file_size,
                'prescription_date': pdf.prescription.issued_date.strftime('%Y-%m-%d'),
                'diagnosis': pdf.prescription.primary_diagnosis
            })
        
        return Response({
            'success': True,
            'data': {
                'patient_id': patient_id,
                'total_pdfs': len(pdfs_data),
                'pdfs': pdfs_data
            },
            'message': 'Patient prescription PDFs retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='verify/(?P<prescription_id>[^/.]+)')
    def verify_prescription(self, request, prescription_id=None):
        """Public endpoint to verify prescription authenticity (no authentication required)"""
        try:
            # Get prescription by ID
            prescription = Prescription.objects.select_related(
                'doctor', 'patient', 'consultation'
            ).prefetch_related('medications').get(id=prescription_id)
            
            # Get the latest PDF version
            latest_pdf = PrescriptionPDF.objects.filter(prescription=prescription).order_by('-created_at').first()
            
            # Prepare verification data
            verification_data = {
                'prescription_id': prescription.id,
                'consultation_id': prescription.consultation_id,
                'issued_date': prescription.issued_date,
                'issued_time': prescription.issued_time,
                'is_finalized': prescription.is_finalized,
                'is_draft': prescription.is_draft,
                'doctor': {
                    'name': prescription.doctor.name,
                    'qualifications': getattr(prescription.doctor, 'qualifications', 'MBBS'),
                    'specialization': getattr(prescription.doctor, 'specialization', 'Family Physician'),
                },
                'patient': {
                    'name': prescription.patient.name,
                    'age': self._calculate_age(getattr(prescription.patient, 'date_of_birth', None)),
                    'gender': getattr(prescription.patient, 'gender', 'N/A'),
                },
                'medications_count': prescription.medications.count(),
                'verification_status': 'VALID' if prescription.is_finalized else 'DRAFT',
                'pdf_available': latest_pdf is not None,
                'latest_pdf_version': latest_pdf.version_number if latest_pdf else None,
                'verification_timestamp': timezone.now().isoformat(),
            }
            
            # Check if request wants JSON (API call) or HTML (browser)
            if request.headers.get('Accept') == 'application/json' or request.GET.get('format') == 'json':
                return Response({
                    'success': True,
                    'data': verification_data,
                    'message': 'Prescription verification successful',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            else:
                # Return HTML template for browser
                from django.shortcuts import render
                return render(request, 'prescription_verify.html', {
                    'verification_data': verification_data,
                    'prescription_id': prescription_id
                })
            
        except Prescription.DoesNotExist:
            if request.headers.get('Accept') == 'application/json' or request.GET.get('format') == 'json':
                return Response({
                    'success': False,
                    'error': {
                        'code': 'PRESCRIPTION_NOT_FOUND',
                        'message': f'Prescription with ID {prescription_id} not found'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)
            else:
                # Return HTML error page
                from django.shortcuts import render
                return render(request, 'prescription_verify.html', {
                    'error': f'Prescription with ID {prescription_id} not found',
                    'prescription_id': prescription_id
                }, status=404)
        except Exception as e:
            if request.headers.get('Accept') == 'application/json' or request.GET.get('format') == 'json':
                return Response({
                    'success': False,
                    'error': {
                        'code': 'VERIFICATION_ERROR',
                        'message': f'Failed to verify prescription: {str(e)}'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Return HTML error page
                from django.shortcuts import render
                return render(request, 'prescription_verify.html', {
                    'error': f'Failed to verify prescription: {str(e)}',
                    'prescription_id': prescription_id
                }, status=500)

    def _calculate_age(self, date_of_birth):
        """Calculate age from date of birth"""
        if not date_of_birth:
            return "N/A"
        
        from datetime import datetime
        today = datetime.now().date()
        age = today.year - date_of_birth.year
        if today.month < date_of_birth.month or (today.month == date_of_birth.month and today.day < date_of_birth.day):
            age -= 1
        return str(age)

    @action(detail=True, methods=['post'], url_path='generate-mobile-pdf')
    def generate_mobile_pdf(self, request, pk=None):
        """Generate PDF for mobile consultation with uploaded prescription image"""
        prescription = self.get_object()
        
        # Check if prescription image is provided
        if 'prescription_image' not in request.FILES:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_IMAGE',
                    'message': 'Prescription image is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Save the uploaded image using PrescriptionImage model
            uploaded_file = request.FILES['prescription_image']
            
            # Create PrescriptionImage instance
            prescription_image = PrescriptionImage.objects.create(
                prescription=prescription,
                image_file=uploaded_file,
                uploaded_by=request.user,
                is_mobile_upload=True
            )
            
            # Generate PDF with the uploaded image
            pdf_record = generate_mobile_prescription_pdf(prescription, prescription_image)
            
            # Generate signed URL for download
            download_url = generate_signed_url(pdf_record.pdf_file.name)
            
            return Response({
                'success': True,
                'data': {
                    'pdf_id': pdf_record.id,
                    'version': pdf_record.version_number,
                    'download_url': download_url,
                    'filename': f"mobile_prescription_{prescription.consultation_id}_v{pdf_record.version_number}.pdf"
                },
                'message': 'Mobile prescription PDF generated successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'PDF_GENERATION_ERROR',
                    'message': f'Failed to generate PDF: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PrescriptionMedicationViewSet(viewsets.ModelViewSet):
    """ViewSet for prescription medications"""
    serializer_class = PrescriptionMedicationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter medications by prescription"""
        prescription_id = self.kwargs.get('prescription_pk')
        return PrescriptionMedication.objects.filter(prescription_id=prescription_id)

    def perform_create(self, serializer):
        """Create medication for prescription"""
        prescription_id = self.kwargs.get('prescription_pk')
        prescription = Prescription.objects.get(id=prescription_id)
        serializer.save(prescription=prescription)

class PrescriptionVitalSignsViewSet(viewsets.ModelViewSet):
    """ViewSet for prescription vital signs"""
    serializer_class = PrescriptionVitalSignsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter vital signs by prescription"""
        prescription_id = self.kwargs.get('prescription_pk')
        return PrescriptionVitalSigns.objects.filter(prescription_id=prescription_id)

    def perform_create(self, serializer):
        """Create vital signs for prescription"""
        prescription_id = self.kwargs.get('prescription_pk')
        prescription = Prescription.objects.get(id=prescription_id)
        serializer.save(prescription=prescription)


class InvestigationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing investigation categories and tests"""
    
    queryset = InvestigationCategory.objects.filter(is_active=True).prefetch_related('tests')
    serializer_class = InvestigationCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def list_all(self, request):
        """Get all investigation categories and tests"""
        categories = InvestigationCategory.objects.filter(is_active=True).prefetch_related('tests')
        tests = InvestigationTest.objects.filter(is_active=True).select_related('category')
        
        data = {
            'categories': InvestigationCategorySerializer(categories, many=True).data,
            'tests': InvestigationTestSerializer(tests, many=True).data
        }
        
        return Response({
            'success': True,
            'data': data,
            'message': 'Investigation list retrieved successfully'
        })
    
    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Get all investigation categories"""
        categories = InvestigationCategory.objects.filter(is_active=True)
        serializer = InvestigationCategorySerializer(categories, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Categories retrieved successfully'
        })
    
    @action(detail=False, methods=['get'])
    def tests(self, request):
        """Get all investigation tests"""
        tests = InvestigationTest.objects.filter(is_active=True).select_related('category')
        serializer = InvestigationTestSerializer(tests, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Tests retrieved successfully'
        })

    @action(detail=False, methods=['post'], url_path='auto-create')
    def auto_create(self, request):
        """Auto-create an investigation test if it doesn't already exist.
        
        Request body:
            name (str, required): Name of the investigation test
            category_id (int, optional): ID of the category; defaults to 'General' category
        
        Returns the test object and whether it was 'existing' or 'newly_created'.
        """
        name = request.data.get('name', '').strip()
        category_id = request.data.get('category_id')

        if not name:
            return Response({
                'success': False,
                'message': 'Test name is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Resolve category
        category = None
        if category_id:
            try:
                category = InvestigationCategory.objects.get(id=category_id)
            except InvestigationCategory.DoesNotExist:
                return Response({
                    'success': False,
                    'message': f'Category with id {category_id} not found'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            # Try to find or create a default "General" category
            category, _ = InvestigationCategory.objects.get_or_create(
                name='General',
                defaults={'description': 'General investigation tests', 'is_active': True, 'order': 999}
            )

        # Try to find existing test (case-insensitive match within the same category)
        existing_test = InvestigationTest.objects.filter(
            name__iexact=name,
            category=category
        ).first()

        if existing_test:
            serializer = InvestigationTestSerializer(existing_test)
            return Response({
                'success': True,
                'data': {
                    'test': serializer.data,
                    'source': 'existing'
                },
                'message': f'Found existing test: {existing_test.name}'
            }, status=status.HTTP_200_OK)

        # Create a new test
        test = InvestigationTest.objects.create(
            name=name,
            category=category,
            is_active=True
        )
        serializer = InvestigationTestSerializer(test)
        return Response({
            'success': True,
            'data': {
                'test': serializer.data,
                'source': 'newly_created'
            },
            'message': f'Created new test: {test.name}'
        }, status=status.HTTP_201_CREATED)


class PrescriptionInvestigationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing prescription investigations"""
    
    queryset = PrescriptionInvestigation.objects.all()
    serializer_class = PrescriptionInvestigationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter by prescription if provided"""
        queryset = super().get_queryset()
        prescription_id = self.request.query_params.get('prescription_id')
        
        if prescription_id:
            queryset = queryset.filter(prescription_id=prescription_id)
        
        return queryset.select_related('test', 'test__category')
    
    @action(detail=False, methods=['post'])
    def add_to_prescription(self, request):
        """Add investigation tests to a prescription"""
        prescription_id = request.data.get('prescription_id')
        tests = request.data.get('tests', [])
        
        if not prescription_id:
            return Response({
                'success': False,
                'message': 'Prescription ID is required'
            }, status=400)
        
        try:
            prescription = Prescription.objects.get(id=prescription_id)
        except Prescription.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Prescription not found'
            }, status=404)
        
        # Check if user has permission to modify this prescription
        if not (request.user == prescription.doctor or request.user.is_staff):
            return Response({
                'success': False,
                'message': 'You do not have permission to modify this prescription'
            }, status=403)
        
        created_investigations = []
        
        for test_data in tests:
            test_id = test_data.get('test_id')
            priority = test_data.get('priority', 'routine')
            special_instructions = test_data.get('special_instructions', '')
            notes = test_data.get('notes', '')
            
            try:
                test = InvestigationTest.objects.get(id=test_id, is_active=True)
            except InvestigationTest.DoesNotExist:
                continue
            
            # Create or update investigation
            investigation, created = PrescriptionInvestigation.objects.get_or_create(
                prescription=prescription,
                test=test,
                defaults={
                    'priority': priority,
                    'special_instructions': special_instructions,
                    'notes': notes,
                    'order': len(created_investigations) + 1
                }
            )
            
            if not created:
                # Update existing investigation
                investigation.priority = priority
                investigation.special_instructions = special_instructions
                investigation.notes = notes
                investigation.save()
            
            created_investigations.append(investigation)
        
        serializer = PrescriptionInvestigationSerializer(created_investigations, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'message': f'{len(created_investigations)} investigation(s) added to prescription'
        })
    
    @action(detail=False, methods=['delete'])
    def remove_from_prescription(self, request):
        """Remove investigation tests from a prescription"""
        prescription_id = request.data.get('prescription_id')
        test_ids = request.data.get('test_ids', [])
        
        if not prescription_id or not test_ids:
            return Response({
                'success': False,
                'message': 'Prescription ID and test IDs are required'
            }, status=400)
        
        try:
            prescription = Prescription.objects.get(id=prescription_id)
        except Prescription.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Prescription not found'
            }, status=404)
        
        # Check if user has permission to modify this prescription
        if not (request.user == prescription.doctor or request.user.is_staff):
            return Response({
                'success': False,
                'message': 'You do not have permission to modify this prescription'
            }, status=403)
        
        deleted_count = PrescriptionInvestigation.objects.filter(
            prescription_id=prescription_id,
            test_id__in=test_ids
        ).delete()[0]
        
        return Response({
            'success': True,
            'message': f'{deleted_count} investigation(s) removed from prescription'
        })

