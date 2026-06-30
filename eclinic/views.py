from rest_framework import status, permissions, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.db.models import Q, Count, Sum, Avg
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from datetime import datetime, timedelta
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .models import Clinic
from .serializers import ClinicSerializer, ClinicCreateSerializer
from .models import ClinicService, ClinicInventory, ClinicAppointment, ClinicReview, ClinicDocument
from .serializers import ClinicServiceSerializer, ClinicInventorySerializer, ClinicAppointmentSerializer, ClinicReviewSerializer, ClinicDocumentSerializer
from .serializers import ClinicServiceCreateSerializer, ClinicInventoryCreateSerializer, ClinicAppointmentCreateSerializer, ClinicReviewCreateSerializer, ClinicDocumentCreateSerializer
from .serializers import ClinicSearchSerializer
from prescriptions.models import PrescriptionMedication
from .serializers import (
    GlobalMedicationSerializer, GlobalMedicationCreateSerializer, GlobalMedicationSearchSerializer
)
from .models import (
    GlobalMedication
)
from .services.fda_api import search_fda_medications, get_fda_medication_details


class ClinicPagination(PageNumberPagination):
    page_size = 1000
    page_size_query_param = 'page_size'
    max_page_size = 1000

class MedicationPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 1000

class ClinicViewSet(ModelViewSet):
    queryset = Clinic.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = ClinicPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['city', 'state', 'is_verified', 'is_active']
    search_fields = ['name', 'description', 'city', 'specialties']
    ordering_fields = ['created_at', 'name', 'city']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return ClinicCreateSerializer
        return ClinicSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Clinic.objects.all()
        if user.role == 'admin':
            return queryset.filter(admin=user)
        elif user.role in ['superadmin']:
            return queryset
        else:
            return queryset.filter(is_active=True)

    def perform_create(self, serializer):
        user = self.request.user
        # Only superadmin can create clinics
        if hasattr(user, 'role') and user.role == 'superadmin':
            serializer.save()
        else:
            raise PermissionDenied('Only superadmin can create eClinics.')

    def perform_update(self, serializer):
        serializer.save()


class ClinicServiceViewSet(ModelViewSet):
    """ViewSet for clinic service management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get services for specific clinic"""
        clinic_id = self.kwargs.get('clinic_id')
        return ClinicService.objects.filter(clinic_id=clinic_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ClinicServiceCreateSerializer
        return ClinicServiceSerializer
    
    def perform_create(self, serializer):
        """Set clinic_id when creating service"""
        clinic_id = self.kwargs.get('clinic_id')
        serializer.save(clinic_id=clinic_id)


class GlobalMedicationViewSet(ModelViewSet):
    """ViewSet for global medication management (Super Admin only)"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = GlobalMedicationSerializer
    pagination_class = MedicationPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'generic_name', 'brand_name', 'composition', 'therapeutic_class']
    ordering_fields = ['name', 'created_at', 'updated_at']
    ordering = ['name']
    
    def get_queryset(self):
        """Get all global medications"""
        return GlobalMedication.objects.filter(is_active=True)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return GlobalMedicationCreateSerializer
        return GlobalMedicationSerializer
    
    def get_permissions(self):
        """Only super admin can manage global medications"""
        # Handle anonymous users
        if not self.request.user.is_authenticated:
            return [permissions.IsAuthenticated()]
        
        # Check if user has role attribute and is superadmin
        if hasattr(self.request.user, 'role') and self.request.user.role == 'superadmin':
            return super().get_permissions()
        else:
            return [permissions.IsAuthenticated()]
    
    def list(self, request, *args, **kwargs):
        """List medications with proper pagination"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated_response = self.get_paginated_response(serializer.data)
            
            # Transform to expected format
            return Response({
                'success': True,
                'data': paginated_response.data['results'],
                'pagination': {
                    'count': paginated_response.data['count'],
                    'next': paginated_response.data['next'],
                    'previous': paginated_response.data['previous'],
                    'page_size': self.pagination_class.page_size,
                    'total_pages': (paginated_response.data['count'] + self.pagination_class.page_size - 1) // self.pagination_class.page_size
                },
                'message': 'Medications retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Medications retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'], url_path='search')
    def search_medications(self, request):
        # Override permissions for this action
        self.permission_classes = [permissions.AllowAny]
        """Enhanced medication search with multiple sources"""
        query = request.query_params.get('q', '').strip()
        limit = int(request.query_params.get('limit', 20))
        include_fda = request.query_params.get('include_fda', 'false').lower() == 'true'
        source = request.query_params.get('source', 'all')  # 'local', 'fda', 'all'
        
        if not query:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_QUERY',
                    'message': 'Search query is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            results = []
            
            # 1. Search local database
            if source in ['local', 'all']:
                local_medications = GlobalMedication.objects.filter(
                    is_active=True
                ).filter(
                    Q(name__icontains=query) |
                    Q(generic_name__icontains=query) |
                    Q(brand_name__icontains=query) |
                    Q(composition__icontains=query) |
                    Q(therapeutic_class__icontains=query)
                )[:limit]
                
                for med in local_medications:
                    results.append({
                        'id': f"local_{med.id}",
                        'name': med.name,
                        'generic_name': med.generic_name,
                        'brand_name': med.brand_name,
                        'strength': med.strength,
                        'dosage_form': med.get_dosage_form_display(),
                        'source': 'local_database',
                        'therapeutic_class': med.therapeutic_class,
                        'is_verified': med.is_verified,
                        'medication_type': med.get_medication_type_display(),
                        'composition': med.composition,
                        'indication': med.indication,
                        'manufacturer': med.manufacturer
                    })
            
            # 2. Search FDA API if requested
            if source in ['fda', 'all'] and include_fda and len(results) < limit:
                fda_limit = limit - len(results)
                fda_results = search_fda_medications(query, fda_limit)
                
                for fda_med in fda_results:
                    results.append({
                        'id': fda_med['id'],
                        'name': fda_med['name'],
                        'generic_name': fda_med['generic_name'],
                        'brand_name': fda_med['brand_name'],
                        'strength': fda_med['strength'],
                        'dosage_form': fda_med['dosage_form'],
                        'source': 'fda_api',
                        'therapeutic_class': fda_med['therapeutic_class'],
                        'is_verified': fda_med['is_verified'],
                        'medication_type': fda_med['medication_type'],
                        'composition': fda_med['composition'],
                        'indication': fda_med['indication'],
                        'manufacturer': fda_med['manufacturer']
                    })
            
            return Response({
                'success': True,
                'data': {
                    'medications': results,
                    'total_found': len(results),
                    'query': query,
                    'sources_searched': ['local_database'] + (['fda_api'] if include_fda else [])
                },
                'message': 'Medications found successfully',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'SEARCH_ERROR',
                    'message': f'Error searching medications: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='bulk-create')
    def bulk_create_medications(self, request):
        """Bulk create medications from CSV or JSON"""
        try:
            medications_data = request.data.get('medications', [])
            
            if not medications_data:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MISSING_DATA',
                        'message': 'Medications data is required'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            created_count = 0
            errors = []
            
            for med_data in medications_data:
                try:
                    serializer = GlobalMedicationCreateSerializer(data=med_data, context={'request': request})
                    if serializer.is_valid():
                        serializer.save()
                        created_count += 1
                    else:
                        errors.append({
                            'data': med_data,
                            'errors': serializer.errors
                        })
                except Exception as e:
                    errors.append({
                        'data': med_data,
                        'error': str(e)
                    })
            
            return Response({
                'success': True,
                'data': {
                    'created_count': created_count,
                    'total_attempted': len(medications_data),
                    'errors': errors
                },
                'message': f'Successfully created {created_count} medications',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'BULK_CREATE_ERROR',
                    'message': f'Error in bulk creation: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='import-from-fda')
    def import_from_fda(self, request):
        """Import medications from FDA API into local database"""
        try:
            drug_name = request.data.get('drug_name', '').strip()
            
            if not drug_name:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MISSING_DRUG_NAME',
                        'message': 'Drug name is required'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get FDA medication details
            fda_medication = get_fda_medication_details(drug_name)
            
            if not fda_medication:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'FDA_MEDICATION_NOT_FOUND',
                        'message': f'Medication "{drug_name}" not found in FDA database'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if medication already exists
            existing_medication = GlobalMedication.objects.filter(
                name__iexact=fda_medication['name']
            ).first()
            
            if existing_medication:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MEDICATION_EXISTS',
                        'message': f'Medication "{fda_medication["name"]}" already exists in local database'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_409_CONFLICT)
            
            # Create new medication
            medication_data = {
                'name': fda_medication['name'],
                'generic_name': fda_medication['generic_name'],
                'brand_name': fda_medication['brand_name'],
                'composition': fda_medication['composition'],
                'dosage_form': fda_medication['dosage_form'],
                'strength': fda_medication['strength'],
                'medication_type': fda_medication['medication_type'],
                'therapeutic_class': fda_medication['therapeutic_class'],
                'indication': fda_medication['indication'],
                'contraindications': fda_medication['contraindications'],
                'side_effects': fda_medication['side_effects'],
                'dosage_instructions': fda_medication['dosage_instructions'],
                'frequency_options': fda_medication['frequency_options'],
                'timing_options': fda_medication['timing_options'],
                'manufacturer': fda_medication['manufacturer'],
                'license_number': fda_medication['license_number'],
                'is_prescription_required': fda_medication['is_prescription_required'],
                'is_active': True,
                'is_verified': True,
                'created_by': request.user
            }
            
            new_medication = GlobalMedication.objects.create(**medication_data)
            
            serializer = GlobalMedicationSerializer(new_medication)
            
            return Response({
                'success': True,
                'data': {
                    'medication': serializer.data,
                    'source': 'fda_api'
                },
                'message': f'Successfully imported "{fda_medication["name"]}" from FDA database',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'IMPORT_ERROR',
                    'message': f'Error importing from FDA: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='auto-create', permission_classes=[permissions.AllowAny])
    def auto_create_medication(self, request):
        """Auto-create medication in global catalog - public access for consultation workspace"""
        try:
            name = request.data.get('name', '').strip()
            composition = request.data.get('composition', '').strip()
            dosage_form = request.data.get('dosage_form', 'Tablet').strip()
            
            if not name:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MISSING_NAME',
                        'message': 'Medication name is required'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if medication already exists
            existing_medication = GlobalMedication.objects.filter(
                name__iexact=name
            ).first()
            
            if existing_medication:
                return Response({
                    'success': True,
                    'data': {
                        'medication': GlobalMedicationSerializer(existing_medication).data,
                        'source': 'existing_database'
                    },
                    'message': f'Medication "{name}" already exists in database',
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_200_OK)
            
            # Create new medication
            medication_data = {
                'name': name,
                'generic_name': name,  # Use name as generic name if not provided
                'composition': composition or name,
                'dosage_form': dosage_form,
                'strength': 'As prescribed',  # Default strength
                'medication_type': 'prescription',  # Default type
                'therapeutic_class': 'General',  # Default class
                'is_prescription_required': True,
                'is_active': True,
                'is_verified': False,  # Not verified since it's auto-created
                'created_by': request.user if request.user.is_authenticated else None
            }
            
            new_medication = GlobalMedication.objects.create(**medication_data)
            
            serializer = GlobalMedicationSerializer(new_medication)
            
            return Response({
                'success': True,
                'data': {
                    'medication': serializer.data,
                    'source': 'auto_created'
                },
                'message': f'Successfully created medication "{name}"',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CREATE_ERROR',
                    'message': f'Error creating medication: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@permission_classes([])
def public_auto_create_medication(request):
    """Public auto-create medication endpoint - no authentication required"""
    try:
        name = request.data.get('name', '').strip()
        composition = request.data.get('composition', '').strip()
        dosage_form = request.data.get('dosage_form', 'Tablet').strip()
        
        if not name:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_NAME',
                    'message': 'Medication name is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if medication already exists
        existing_medication = GlobalMedication.objects.filter(
            name__iexact=name
        ).first()
        
        if existing_medication:
            return Response({
                'success': True,
                'data': {
                    'medication': GlobalMedicationSerializer(existing_medication).data,
                    'source': 'existing_database'
                },
                'message': f'Medication "{name}" already exists in database',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        
        # Create new medication
        medication_data = {
            'name': name,
            'generic_name': name,  # Use name as generic name if not provided
            'composition': composition or name,
            'dosage_form': dosage_form,
            'strength': 'As prescribed',  # Default strength
            'medication_type': 'prescription',  # Default type
            'therapeutic_class': 'General',  # Default class
            'is_prescription_required': True,
            'is_active': True,
            'is_verified': False,  # Not verified since it's auto-created
            'created_by': None  # No user for public creation
        }
        
        new_medication = GlobalMedication.objects.create(**medication_data)
        
        serializer = GlobalMedicationSerializer(new_medication)
        
        return Response({
            'success': True,
            'data': {
                'medication': serializer.data,
                'source': 'auto_created'
            },
            'message': f'Successfully created medication "{name}"',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'CREATE_ERROR',
                'message': f'Error creating medication: {str(e)}'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ClinicInventoryViewSet(ModelViewSet):
    """ViewSet for clinic inventory management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get inventory for specific clinic"""
        clinic_id = self.kwargs.get('clinic_id')
        return ClinicInventory.objects.filter(clinic_id=clinic_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ClinicInventoryCreateSerializer
        return ClinicInventorySerializer
    
    def perform_create(self, serializer):
        """Set clinic_id when creating inventory item"""
        clinic_id = self.kwargs.get('clinic_id')
        serializer.save(clinic_id=clinic_id)

    @action(detail=False, methods=['get'], url_path='medications/search')
    def search_medications(self, request, clinic_id=None):
        """Search medications in global catalog and clinic inventory"""
        query = request.query_params.get('q', '').strip()
        limit = int(request.query_params.get('limit', 10))
        
        if not query:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_QUERY',
                    'message': 'Search query is required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            results = []
            
            # 1. Search in global medication catalog
            global_medications = GlobalMedication.objects.filter(
                is_active=True
            ).filter(
                Q(name__icontains=query) |
                Q(generic_name__icontains=query) |
                Q(brand_name__icontains=query) |
                Q(composition__icontains=query)
            )[:limit]
            
            for med in global_medications:
                # Check if this medication exists in clinic inventory
                clinic_inventory = ClinicInventory.objects.filter(
                    clinic_id=clinic_id,
                    global_medication=med,
                    is_active=True
                ).first()
                
                results.append({
                    'id': f"global_{med.id}",
                    'name': med.display_name,
                    'strength': med.strength or '',
                    'form': med.get_dosage_form_display(),
                    'source': 'global_catalog',
                    'stock': clinic_inventory.current_stock if clinic_inventory else 0,
                    'unit': clinic_inventory.unit if clinic_inventory else 'units',
                    'is_low_stock': clinic_inventory.is_low_stock if clinic_inventory else True,
                    'expiry_date': clinic_inventory.expiry_date if clinic_inventory else None,
                    'supplier': clinic_inventory.supplier_name if clinic_inventory else None,
                    'global_medication_id': med.id,
                    'composition': med.composition,
                    'therapeutic_class': med.therapeutic_class,
                    'frequency_options': med.frequency_options,
                    'timing_options': med.timing_options
                })
            
            # 2. Search in clinic inventory (medicines only) - for clinic-specific items
            inventory_medications = ClinicInventory.objects.filter(
                clinic_id=clinic_id,
                category='medicine',
                is_active=True,
                global_medication__isnull=True  # Only clinic-specific items
            ).filter(
                Q(item_name__icontains=query) |
                Q(description__icontains=query) |
                Q(brand__icontains=query)
            )[:limit]
            
            for med in inventory_medications:
                results.append({
                    'id': f"inventory_{med.id}",
                    'name': med.item_name,
                    'strength': med.description or '',
                    'form': med.brand or 'Tablet',
                    'source': 'clinic_inventory',
                    'stock': med.current_stock,
                    'unit': med.unit,
                    'is_low_stock': med.is_low_stock,
                    'expiry_date': med.expiry_date,
                    'supplier': med.supplier_name,
                    'global_medication_id': None,
                    'composition': med.description,
                    'therapeutic_class': '',
                    'frequency_options': [],
                    'timing_options': []
                })
            
            # 3. Search in previously prescribed medications (from prescriptions in this clinic)
            try:
                clinic_prescriptions = PrescriptionMedication.objects.filter(
                    prescription__consultation__clinic_id=clinic_id
                ).filter(
                    Q(medicine_name__icontains=query) |
                    Q(composition__icontains=query) |
                    Q(dosage_form__icontains=query)
                ).values('medicine_name', 'composition', 'dosage_form').distinct()[:limit]
                
                # If no clinic-specific prescriptions found, search all prescriptions by doctors in this clinic
                if not clinic_prescriptions.exists():
                    clinic_prescriptions = PrescriptionMedication.objects.filter(
                        prescription__doctor__clinic_associations__clinic_id=clinic_id
                    ).filter(
                        Q(medicine_name__icontains=query) |
                        Q(composition__icontains=query) |
                        Q(dosage_form__icontains=query)
                    ).values('medicine_name', 'composition', 'dosage_form').distinct()[:limit]
            except Exception as e:
                # If there's an issue with clinic relationships, search all medications
                clinic_prescriptions = PrescriptionMedication.objects.filter(
                    Q(medicine_name__icontains=query) |
                    Q(composition__icontains=query) |
                    Q(dosage_form__icontains=query)
                ).values('medicine_name', 'composition', 'dosage_form').distinct()[:limit]
            
            # Add prescribed medications (avoid duplicates)
            existing_names = {med['name'] for med in results}
            for med in clinic_prescriptions:
                if med['medicine_name'] not in existing_names:
                    results.append({
                        'id': f"prescribed_{med['medicine_name']}",
                        'name': med['medicine_name'],
                        'strength': med['composition'] or '',
                        'form': med['dosage_form'] or 'Tablet',
                        'source': 'previously_prescribed',
                        'stock': None,
                        'unit': None,
                        'is_low_stock': None,
                        'expiry_date': None,
                        'supplier': None,
                        'global_medication_id': None,
                        'composition': med['composition'],
                        'therapeutic_class': '',
                        'frequency_options': [],
                        'timing_options': []
                    })
                    existing_names.add(med['medicine_name'])
            
            # Sort by relevance (global catalog first, then inventory, then prescribed)
            def sort_key(x):
                if x['source'] == 'global_catalog':
                    return 0
                elif x['source'] == 'clinic_inventory':
                    return 1
                else:
                    return 2
            
            results.sort(key=sort_key)
            
            return Response({
                'success': True,
                'data': {
                    'medications': results[:limit],
                    'total_found': len(results),
                    'query': query
                },
                'message': 'Medications found successfully',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'SEARCH_ERROR',
                    'message': f'Error searching medications: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='medications/auto-create')
    def auto_create_medication(self, request, clinic_id=None):
        """Auto-create medication in clinic inventory from global catalog"""
        try:
            # First, verify that the clinic exists (optional, can be removed if not needed)
            try:
                clinic = Clinic.objects.get(id=clinic_id)
            except Clinic.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'CLINIC_NOT_FOUND',
                        'message': f'Clinic with ID "{clinic_id}" does not exist. Available clinics: {list(Clinic.objects.values_list("id", flat=True))}'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_404_NOT_FOUND)

            data = request.data
            name = data.get('name', '').strip()
            composition = data.get('composition', '').strip()
            dosage_form = data.get('dosage_form', 'Tablet').strip()
            strength = data.get('strength', '').strip()

            if not name:
                return Response({
                    'success': False,
                    'error': {
                        'code': 'MISSING_DATA',
                        'message': 'Name is required'
                    },
                    'timestamp': timezone.now().isoformat()
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if medication already exists in global catalog
            existing_med = GlobalMedication.objects.filter(name__iexact=name, is_active=True).first()
            if existing_med:
                serializer = GlobalMedicationSerializer(existing_med)
                return Response({
                    'success': True,
                    'data': {
                        'medication': serializer.data,
                        'message': 'Medication already exists in global catalog'
                    },
                    'message': 'Medication found in global catalog',
                    'timestamp': timezone.now().isoformat()
                })

            # Create new global medication
            new_med = GlobalMedication.objects.create(
                name=name,
                composition=composition,
                dosage_form=dosage_form,
                strength=strength,
                is_active=True,
                is_verified=False,
                created_by=request.user
            )
            serializer = GlobalMedicationSerializer(new_med)
            return Response({
                'success': True,
                'data': {
                    'medication': serializer.data,
                    'message': 'Medication created successfully in global catalog'
                },
                'message': 'Medication created successfully',
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'CREATION_ERROR',
                    'message': f'Error creating medication: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ClinicAppointmentViewSet(ModelViewSet):
    """ViewSet for clinic appointment management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get appointments for specific clinic"""
        clinic_id = self.kwargs.get('clinic_id')
        user = self.request.user
        queryset = ClinicAppointment.objects.filter(clinic_id=clinic_id).select_related(
            'patient', 'doctor', 'clinic'
        )
        
        # Filter based on user role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'doctor':
            return queryset.filter(doctor=user)
        
        return queryset
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ClinicAppointmentCreateSerializer
        return ClinicAppointmentSerializer
    
    @action(detail=True, methods=['post'])
    def confirm(self, request, clinic_id=None, pk=None):
        """Confirm appointment"""
        appointment = self.get_object()
        
        if appointment.status != 'scheduled':
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Only scheduled appointments can be confirmed'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        appointment.status = 'confirmed'
        appointment.save()
        
        serializer = ClinicAppointmentSerializer(appointment)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Appointment confirmed successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, clinic_id=None, pk=None):
        """Cancel appointment"""
        appointment = self.get_object()
        
        if appointment.status in ['completed', 'cancelled']:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Cannot cancel completed or already cancelled appointment'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        appointment.status = 'cancelled'
        appointment.save()
        
        serializer = ClinicAppointmentSerializer(appointment)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Appointment cancelled successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class ClinicReviewViewSet(ModelViewSet):
    """ViewSet for clinic review management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get reviews for specific clinic"""
        clinic_id = self.kwargs.get('clinic_id')
        return ClinicReview.objects.filter(clinic_id=clinic_id).select_related('patient', 'clinic')
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ClinicReviewCreateSerializer
        return ClinicReviewSerializer


class ClinicDocumentViewSet(ModelViewSet):
    """ViewSet for clinic document management"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get documents for specific clinic"""
        clinic_id = self.kwargs.get('clinic_id')
        return ClinicDocument.objects.filter(clinic_id=clinic_id)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return ClinicDocumentCreateSerializer
        return ClinicDocumentSerializer


class ClinicSearchView(APIView):
    """Search clinics with advanced filters"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('query', OpenApiTypes.STR, description='Search query'),
            OpenApiParameter('city', OpenApiTypes.STR, description='City filter'),
            OpenApiParameter('state', OpenApiTypes.STR, description='State filter'),
            OpenApiParameter('specialization', OpenApiTypes.STR, description='Specialization filter'),
            OpenApiParameter('service', OpenApiTypes.STR, description='Service filter'),
            OpenApiParameter('is_verified', OpenApiTypes.BOOL, description='Verified clinic filter'),
            OpenApiParameter('latitude', OpenApiTypes.FLOAT, description='Latitude for location search'),
            OpenApiParameter('longitude', OpenApiTypes.FLOAT, description='Longitude for location search'),
            OpenApiParameter('radius_km', OpenApiTypes.FLOAT, description='Search radius in kilometers'),
        ],
        responses={200: ClinicSerializer(many=True)},
        description="Search clinics with advanced filters"
    )
    def get(self, request):
        """Search clinics with advanced filters"""
        serializer = ClinicSearchSerializer(data=request.query_params)
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
        queryset = Clinic.objects.filter(is_active=True)
        
        # Apply role-based filtering
        user = request.user
        if user.role == 'patient':
            queryset = queryset.filter(is_verified=True)
        
        # Apply search filters
        search_data = serializer.validated_data
        
        if search_data.get('query'):
            query = search_data['query']
            queryset = queryset.filter(
                Q(name__icontains=query) |
                Q(description__icontains=query) |
                Q(specialties__icontains=query)
            )
        
        if search_data.get('city'):
            queryset = queryset.filter(city__icontains=search_data['city'])
        
        if search_data.get('state'):
            queryset = queryset.filter(state__icontains=search_data['state'])
        
        if search_data.get('specialization'):
            queryset = queryset.filter(specialties__icontains=search_data['specialization'])
        
        if search_data.get('service'):
            queryset = queryset.filter(
                clinic_services__name__icontains=search_data['service']
            ).distinct()
        
        if search_data.get('is_verified') is not None:
            queryset = queryset.filter(is_verified=search_data['is_verified'])
        
        # Location-based search
        if search_data.get('latitude') and search_data.get('longitude'):
            lat = search_data['latitude']
            lng = search_data['longitude']
            radius = search_data.get('radius_km', 10)
            
            # Simple distance calculation (for more accuracy, use PostGIS)
            queryset = queryset.filter(
                latitude__isnull=False,
                longitude__isnull=False
            ).extra(
                where=[
                    "6371 * acos(cos(radians(%s)) * cos(radians(latitude)) * cos(radians(longitude) - radians(%s)) + sin(radians(%s)) * sin(radians(latitude))) <= %s"
                ],
                params=[lat, lng, lat, radius]
            )
        
        # Paginate results
        paginator = ClinicPagination()
        page = paginator.paginate_queryset(queryset, request)
        
        if page is not None:
            serializer = ClinicSerializer(page, many=True)
            return paginator.get_paginated_response({
                'success': True,
                'data': serializer.data,
                'message': 'Search results retrieved successfully',
                'timestamp': timezone.now().isoformat()
            })
        
        serializer = ClinicSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Search results retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class ClinicStatsView(APIView):
    """Get clinic statistics for dashboard"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: dict},
        description="Get clinic statistics for SuperAdmin dashboard"
    )
    def get(self, request):
        """Get clinic statistics for dashboard"""
        # Check permissions - only SuperAdmin can access
        if request.user.role != 'superadmin':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only SuperAdmin can access clinic statistics'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Calculate basic statistics using database queries (efficient)
        total_clinics = Clinic.objects.count()
        active_clinics = Clinic.objects.filter(is_active=True).count()
        online_consultations = Clinic.objects.filter(accepts_online_consultations=True).count()
        inactive_clinics = Clinic.objects.filter(is_active=False).count()
        
        # Calculate monthly change (clinics created this month vs last month)
        now = timezone.now()
        this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_start = (this_month_start - timedelta(days=1)).replace(day=1)
        
        this_month_clinics = Clinic.objects.filter(created_at__gte=this_month_start).count()
        last_month_clinics = Clinic.objects.filter(
            created_at__gte=last_month_start,
            created_at__lt=this_month_start
        ).count()
        
        monthly_change = this_month_clinics - last_month_clinics
        
        stats_data = {
            'total_clinics': {
                'value': total_clinics,
                'change': f"{'+' if monthly_change >= 0 else ''}{monthly_change}"
            },
            'active_clinics': {
                'value': active_clinics,
                'change': '+0'  # Could calculate this if needed
            },
            'online_consultations': {
                'value': online_consultations,
                'change': '+0'  # Could calculate this if needed
            },
            'inactive_clinics': {
                'value': inactive_clinics,
                'change': '+0'  # Could calculate this if needed
            }
        }
        
        return Response({
            'success': True,
            'data': stats_data,
            'message': 'Clinic statistics retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


class ClinicAnalyticsView(APIView):
    """Get comprehensive analytics for SuperAdmin dashboard"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        responses={200: dict},
        description="Get comprehensive analytics for SuperAdmin dashboard"
    )
    def get(self, request):
        """Get comprehensive analytics data"""
        # Check permissions - only SuperAdmin can access
        if request.user.role != 'superadmin':
            return Response({
                'success': False,
                'error': {
                    'code': 'PERMISSION_DENIED',
                    'message': 'Only SuperAdmin can access clinic analytics'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Time periods
            now = timezone.now()
            last_7_days = now - timedelta(days=7)
            last_30_days = now - timedelta(days=30)
            last_90_days = now - timedelta(days=90)
            
            # Basic metrics
            total_clinics = Clinic.objects.count()
            active_clinics = Clinic.objects.filter(is_active=True).count()
            verified_clinics = Clinic.objects.filter(is_verified=True).count()
            online_clinics = Clinic.objects.filter(accepts_online_consultations=True).count()
            
            # Growth metrics
            new_clinics_7d = Clinic.objects.filter(created_at__gte=last_7_days).count()
            new_clinics_30d = Clinic.objects.filter(created_at__gte=last_30_days).count()
            new_clinics_90d = Clinic.objects.filter(created_at__gte=last_90_days).count()
            
            # Geographic analytics
            city_distribution = Clinic.objects.values('city').annotate(
                count=Count('id')
            ).order_by('-count')[:10] if Clinic.objects.exists() else []
            
            state_distribution = Clinic.objects.values('state').annotate(
                count=Count('id')
            ).order_by('-count')[:10] if Clinic.objects.exists() else []
            
            # Specialization analytics
            all_specialties = []
            if Clinic.objects.exists():
                for clinic in Clinic.objects.all():
                    if clinic.specialties:
                        all_specialties.extend(clinic.specialties)
            
            specialty_counts = {}
            for specialty in all_specialties:
                specialty_counts[specialty] = specialty_counts.get(specialty, 0) + 1
            
            top_specialties = sorted(specialty_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Monthly trends (last 12 months)
            monthly_trends = []
            for i in range(12):
                month_start = now.replace(day=1) - timedelta(days=30*i)
                month_end = month_start.replace(day=1) + timedelta(days=32)
                month_end = month_end.replace(day=1) - timedelta(days=1)
                
                count = Clinic.objects.filter(
                    created_at__gte=month_start,
                    created_at__lte=month_end
                ).count()
                
                monthly_trends.append({
                    'month': month_start.strftime('%B %Y'),
                    'count': count,
                    'period': month_start.strftime('%Y-%m')
                })
            
            monthly_trends.reverse()
            
            # Performance metrics
            verification_rate = round((verified_clinics / total_clinics * 100) if total_clinics > 0 else 0, 1)
            activation_rate = round((active_clinics / total_clinics * 100) if total_clinics > 0 else 0, 1)
            online_rate = round((online_clinics / total_clinics * 100) if total_clinics > 0 else 0, 1)
            
            # Recent activity
            recent_clinics = Clinic.objects.order_by('-created_at')[:5] if Clinic.objects.exists() else []
            recent_activity = []
            for clinic in recent_clinics:
                recent_activity.append({
                    'id': clinic.id,
                    'name': clinic.name,
                    'city': clinic.city,
                    'state': clinic.state,
                    'created_at': clinic.created_at.strftime('%Y-%m-%d'),
                    'is_verified': clinic.is_verified,
                    'is_active': clinic.is_active
                })
            
            analytics = {
                # Overview metrics
                'overview': {
                    'total_clinics': total_clinics,
                    'active_clinics': active_clinics,
                    'verified_clinics': verified_clinics,
                    'online_clinics': online_clinics,
                    'verification_rate': verification_rate,
                    'activation_rate': activation_rate,
                    'online_rate': online_rate
                },
                
                # Growth metrics
                'growth': {
                    'new_clinics_7d': new_clinics_7d,
                    'new_clinics_30d': new_clinics_30d,
                    'new_clinics_90d': new_clinics_90d,
                    'growth_rate_7d': round((new_clinics_7d / total_clinics * 100) if total_clinics > 0 else 0, 1),
                    'growth_rate_30d': round((new_clinics_30d / total_clinics * 100) if total_clinics > 0 else 0, 1),
                    'growth_rate_90d': round((new_clinics_90d / total_clinics * 100) if total_clinics > 0 else 0, 1)
                },
                
                # Geographic data
                'geographic': {
                    'cities': [{'city': item['city'], 'count': item['count']} for item in city_distribution],
                    'states': [{'state': item['state'], 'count': item['count']} for item in state_distribution]
                },
                
                # Specialization data
                'specializations': {
                    'top_specialties': [{'specialty': item[0], 'count': item[1]} for item in top_specialties],
                    'total_specialties': len(specialty_counts)
                },
                
                # Trends
                'trends': {
                    'monthly_growth': monthly_trends,
                    'last_updated': now.strftime('%Y-%m-%d %H:%M:%S')
                },
                
                # Recent activity
                'recent_activity': recent_activity
            }
            
            return Response({
                'success': True,
                'data': analytics,
                'message': 'Analytics data retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'ANALYTICS_ERROR',
                    'message': f'Failed to fetch analytics: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PublicClinicView(APIView):
    """Public endpoint for viewing e-clinics"""
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('page', OpenApiTypes.INT, description='Page number', default=1),
            OpenApiParameter('page_size', OpenApiTypes.INT, description='Items per page', default=20),
            OpenApiParameter('search', OpenApiTypes.STR, description='Search query'),
            OpenApiParameter('city', OpenApiTypes.STR, description='Filter by city'),
            OpenApiParameter('state', OpenApiTypes.STR, description='Filter by state'),
            OpenApiParameter('is_verified', OpenApiTypes.STR, description='Filter by verification status'),
            OpenApiParameter('is_active', OpenApiTypes.STR, description='Filter by active status'),
        ],
        responses={200: ClinicSerializer(many=True)},
        description="Get public list of e-clinics"
    )
    def get(self, request):
        """Get public list of e-clinics"""
        try:
            # Get query parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            search = request.query_params.get('search', '')
            city = request.query_params.get('city', '')
            state = request.query_params.get('state', '')
            is_verified = request.query_params.get('is_verified', '')
            is_active = request.query_params.get('is_active', '')
            
            # Build queryset
            queryset = Clinic.objects.filter(is_active=True)
            
            # Apply filters
            if search:
                queryset = queryset.filter(
                    Q(name__icontains=search) |
                    Q(description__icontains=search) |
                    Q(city__icontains=search) |
                    Q(specialties__icontains=search)
                )
            
            if city:
                queryset = queryset.filter(city__icontains=city)
            
            if state:
                queryset = queryset.filter(state__icontains=state)
            
            if is_verified:
                queryset = queryset.filter(is_verified=is_verified.lower() == 'true')
            
            if is_active:
                queryset = queryset.filter(is_active=is_active.lower() == 'true')
            
            # Pagination
            start = (page - 1) * page_size
            end = start + page_size
            total_count = queryset.count()
            clinics = queryset[start:end]
            
            serializer = ClinicSerializer(clinics, many=True)
            
            return Response({
                'success': True,
                'data': {
                    'results': serializer.data,
                    'count': total_count,
                    'next': f'?page={page + 1}&page_size={page_size}' if end < total_count else None,
                    'previous': f'?page={page - 1}&page_size={page_size}' if page > 1 else None,
                },
                'message': 'E-clinics retrieved successfully',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 'FETCH_ERROR',
                    'message': f'Failed to fetch e-clinics: {str(e)}'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NearbyClinicView(APIView):
    """Find nearby clinics"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('latitude', OpenApiTypes.FLOAT, description='User latitude', required=True),
            OpenApiParameter('longitude', OpenApiTypes.FLOAT, description='User longitude', required=True),
            OpenApiParameter('radius_km', OpenApiTypes.FLOAT, description='Search radius in kilometers', default=10),
            OpenApiParameter('specialization', OpenApiTypes.STR, description='Specialization filter'),
        ],
        responses={200: ClinicSerializer(many=True)},
        description="Find nearby clinics based on location"
    )
    def get(self, request):
        """Find nearby clinics"""
        latitude = request.query_params.get('latitude')
        longitude = request.query_params.get('longitude')
        radius_km = float(request.query_params.get('radius_km', 10))
        specialization = request.query_params.get('specialization')
        
        if not latitude or not longitude:
            return Response({
                'success': False,
                'error': {
                    'code': 'MISSING_PARAMETERS',
                    'message': 'Latitude and longitude are required'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            lat = float(latitude)
            lng = float(longitude)
        except ValueError:
            return Response({
                'success': False,
                'error': {
                    'code': 'INVALID_COORDINATES',
                    'message': 'Invalid latitude or longitude'
                },
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find nearby clinics
        queryset = Clinic.objects.filter(
            is_active=True,
            is_verified=True,
            latitude__isnull=False,
            longitude__isnull=False
        ).extra(
            select={
                'distance': "6371 * acos(cos(radians(%s)) * cos(radians(latitude)) * cos(radians(longitude) - radians(%s)) + sin(radians(%s)) * sin(radians(latitude)))"
            },
            select_params=[lat, lng, lat],
            where=[
                "6371 * acos(cos(radians(%s)) * cos(radians(latitude)) * cos(radians(longitude) - radians(%s)) + sin(radians(%s)) * sin(radians(latitude))) <= %s"
            ],
            params=[lat, lng, lat, radius_km],
            order_by=['distance']
        )
        
        # Apply specialization filter if provided
        if specialization:
            queryset = queryset.filter(specialties__icontains=specialization)
        
        serializer = ClinicSerializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'message': 'Nearby clinics retrieved successfully',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def public_medication_search(request):
    """Public medication search endpoint - no authentication required"""
    query = request.query_params.get('q', '').strip()
    
    # Validate and parse limit parameter
    try:
        limit = int(request.query_params.get('limit', 20))
        if limit <= 0:
            limit = 20
    except (ValueError, TypeError):
        limit = 20
    
    # Validate and parse include_fda parameter
    include_fda_param = request.query_params.get('include_fda', 'false').lower()
    include_fda = include_fda_param in ['true', '1', 'yes', 'on']
    
    source = request.query_params.get('source', 'all')  # 'local', 'fda', 'all'
    
    if not query:
        return Response({
            'success': False,
            'error': {
                'code': 'MISSING_QUERY',
                'message': 'Search query is required'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        results = []
        
        # 1. Search local database
        if source in ['local', 'all']:
            local_medications = GlobalMedication.objects.filter(
                is_active=True
            ).filter(
                Q(name__icontains=query) |
                Q(generic_name__icontains=query) |
                Q(brand_name__icontains=query) |
                Q(composition__icontains=query) |
                Q(therapeutic_class__icontains=query)
            )[:limit]
            
            for med in local_medications:
                results.append({
                    'id': f"local_{med.id}",
                    'name': med.name,
                    'generic_name': med.generic_name,
                    'brand_name': med.brand_name,
                    'strength': med.strength,
                    'dosage_form': med.get_dosage_form_display(),
                    'source': 'local_database',
                    'therapeutic_class': med.therapeutic_class,
                    'is_verified': med.is_verified,
                    'medication_type': med.get_medication_type_display(),
                    'composition': med.composition,
                    'indication': med.indication,
                    'manufacturer': med.manufacturer
                })
        
        # 2. Search FDA API if requested
        if source in ['fda', 'all'] and include_fda and len(results) < limit:
            fda_limit = limit - len(results)
            fda_results = search_fda_medications(query, fda_limit)
            
            for fda_med in fda_results:
                results.append({
                    'id': fda_med['id'],
                    'name': fda_med['name'],
                    'generic_name': fda_med['generic_name'],
                    'brand_name': fda_med['brand_name'],
                    'strength': fda_med['strength'],
                    'dosage_form': fda_med['dosage_form'],
                    'source': 'fda_api',
                    'therapeutic_class': fda_med['therapeutic_class'],
                    'is_verified': fda_med['is_verified'],
                    'medication_type': fda_med['medication_type'],
                    'composition': fda_med['composition'],
                    'indication': fda_med['indication'],
                    'manufacturer': fda_med['manufacturer']
                })
        
        return Response({
            'success': True,
            'data': {
                'medications': results,
                'total_found': len(results),
                'query': query,
                'sources_searched': ['local_database'] + (['fda_api'] if include_fda else [])
            },
            'message': 'Medications found successfully',
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': {
                'code': 'SEARCH_ERROR',
                'message': f'Error searching medications: {str(e)}'
            },
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



