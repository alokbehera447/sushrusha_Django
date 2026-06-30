from rest_framework.routers import DefaultRouter
from django.urls import path, include, re_path
from .views import (
    PrescriptionViewSet, 
    PrescriptionMedicationViewSet, 
    PrescriptionVitalSignsViewSet,
    InvestigationViewSet,
    PrescriptionInvestigationViewSet
)

router = DefaultRouter()
router.register(r'', PrescriptionViewSet, basename='prescription')

# Nested routers for medications and vital signs
medication_router = DefaultRouter()
medication_router.register(r'medications', PrescriptionMedicationViewSet, basename='prescription-medication')

vital_signs_router = DefaultRouter()
vital_signs_router.register(r'vital-signs', PrescriptionVitalSignsViewSet, basename='prescription-vital-signs')

# Custom endpoints (must come before router.urls to avoid conflicts)
custom_urlpatterns = [
    # Draft and finalized endpoints (must come before router to avoid conflicts)
    path('drafts/', PrescriptionViewSet.as_view({'get': 'drafts'}), name='prescription-drafts'),
    path('finalized/', PrescriptionViewSet.as_view({'get': 'finalized'}), name='prescription-finalized'),
    
    # Consultation-specific prescription endpoint
    path('consultation/<str:consultation_id>/', PrescriptionViewSet.as_view({'get': 'by_consultation'}), name='prescription-by-consultation'),
    
    # Patient-specific endpoints
    path('patient/<str:patient_id>/', PrescriptionViewSet.as_view({'get': 'by_patient'}), name='prescription-by-patient'),
    path('patient/<int:patient_id>/pdfs/', PrescriptionViewSet.as_view({'get': 'patient_pdfs'}), name='patient-prescription-pdfs'),
    
    # PDF-related endpoints for individual prescriptions
    path('<int:pk>/pdf-versions/', PrescriptionViewSet.as_view({'get': 'pdf_versions'}), name='prescription-pdf-versions'),
    re_path(r'^(?P<pk>\d+)/pdf/(?P<version>[^/]+)/$', PrescriptionViewSet.as_view({'get': 'download_pdf'}), name='prescription-download-pdf'),
    
    # Other action endpoints
    path('<int:pk>/finalize/', PrescriptionViewSet.as_view({'post': 'finalize'}), name='prescription-finalize'),
    path('<int:pk>/save-draft/', PrescriptionViewSet.as_view({'post': 'save_draft'}), name='prescription-save-draft'),
    path('<int:pk>/auto-save/', PrescriptionViewSet.as_view({'post': 'auto_save'}), name='prescription-auto-save'),
    path('<int:pk>/finalize-and-generate-pdf/', PrescriptionViewSet.as_view({'post': 'finalize_and_generate_pdf'}), name='prescription-finalize-and-generate-pdf'),
    
    # Public verification endpoint (no authentication required)
    path('verify/<int:prescription_id>/', PrescriptionViewSet.as_view({'get': 'verify_prescription'}), name='prescription-verify'),
    
    # Investigation URLs
    path('investigations/', InvestigationViewSet.as_view({
        'get': 'list_all',
        'post': 'create'
    }), name='investigation-list'),
    path('investigations/categories/', InvestigationViewSet.as_view({
        'get': 'categories'
    }), name='investigation-categories'),
    path('investigations/tests/', InvestigationViewSet.as_view({
        'get': 'tests',
        'post': 'create_test'
    }), name='investigation-tests'),
    path('investigations/tests/<int:test_pk>/', InvestigationViewSet.as_view({
        'patch': 'update_test',
        'delete': 'delete_test'
    }), name='investigation-test-detail'),
    path('investigations/auto-create/', InvestigationViewSet.as_view({
        'post': 'auto_create'
    }), name='investigation-auto-create'),

    # Prescription Investigation URLs
    path('investigations/prescription/', PrescriptionInvestigationViewSet.as_view({
        'get': 'list',
        'post': 'add_to_prescription'
    }), name='prescription-investigation-list'),
    path('investigations/prescription/remove/', PrescriptionInvestigationViewSet.as_view({
        'delete': 'remove_from_prescription'
    }), name='prescription-investigation-remove'),
    path('investigations/prescription/<int:pk>/', PrescriptionInvestigationViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='prescription-investigation-detail'),
]

# Nested routes for prescription medications and vital signs
nested_urlpatterns = [
    path('<int:prescription_pk>/', include(medication_router.urls)),
    path('<int:prescription_pk>/', include(vital_signs_router.urls)),
]

# Combine all URL patterns - put router URLs first to handle standard CRUD operations
urlpatterns = router.urls + custom_urlpatterns + nested_urlpatterns

