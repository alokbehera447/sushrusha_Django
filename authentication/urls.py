from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Health check
    path('health/', views.health_check, name='health_check'),
    
    # Authentication endpoints
    path('send-otp/', views.SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify_otp'),
    path('refresh/', views.CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # WhatsApp Webhook
    path('whatsapp/webhook/', views.WhatsAppWebhookView.as_view(), name='whatsapp_webhook'),
    
    # Account type lookup
    path('account-type/', views.account_type_lookup, name='account_type_lookup'),
    
    # Profile management
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    
    # Session management
    path('sessions/', views.UserSessionsView.as_view(), name='user_sessions'),
    
    # Admin user management (Admin/SuperAdmin only)
    path('admin/users/', views.AdminUserManagementView.as_view(), name='admin_users'),
    path('admin/users/<str:user_id>/', views.AdminUserDetailView.as_view(), name='admin_user_detail'),
    
    # Admin OTP verification for patient access
    path('admin/patient-access-otp/', views.AdminAccessOTPView.as_view(), name='admin_patient_access_otp'),
    
    # SuperAdmin admin management (SuperAdmin only)
    path('superadmin/admins/', views.AdminManagementView.as_view(), name='admin_management'),
    path('superadmin/admins/stats/', views.AdminStatsView.as_view(), name='admin_stats'),
    path('superadmin/admins/<str:admin_id>/', views.AdminDetailView.as_view(), name='admin_detail'),
]

