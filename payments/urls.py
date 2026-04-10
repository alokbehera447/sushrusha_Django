from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from . import razorpay_views

app_name = 'payments'

# Create router for ViewSets
router = DefaultRouter()
router.register(r'', views.PaymentViewSet, basename='payment')
router.register(r'methods', views.PaymentMethodViewSet, basename='payment-method')
router.register(r'refunds', views.PaymentRefundViewSet, basename='payment-refund')
router.register(r'discounts', views.PaymentDiscountViewSet, basename='payment-discount')

urlpatterns = [
    # ── Razorpay payment gateway ──────────────────────────────────────────
    path('razorpay/create-order/',    razorpay_views.RazorpayCreateOrderView.as_view(),  name='razorpay-create-order'),
    path('razorpay/verify-payment/',  razorpay_views.RazorpayVerifyPaymentView.as_view(), name='razorpay-verify-payment'),
    path('razorpay/webhook/',         razorpay_views.RazorpayWebhookView.as_view(),       name='razorpay-webhook'),
    path('razorpay/refund/',          razorpay_views.RazorpayRefundView.as_view(),        name='razorpay-refund'),
    path('razorpay/order-status/<str:order_id>/', razorpay_views.RazorpayOrderStatusView.as_view(), name='razorpay-order-status'),

    # ── Patient-specific payment endpoints ────────────────────────────────
    path('patient/payments/', views.PatientPaymentsView.as_view(), name='patient-payments'),

    # ── Payment search and statistics ─────────────────────────────────────
    path('search/', views.PaymentSearchView.as_view(), name='payment-search'),
    path('stats/', views.PaymentStatsView.as_view(), name='payment-stats'),

    # ── Payment tracking and analytics ────────────────────────────────────
    path('tracking/', views.PaymentTrackingView.as_view(), name='payment-tracking'),
    path('history/', views.PaymentHistoryView.as_view(), name='payment-history'),
    path('analytics/', views.PaymentAnalyticsView.as_view(), name='payment-analytics'),
    path('receipt/<str:payment_id>/', views.PaymentReceiptView.as_view(), name='payment-receipt'),

    # ── Discount validation ───────────────────────────────────────────────
    path('validate-discount/', views.DiscountValidationView.as_view(), name='validate-discount'),

    # ── Include router URLs for main payment operations ───────────────────
    path('', include(router.urls)),
]
