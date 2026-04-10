from django.contrib import admin
from .models import (
    Payment, PaymentMethod, PaymentRefund,
    PaymentTransaction, PaymentDiscount, PaymentDiscountUsage,
    RazorpayOrder,
)


@admin.register(RazorpayOrder)
class RazorpayOrderAdmin(admin.ModelAdmin):
    list_display  = ('razorpay_order_id', 'patient', 'amount', 'currency',
                     'status', 'is_verified', 'created_at')
    list_filter   = ('status', 'is_verified', 'currency')
    search_fields = ('razorpay_order_id', 'razorpay_payment_id',
                     'patient__name', 'receipt')
    readonly_fields = ('razorpay_order_id', 'razorpay_payment_id',
                       'razorpay_signature', 'order_response',
                       'payment_response', 'created_at', 'updated_at')
    ordering = ('-created_at',)


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display  = ('id', 'patient', 'amount', 'payment_method',
                     'status', 'gateway_name', 'created_at')
    list_filter   = ('status', 'payment_method', 'payment_type', 'gateway_name')
    search_fields = ('id', 'patient__name', 'gateway_transaction_id',
                     'description')
    readonly_fields = ('id', 'gateway_response', 'created_at', 'updated_at')
    ordering = ('-created_at',)


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'method_type', 'is_default', 'is_active', 'created_at')
    list_filter  = ('method_type', 'is_default', 'is_active')


@admin.register(PaymentRefund)
class PaymentRefundAdmin(admin.ModelAdmin):
    list_display  = ('id', 'payment', 'refund_amount', 'status', 'created_at')
    list_filter   = ('status', 'reason')
    readonly_fields = ('id', 'gateway_refund_id', 'gateway_response',
                       'created_at', 'updated_at')


@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display  = ('payment', 'transaction_type', 'amount',
                     'is_successful', 'created_at')
    list_filter   = ('transaction_type', 'is_successful')
    readonly_fields = ('gateway_transaction_id', 'gateway_response', 'created_at')


@admin.register(PaymentDiscount)
class PaymentDiscountAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'discount_type', 'discount_value',
                    'is_active', 'valid_from', 'valid_until')
    list_filter  = ('discount_type', 'is_active')
    search_fields = ('code', 'name')


@admin.register(PaymentDiscountUsage)
class PaymentDiscountUsageAdmin(admin.ModelAdmin):
    list_display = ('discount', 'payment', 'user', 'discount_amount', 'used_at')
