from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from decimal import Decimal


class Payment(models.Model):
    """Main payment model"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
        ('partially_refunded', 'Partially Refunded'),
    ]
    
    PAYMENT_METHODS = [
        ('card', 'Credit/Debit Card'),
        ('upi', 'UPI'),
        ('net_banking', 'Net Banking'),
        ('wallet', 'Digital Wallet'),
        ('cash', 'Cash'),
        ('bank_transfer', 'Bank Transfer'),
        ('insurance', 'Insurance'),
        ('other', 'Other'),
    ]
    
    PAYMENT_TYPES = [
        ('consultation', 'Consultation Fee'),
        ('prescription', 'Prescription'),
        ('lab_test', 'Lab Test'),
        ('procedure', 'Medical Procedure'),
        ('follow_up', 'Follow-up'),
        ('cancellation_fee', 'Cancellation Fee'),
        ('other', 'Other'),
    ]
    
    id = models.CharField(max_length=20, primary_key=True, unique=True, editable=False)
    
    # Related entities
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='payments'
    )
    doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='received_payments',
        null=True, blank=True
    )
    consultation = models.ForeignKey(
        'consultations.Consultation', 
        on_delete=models.CASCADE, 
        related_name='payments',
        null=True, blank=True
    )
    
    # Payment Details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='INR')
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPES, default='consultation')
    description = models.CharField(max_length=200)
    
    # Payment Method
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHODS)
    payment_method_details = models.JSONField(default=dict, help_text="Additional payment method details")
    
    # Status and Processing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Gateway Information
    gateway_name = models.CharField(max_length=50, blank=True, help_text="Payment gateway used")
    gateway_transaction_id = models.CharField(max_length=100, blank=True)
    gateway_response = models.JSONField(default=dict, help_text="Gateway response data")
    
    # Fees and Charges
    platform_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    gateway_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    net_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Timestamps
    initiated_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    
    # Failure Information
    failure_reason = models.TextField(blank=True)
    failure_code = models.CharField(max_length=50, blank=True)
    
    # Receipt
    receipt_number = models.CharField(max_length=50, blank=True)
    receipt_url = models.URLField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payments'
        verbose_name = 'Payment'
        verbose_name_plural = 'Payments'
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        if not self.id:
            # Generate payment ID
            # Safe ID generation
            last_payment = Payment.objects.filter(id__startswith='PAY').order_by('id').last()
            new_number = 1
            if last_payment and last_payment.id[3:].isdigit():
                new_number = int(last_payment.id[3:]) + 1
            else:
                new_number = Payment.objects.count() + 1

            
            self.id = f"PAY{new_number:03d}"
        
        # Calculate net amount
        self.net_amount = self.amount - self.discount_amount + self.platform_fee + self.gateway_fee + self.tax_amount
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Payment {self.id} - {self.patient.name} - ₹{self.amount}"
    
    @property
    def is_successful(self):
        """Check if payment is successful"""
        return self.status == 'completed'
    
    @property
    def is_refundable(self):
        """Check if payment can be refunded"""
        return self.status in ['completed'] and not self.refunds.exists()


class PaymentMethod(models.Model):
    """Saved payment methods for users"""
    
    METHOD_TYPES = [
        ('card', 'Credit/Debit Card'),
        ('upi', 'UPI'),
        ('bank_account', 'Bank Account'),
        ('wallet', 'Digital Wallet'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='payment_methods'
    )
    method_type = models.CharField(max_length=20, choices=METHOD_TYPES)
    
    # Card Details (encrypted)
    card_last_four = models.CharField(max_length=4, blank=True)
    card_brand = models.CharField(max_length=20, blank=True)
    card_expiry_month = models.CharField(max_length=2, blank=True)
    card_expiry_year = models.CharField(max_length=4, blank=True)
    
    # UPI Details
    upi_id = models.CharField(max_length=100, blank=True)
    
    # Bank Account Details
    bank_name = models.CharField(max_length=100, blank=True)
    account_last_four = models.CharField(max_length=4, blank=True)
    
    # Wallet Details
    wallet_provider = models.CharField(max_length=50, blank=True)
    wallet_phone = models.CharField(max_length=15, blank=True)
    
    # Gateway Information
    gateway_method_id = models.CharField(max_length=100, blank=True)
    gateway_customer_id = models.CharField(max_length=100, blank=True)
    
    # Settings
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    nickname = models.CharField(max_length=50, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payment_methods'
        verbose_name = 'Payment Method'
        verbose_name_plural = 'Payment Methods'
        ordering = ['-is_default', '-created_at']
    
    def __str__(self):
        if self.method_type == 'card':
            return f"**** {self.card_last_four} ({self.card_brand})"
        elif self.method_type == 'upi':
            return f"UPI: {self.upi_id}"
        elif self.method_type == 'bank_account':
            return f"{self.bank_name} **** {self.account_last_four}"
        elif self.method_type == 'wallet':
            return f"{self.wallet_provider} - {self.wallet_phone}"
        return f"{self.method_type} - {self.user.name}"


class PaymentRefund(models.Model):
    """Payment refund model"""
    
    REFUND_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    REFUND_REASONS = [
        ('consultation_cancelled', 'Consultation Cancelled'),
        ('doctor_unavailable', 'Doctor Unavailable'),
        ('technical_issue', 'Technical Issue'),
        ('patient_request', 'Patient Request'),
        ('duplicate_payment', 'Duplicate Payment'),
        ('other', 'Other'),
    ]
    
    id = models.CharField(max_length=20, primary_key=True, unique=True, editable=False)
    payment = models.ForeignKey(
        Payment, 
        on_delete=models.CASCADE, 
        related_name='refunds'
    )
    
    # Refund Details
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.CharField(max_length=30, choices=REFUND_REASONS)
    description = models.TextField(blank=True)
    
    # Status and Processing
    status = models.CharField(max_length=20, choices=REFUND_STATUS, default='pending')
    
    # Gateway Information
    gateway_refund_id = models.CharField(max_length=100, blank=True)
    gateway_response = models.JSONField(default=dict)
    
    # Timestamps
    initiated_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Initiated by
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='initiated_refunds'
    )
    
    # Failure Information
    failure_reason = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payment_refunds'
        verbose_name = 'Payment Refund'
        verbose_name_plural = 'Payment Refunds'
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        if not self.id:
            # Generate refund ID
            last_refund = PaymentRefund.objects.filter(id__startswith='REF').order_by('id').last()
            new_number = 1
            if last_refund and last_refund.id[3:].isdigit():
                new_number = int(last_refund.id[3:]) + 1
            else:
                new_number = PaymentRefund.objects.count() + 1

            
            self.id = f"REF{new_number:03d}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Refund {self.id} - ₹{self.refund_amount} for {self.payment.id}"


class PaymentTransaction(models.Model):
    """Individual payment transaction logs"""
    
    TRANSACTION_TYPES = [
        ('payment', 'Payment'),
        ('refund', 'Refund'),
        ('chargeback', 'Chargeback'),
        ('fee', 'Fee'),
        ('adjustment', 'Adjustment'),
    ]
    
    payment = models.ForeignKey(
        Payment, 
        on_delete=models.CASCADE, 
        related_name='transactions'
    )
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Gateway Information
    gateway_transaction_id = models.CharField(max_length=100)
    gateway_response = models.JSONField(default=dict)
    
    # Status
    is_successful = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'payment_transactions'
        verbose_name = 'Payment Transaction'
        verbose_name_plural = 'Payment Transactions'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.transaction_type} - ₹{self.amount} ({self.payment.id})"


class PaymentDiscount(models.Model):
    """Discount codes and coupons"""
    
    DISCOUNT_TYPES = [
        ('percentage', 'Percentage'),
        ('fixed_amount', 'Fixed Amount'),
        ('free_consultation', 'Free Consultation'),
    ]
    
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    
    # Discount Details
    discount_type = models.CharField(max_length=20, choices=DISCOUNT_TYPES)
    discount_value = models.DecimalField(max_digits=10, decimal_places=2)
    max_discount_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    min_order_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Validity
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    
    # Usage Limits
    max_uses = models.PositiveIntegerField(null=True, blank=True)
    max_uses_per_user = models.PositiveIntegerField(default=1)
    current_uses = models.PositiveIntegerField(default=0)
    
    # Applicability
    applicable_to_first_time_users = models.BooleanField(default=False)
    applicable_doctors = models.ManyToManyField(
        settings.AUTH_USER_MODEL, 
        blank=True,
        related_name='applicable_discounts'
    )
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Metadata
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='created_discounts'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payment_discounts'
        verbose_name = 'Payment Discount'
        verbose_name_plural = 'Payment Discounts'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.code} - {self.name}"
    
    @property
    def is_valid(self):
        """Check if discount is currently valid"""
        now = timezone.now()
        return (
            self.is_active and 
            self.valid_from <= now <= self.valid_until and
            (self.max_uses is None or self.current_uses < self.max_uses)
        )


class PaymentDiscountUsage(models.Model):
    """Track discount usage"""
    
    discount = models.ForeignKey(
        PaymentDiscount, 
        on_delete=models.CASCADE, 
        related_name='usage_records'
    )
    payment = models.ForeignKey(
        Payment, 
        on_delete=models.CASCADE, 
        related_name='discount_usage'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='discount_usage'
    )
    
    # Usage Details
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Metadata
    used_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'payment_discount_usage'
        verbose_name = 'Payment Discount Usage'
        verbose_name_plural = 'Payment Discount Usage'
        unique_together = ['discount', 'payment']
        ordering = ['-used_at']
    
    def __str__(self):
        return f"{self.discount.code} used by {self.user.name} - ₹{self.discount_amount}"


class RazorpayOrder(models.Model):
    """Tracks a Razorpay order through its full lifecycle."""

    STATUS_CHOICES = [
        ('created', 'Created'),
        ('attempted', 'Attempted'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
    ]

    # Link to internal payment record (set after verification)
    payment = models.OneToOneField(
        Payment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='razorpay_order',
    )
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='razorpay_orders',
    )
    consultation = models.ForeignKey(
        'consultations.Consultation',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='razorpay_orders',
    )

    # Razorpay identifiers
    razorpay_order_id = models.CharField(max_length=100, unique=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True)
    razorpay_signature = models.CharField(max_length=255, blank=True)

    # Order details
    amount = models.DecimalField(max_digits=10, decimal_places=2)   # INR
    amount_in_paise = models.PositiveIntegerField()                  # Razorpay uses paise
    currency = models.CharField(max_length=3, default='INR')
    receipt = models.CharField(max_length=100, blank=True)
    notes = models.JSONField(default=dict)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='created')
    is_verified = models.BooleanField(default=False)

    # Full gateway responses
    order_response = models.JSONField(default=dict)
    payment_response = models.JSONField(default=dict)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'razorpay_orders'
        verbose_name = 'Razorpay Order'
        verbose_name_plural = 'Razorpay Orders'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.razorpay_order_id} – ₹{self.amount} ({self.status})"
