from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import RegexValidator


class Clinic(models.Model):
    """Main e-clinic model (online only)"""

    CLINIC_TYPES = [
        ('virtual_clinic', 'Virtual Clinic'),
    ]

    id = models.CharField(max_length=20, primary_key=True, unique=True, editable=False)
    name = models.CharField(max_length=200)
    clinic_type = models.CharField(max_length=20, choices=CLINIC_TYPES, default='virtual_clinic')
    description = models.TextField(blank=True)

    # Contact Information
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone = models.CharField(validators=[phone_regex], max_length=17)
    email = models.EmailField()
    website = models.URLField(blank=True)

    # Address (for online clinics, can be used for legal/registration purposes)
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    pincode = models.CharField(max_length=10)
    country = models.CharField(max_length=100, default='India')
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    # Operating Hours
    operating_hours = models.JSONField(default=dict, help_text="Operating hours for each day of the week")

    # Services and Specialties
    specialties = models.JSONField(default=list, help_text="List of medical specialties offered")
    services = models.JSONField(default=list, help_text="List of services offered")
    facilities = models.JSONField(default=list, help_text="List of facilities available")

    # Registration and Licensing
    registration_number = models.CharField(max_length=100, unique=True)
    license_number = models.CharField(max_length=100, blank=True)
    accreditation = models.CharField(max_length=200, blank=True)

    # Images and Media
    cover_image = models.ImageField(upload_to='clinic_covers/', blank=True, null=True)
    gallery_images = models.JSONField(default=list, help_text="List of gallery image URLs")

    # Status and Settings
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    accepts_online_consultations = models.BooleanField(default=True)
    
    # Consultation Settings
    consultation_duration = models.PositiveIntegerField(
        default=15,
        help_text="Duration of each consultation slot in minutes"
    )

    # Admin (single admin per e-clinic)
    admin = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='administered_clinic',
        limit_choices_to={'role': 'admin'}
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'clinics'
        verbose_name = 'Clinic'
        verbose_name_plural = 'Clinics'
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.id:
            # Generate clinic ID
            last_clinic = Clinic.objects.order_by('id').last()
            if last_clinic:
                last_number = int(last_clinic.id[3:])
                new_number = last_number + 1
            else:
                new_number = 1
            self.id = f"CLI{new_number:03d}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def full_address(self):
        address_parts = [self.street, self.city, self.state, self.pincode, self.country]
        return ', '.join([part for part in address_parts if part])


class ClinicRoom(models.Model):
    """Rooms/chambers in a clinic"""
    
    ROOM_TYPES = [
        ('consultation', 'Consultation Room'),
        ('procedure', 'Procedure Room'),
        ('emergency', 'Emergency Room'),
        ('icu', 'ICU'),
        ('operation_theater', 'Operation Theater'),
        ('lab', 'Laboratory'),
        ('pharmacy', 'Pharmacy'),
        ('reception', 'Reception'),
        ('waiting', 'Waiting Area'),
        ('other', 'Other'),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='rooms'
    )
    room_number = models.CharField(max_length=20)
    room_type = models.CharField(max_length=20, choices=ROOM_TYPES)
    name = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    
    # Capacity and Equipment
    capacity = models.PositiveIntegerField(default=1)
    equipment = models.JSONField(default=list, help_text="List of equipment in the room")
    
    # Availability
    is_available = models.BooleanField(default=True)
    is_bookable = models.BooleanField(default=True)
    
    # Assigned Doctor (for consultation rooms)
    assigned_doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='assigned_rooms'
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_rooms'
        verbose_name = 'Clinic Room'
        verbose_name_plural = 'Clinic Rooms'
        unique_together = ['clinic', 'room_number']
    
    def __str__(self):
        return f"Room {self.room_number} - {self.clinic.name}"


class ClinicStaff(models.Model):
    """Staff members in a clinic"""
    
    STAFF_ROLES = [
        ('receptionist', 'Receptionist'),
        ('nurse', 'Nurse'),
        ('technician', 'Technician'),
        ('pharmacist', 'Pharmacist'),
        ('admin', 'Administrator'),
        ('manager', 'Manager'),
        ('security', 'Security'),
        ('housekeeping', 'Housekeeping'),
        ('other', 'Other'),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='staff'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='staff_positions'
    )
    
    # Role and Responsibilities
    role = models.CharField(max_length=20, choices=STAFF_ROLES)
    department = models.CharField(max_length=100, blank=True)
    responsibilities = models.TextField(blank=True)
    
    # Employment Details
    employee_id = models.CharField(max_length=50, blank=True)
    hire_date = models.DateField()
    salary = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # Work Schedule
    work_schedule = models.JSONField(default=dict, help_text="Work schedule for the staff member")
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_staff'
        verbose_name = 'Clinic Staff'
        verbose_name_plural = 'Clinic Staff'
        unique_together = ['clinic', 'user']
    
    def __str__(self):
        return f"{self.user.name} - {self.role} at {self.clinic.name}"


class ClinicService(models.Model):
    """Services offered by a clinic"""
    
    SERVICE_CATEGORIES = [
        ('consultation', 'Consultation'),
        ('diagnostic', 'Diagnostic'),
        ('treatment', 'Treatment'),
        ('surgery', 'Surgery'),
        ('emergency', 'Emergency'),
        ('preventive', 'Preventive Care'),
        ('rehabilitation', 'Rehabilitation'),
        ('other', 'Other'),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='clinic_services'
    )
    
    # Service Details
    name = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=SERVICE_CATEGORIES)
    description = models.TextField(blank=True)
    
    # Pricing
    base_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    price_range_min = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    price_range_max = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # Availability
    is_available = models.BooleanField(default=True)
    requires_appointment = models.BooleanField(default=True)
    
    # Duration and Requirements
    estimated_duration = models.PositiveIntegerField(null=True, blank=True, help_text="Duration in minutes")
    preparation_required = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_services'
        verbose_name = 'Clinic Service'
        verbose_name_plural = 'Clinic Services'
    
    def __str__(self):
        return f"{self.name} - {self.clinic.name}"


class ClinicReview(models.Model):
    """Reviews and ratings for clinics"""
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='reviews'
    )
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='clinic_reviews'
    )
    consultation = models.ForeignKey(
        'consultations.Consultation', 
        on_delete=models.CASCADE, 
        related_name='clinic_review',
        null=True, 
        blank=True
    )
    
    # Rating and Review
    overall_rating = models.PositiveIntegerField()
    review_text = models.TextField(blank=True)
    
    # Specific ratings
    cleanliness_rating = models.PositiveIntegerField(null=True, blank=True)
    staff_rating = models.PositiveIntegerField(null=True, blank=True)
    facilities_rating = models.PositiveIntegerField(null=True, blank=True)
    wait_time_rating = models.PositiveIntegerField(null=True, blank=True)
    
    # Status
    is_approved = models.BooleanField(default=True)
    is_anonymous = models.BooleanField(default=False)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_reviews'
        verbose_name = 'Clinic Review'
        verbose_name_plural = 'Clinic Reviews'
        unique_together = ['clinic', 'patient', 'consultation']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Review for {self.clinic.name} by {self.patient.name} - {self.overall_rating}/5"


class GlobalMedication(models.Model):
    """Global medication catalog managed by super admin"""
    
    MEDICATION_FORMS = [
        ('tablet', 'Tablet'),
        ('capsule', 'Capsule'),
        ('syrup', 'Syrup'),
        ('injection', 'Injection'),
        ('cream', 'Cream'),
        ('ointment', 'Ointment'),
        ('drops', 'Drops'),
        ('inhaler', 'Inhaler'),
        ('suppository', 'Suppository'),
        ('other', 'Other'),
    ]
    
    MEDICATION_TYPES = [
        ('generic', 'Generic'),
        ('branded', 'Branded'),
        ('combination', 'Combination'),
    ]
    
    # Basic Information
    name = models.CharField(max_length=200, unique=True)
    generic_name = models.CharField(max_length=200, blank=True)
    brand_name = models.CharField(max_length=200, blank=True)
    composition = models.TextField(blank=True, help_text="Active ingredients and composition")
    
    # Medication Details
    dosage_form = models.CharField(max_length=20, choices=MEDICATION_FORMS, default='tablet')
    strength = models.CharField(max_length=100, blank=True, help_text="e.g., 500mg, 10mg/ml")
    medication_type = models.CharField(max_length=20, choices=MEDICATION_TYPES, default='generic')
    
    # Therapeutic Information
    therapeutic_class = models.CharField(max_length=200, blank=True)
    indication = models.TextField(blank=True, help_text="What this medication is used for")
    contraindications = models.TextField(blank=True)
    side_effects = models.TextField(blank=True)
    
    # Dosage Information
    dosage_instructions = models.TextField(blank=True, help_text="General dosage instructions")
    frequency_options = models.JSONField(default=list, help_text="Available frequency options")
    timing_options = models.JSONField(default=list, help_text="Available timing options")
    
    # Regulatory Information
    manufacturer = models.CharField(max_length=200, blank=True)
    license_number = models.CharField(max_length=100, blank=True)
    is_prescription_required = models.BooleanField(default=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    
    # Metadata
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_medications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'global_medications'
        verbose_name = 'Global Medication'
        verbose_name_plural = 'Global Medications'
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['generic_name']),
            models.Index(fields=['brand_name']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.strength})"
    
    @property
    def display_name(self):
        """Get display name with strength"""
        if self.strength:
            return f"{self.name} {self.strength}"
        return self.name
    
    @property
    def full_name(self):
        """Get full medication name with all details"""
        parts = [self.name]
        if self.strength:
            parts.append(self.strength)
        if self.dosage_form:
            parts.append(f"({self.get_dosage_form_display()})")
        return " ".join(parts)


class ClinicInventory(models.Model):
    """Inventory management for clinics"""
    
    ITEM_CATEGORIES = [
        ('medicine', 'Medicine'),
        ('equipment', 'Medical Equipment'),
        ('supplies', 'Medical Supplies'),
        ('consumables', 'Consumables'),
        ('other', 'Other'),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='inventory'
    )
    
    # Link to global medication (for medicines only)
    global_medication = models.ForeignKey(
        GlobalMedication,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='clinic_inventories',
        help_text="Link to global medication catalog"
    )
    
    # Item Details
    item_name = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=ITEM_CATEGORIES)
    description = models.TextField(blank=True)
    brand = models.CharField(max_length=100, blank=True)
    model_number = models.CharField(max_length=100, blank=True)
    
    # Quantity and Stock
    current_stock = models.PositiveIntegerField(default=0)
    minimum_stock = models.PositiveIntegerField(default=0)
    maximum_stock = models.PositiveIntegerField(default=0)
    unit = models.CharField(max_length=20, default='pieces')
    
    # Pricing
    unit_cost = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    selling_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    # Expiry and Batch
    batch_number = models.CharField(max_length=100, blank=True)
    expiry_date = models.DateField(null=True, blank=True)
    
    # Supplier Information
    supplier_name = models.CharField(max_length=200, blank=True)
    supplier_contact = models.CharField(max_length=100, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_inventory'
        verbose_name = 'Clinic Inventory'
        verbose_name_plural = 'Clinic Inventory'
        unique_together = ['clinic', 'global_medication', 'batch_number']
    
    def __str__(self):
        if self.global_medication:
            return f"{self.global_medication.display_name} - {self.clinic.name}"
        return f"{self.item_name} - {self.clinic.name}"
    
    def save(self, *args, **kwargs):
        # Auto-populate item_name from global_medication if available
        if self.global_medication and not self.item_name:
            self.item_name = self.global_medication.display_name
        super().save(*args, **kwargs)
    
    @property
    def is_low_stock(self):
        """Check if item is low on stock"""
        return self.current_stock <= self.minimum_stock
    
    @property
    def is_expired(self):
        """Check if item is expired"""
        if self.expiry_date:
            return timezone.now().date() > self.expiry_date
        return False



class ClinicAppointment(models.Model):
    """Appointments for clinics"""
    
    STATUS_CHOICES = [
        ("scheduled", "Scheduled"),
        ("completed", "Completed"),
        ("cancelled", "Cancelled"),
        ("rescheduled", "Rescheduled"),
        ("no_show", "No Show"),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name="clinic_appointments"
    )
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name="patient_clinic_appointments"
    )
    doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name="doctor_clinic_appointments"
    )
    
    appointment_date = models.DateField()
    appointment_time = models.TimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="scheduled")
    reason = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "clinic_appointments"
        verbose_name = "Clinic Appointment"
        verbose_name_plural = "Clinic Appointments"
        ordering = ["appointment_date", "appointment_time"]
    
    def __str__(self):
        return f"Appointment for {self.patient.name} with Dr. {self.doctor.name} at {self.clinic.name} on {self.appointment_date} {self.appointment_time}"




class ClinicDocument(models.Model):
    """Documents related to clinics"""
    
    DOCUMENT_TYPES = [
        ("license", "License"),
        ("registration", "Registration"),
        ("accreditation", "Accreditation"),
        ("insurance", "Insurance"),
        ("other", "Other"),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name="clinic_documents"
    )
    
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES)
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to="clinic_documents/")
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name="uploaded_clinic_documents"
    )
    
    # Metadata
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "clinic_documents"
        verbose_name = "Clinic Document"
        verbose_name_plural = "Clinic Documents"
        ordering = ["-uploaded_at"]
    
    def __str__(self):
        return f"{self.title} ({self.document_type}) for {self.clinic.name}"


class ClinicPatient(models.Model):
    """
    Track patients registered/associated with a clinic.
    A patient can belong to multiple clinics.
    """
    
    REGISTRATION_SOURCE = [
        ('admin_created', 'Created by Admin'),
        ('consultation', 'Via Consultation'),
        ('self_registered', 'Self Registered'),
        ('migrated', 'Migrated from existing data'),
    ]
    
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        related_name='clinic_patients'
    )
    patient = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='patient_clinics',
        limit_choices_to={'role': 'patient'}
    )
    
    # Registration details
    registration_source = models.CharField(
        max_length=20, 
        choices=REGISTRATION_SOURCE, 
        default='admin_created'
    )
    registered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='registered_clinic_patients',
        help_text="Admin who registered this patient"
    )
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Metadata
    registered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'clinic_patients'
        verbose_name = 'Clinic Patient'
        verbose_name_plural = 'Clinic Patients'
        unique_together = ['clinic', 'patient']
        ordering = ['-registered_at']
        indexes = [
            models.Index(fields=['clinic', 'is_active']),
            models.Index(fields=['patient', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.patient.name} - {self.clinic.name}"
    
    @classmethod
    def register_patient_to_clinic(cls, patient, clinic, registered_by=None, source='admin_created'):
        """
        Register a patient to a clinic. If already exists, return existing record.
        """
        clinic_patient, created = cls.objects.get_or_create(
            clinic=clinic,
            patient=patient,
            defaults={
                'registered_by': registered_by,
                'registration_source': source,
                'is_active': True
            }
        )
        return clinic_patient, created


