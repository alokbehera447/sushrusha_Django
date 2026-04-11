# Generated manually for missing prescription tables

from django.db import migrations, models
import django.db.models.deletion
import django.core.validators

class Migration(migrations.Migration):

    dependencies = [
        ('prescriptions', '0002_auto_20250730_1537'),
    ]

    operations = [
        # Create PrescriptionMedication model
        # migrations.CreateModel(
        #     name='PrescriptionMedication',
        #     fields=[
        #         ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
        #         ('medicine_name', models.CharField(help_text='Name of the medicine', max_length=200)),
        #         ('composition', models.CharField(blank=True, help_text='Composition/ingredients', max_length=500)),
        #         ('dosage_form', models.CharField(blank=True, help_text='Tablet, Syrup, Injection, etc.', max_length=100)),
        #         ('morning_dose', models.PositiveIntegerField(default=0, help_text='Morning dose')),
        #         ('afternoon_dose', models.PositiveIntegerField(default=0, help_text='Afternoon dose')),
        #         ('evening_dose', models.PositiveIntegerField(default=0, help_text='Evening dose')),
        #         ('frequency', models.CharField(choices=[('once_daily', 'Once Daily'), ('twice_daily', 'Twice Daily'), ('thrice_daily', 'Thrice Daily'), ('four_times_daily', 'Four Times Daily'), ('sos', 'SOS (As Needed)'), ('custom', 'Custom')], default='once_daily', max_length=20)),
        #         ('timing', models.CharField(choices=[('before_breakfast', 'Before Breakfast'), ('after_breakfast', 'After Breakfast'), ('before_lunch', 'Before Lunch'), ('after_lunch', 'After Lunch'), ('before_dinner', 'Before Dinner'), ('after_dinner', 'After Dinner'), ('bedtime', 'Bedtime'), ('empty_stomach', 'Empty Stomach'), ('with_food', 'With Food'), ('custom', 'Custom')], default='after_breakfast', max_length=20)),
        #         ('custom_timing', models.CharField(blank=True, help_text='Custom timing instructions', max_length=200)),
        #         ('duration_days', models.PositiveIntegerField(blank=True, help_text='Duration in days', null=True)),
        #         ('duration_weeks', models.PositiveIntegerField(blank=True, help_text='Duration in weeks', null=True)),
        #         ('duration_months', models.PositiveIntegerField(blank=True, help_text='Duration in months', null=True)),
        #         ('is_continuous', models.BooleanField(default=False, help_text='Continue indefinitely')),
        #         ('special_instructions', models.TextField(blank=True, help_text='Special instructions for this medication')),
        #         ('notes', models.TextField(blank=True, help_text='Additional notes')),
        #         ('order', models.PositiveIntegerField(default=0, help_text='Order of medication in prescription')),
        #         ('created_at', models.DateTimeField(auto_now_add=True)),
        #         ('updated_at', models.DateTimeField(auto_now=True)),
        #         ('prescription', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='medications', to='prescriptions.prescription')),
        #     ],
        #     options={
        #         'verbose_name': 'Prescription Medication',
        #         'verbose_name_plural': 'Prescription Medications',
        #         'db_table': 'prescription_medications',
        #         'ordering': ['order', 'created_at'],
        #     },
        # ),
        
        # Create PrescriptionVitalSigns model
        # migrations.CreateModel(
        #     name='PrescriptionVitalSigns',
        #     fields=[
        #         ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
        #         ('pulse', models.PositiveIntegerField(blank=True, help_text='Pulse rate in bpm', null=True)),
        #         ('blood_pressure_systolic', models.PositiveIntegerField(blank=True, help_text='Systolic BP', null=True)),
        #         ('blood_pressure_diastolic', models.PositiveIntegerField(blank=True, help_text='Diastolic BP', null=True)),
        #         ('temperature', models.DecimalField(blank=True, decimal_places=1, help_text='Temperature in Celsius', max_digits=4, null=True)),
        #         ('weight', models.DecimalField(blank=True, decimal_places=2, help_text='Weight in kg', max_digits=5, null=True)),
        #         ('height', models.DecimalField(blank=True, decimal_places=2, help_text='Height in cm', max_digits=5, null=True)),
        #         ('respiratory_rate', models.PositiveIntegerField(blank=True, help_text='Respiratory rate per minute', null=True)),
        #         ('oxygen_saturation', models.PositiveIntegerField(blank=True, help_text='Oxygen saturation percentage', null=True, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
        #         ('blood_sugar_fasting', models.DecimalField(blank=True, decimal_places=2, help_text='Fasting blood sugar', max_digits=5, null=True)),
        #         ('blood_sugar_postprandial', models.DecimalField(blank=True, decimal_places=2, help_text='Postprandial blood sugar', max_digits=5, null=True)),
        #         ('hba1c', models.DecimalField(blank=True, decimal_places=2, help_text='HbA1c percentage', max_digits=4, null=True)),
        #         ('notes', models.TextField(blank=True, help_text='Additional notes about vital signs')),
        #         ('created_at', models.DateTimeField(auto_now_add=True)),
        #         ('updated_at', models.DateTimeField(auto_now=True)),
        #         ('prescription', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='vital_signs', to='prescriptions.prescription')),
        #     ],
        #     options={
        #         'verbose_name': 'Prescription Vital Signs',
        #         'verbose_name_plural': 'Prescription Vital Signs',
        #         'db_table': 'prescription_vital_signs',
        #     },
        # ),
    ]
