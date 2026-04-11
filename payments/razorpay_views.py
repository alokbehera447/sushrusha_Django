"""
Razorpay Payment Gateway Integration
=====================================
Flow:
  1. POST /api/payments/razorpay/create-order/   → Create Razorpay order, return order_id
  2. Frontend opens Razorpay checkout with order_id
  3. POST /api/payments/razorpay/verify-payment/ → Verify HMAC signature, mark payment done
  4. POST /api/payments/razorpay/webhook/         → Razorpay server-to-server events (optional)

All views use the `requests` library to call Razorpay's REST API directly,
bypassing the razorpay SDK (which has a pkg_resources dependency issue).
"""

import hmac
import hashlib
import json
import logging
import uuid
from decimal import Decimal

import requests
from django.conf import settings
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Payment, PaymentTransaction, RazorpayOrder
from consultations.models import Consultation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Razorpay API helpers
# ---------------------------------------------------------------------------

RAZORPAY_BASE_URL = "https://api.razorpay.com/v1"


def _razorpay_auth():
    """Return HTTP Basic-Auth tuple from Django settings."""
    return (settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)


def _create_razorpay_order(amount_paise: int, currency: str, receipt: str, notes: dict) -> dict:
    """
    Call Razorpay Orders API.
    Returns the raw JSON response dict.
    Raises requests.HTTPError on failure.
    """
    payload = {
        "amount": amount_paise,
        "currency": currency,
        "receipt": receipt,
        "notes": notes,
        "payment_capture": 1,   # auto-capture on successful payment
    }
    response = requests.post(
        f"{RAZORPAY_BASE_URL}/orders",
        json=payload,
        auth=_razorpay_auth(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def _verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
    """
    Verify HMAC-SHA256 signature sent by Razorpay after checkout.
    message = razorpay_order_id + "|" + razorpay_payment_id
    """
    message = f"{order_id}|{payment_id}"
    expected = hmac.new(
        settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_webhook_signature(body: bytes, signature: str) -> bool:
    """
    Verify Razorpay webhook signature (server-to-server).
    Requires RAZORPAY_WEBHOOK_SECRET in settings.
    """
    webhook_secret = getattr(settings, "RAZORPAY_WEBHOOK_SECRET", "")
    if not webhook_secret:
        logger.warning("RAZORPAY_WEBHOOK_SECRET not set – skipping webhook signature check")
        return True  # Allow but log warning

    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _fetch_razorpay_payment(payment_id: str) -> dict:
    """Fetch payment details from Razorpay."""
    response = requests.get(
        f"{RAZORPAY_BASE_URL}/payments/{payment_id}",
        auth=_razorpay_auth(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def _initiate_razorpay_refund(payment_id: str, amount_paise: int, notes: dict) -> dict:
    """Initiate a refund via Razorpay."""
    payload = {"amount": amount_paise, "notes": notes}
    response = requests.post(
        f"{RAZORPAY_BASE_URL}/payments/{payment_id}/refund",
        json=payload,
        auth=_razorpay_auth(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

class RazorpayCreateOrderView(APIView):
    """
    POST /api/payments/razorpay/create-order/

    Create a Razorpay order. The frontend uses the returned `order_id` to
    open the Razorpay checkout modal.

    Request body:
        amount          (number, required)  – amount in INR (e.g. 500.00)
        currency        (str, optional)     – default "INR"
        consultation_id (str, optional)     – link to a consultation
        description     (str, optional)     – brief description / notes

    Response:
        {
            "success": true,
            "data": {
                "order_id":      "order_XXX",
                "amount":        50000,        // paise
                "amount_inr":    500.00,
                "currency":      "INR",
                "key_id":        "rzp_test_...",  // pass to frontend
                "receipt":       "receipt_xxx"
            }
        }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # ── Validate input ────────────────────────────────────────────────
        amount_raw = request.data.get("amount")
        if amount_raw is None:
            return Response(
                {"success": False, "error": {"code": "MISSING_AMOUNT", "message": "amount is required"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            amount_inr = Decimal(str(amount_raw))
            if amount_inr <= 0:
                raise ValueError
        except (ValueError, Exception):
            return Response(
                {"success": False, "error": {"code": "INVALID_AMOUNT", "message": "amount must be a positive number"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        currency = request.data.get("currency", "INR").upper()
        description = request.data.get("description", "Consultation Payment")
        consultation_id = request.data.get("consultation_id")

        # ── Optional: validate consultation ──────────────────────────────
        consultation = None
        if consultation_id:
            try:
                # If user is admin/superadmin, allow any consultation.
                # Otherwise, restrict to consultations belonging to the patient.
                if request.user.role in ('admin', 'superadmin'):
                    consultation = Consultation.objects.get(id=consultation_id)
                else:
                    consultation = Consultation.objects.get(
                        id=consultation_id,
                        patient=request.user,
                    )
            except Consultation.DoesNotExist:
                return Response(
                    {
                        "success": False,
                        "error": {
                            "code": "CONSULTATION_NOT_FOUND",
                            "message": "Consultation not found or does not belong to you",
                        },
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

        # ── Build Razorpay order ──────────────────────────────────────────
        amount_paise = int(amount_inr * 100)  # Razorpay needs paise
        receipt = f"rcpt_{uuid.uuid4().hex[:12]}"
        
        # Use the actual patient ID if it's a consultation payment
        target_patient_user = consultation.patient if consultation else request.user
        
        notes = {
            "patient_id": str(target_patient_user.id),
            "patient_name": getattr(target_patient_user, "name", str(target_patient_user)),
            "consultation_id": str(consultation_id) if consultation_id else "",
            "description": description,
            "initiated_by": str(request.user.id),
        }

        try:
            rzp_order = _create_razorpay_order(
                amount_paise=amount_paise,
                currency=currency,
                receipt=receipt,
                notes=notes,
            )
        except requests.HTTPError as exc:
            logger.error("Razorpay order creation failed: %s", exc)
            try:
                error_detail = exc.response.json()
            except Exception:
                error_detail = str(exc)
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "RAZORPAY_ERROR",
                        "message": "Failed to create Razorpay order",
                        "detail": error_detail,
                    },
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )
        except Exception as exc:
            logger.exception("Unexpected error creating Razorpay order")
            return Response(
                {"success": False, "error": {"code": "SERVER_ERROR", "message": str(exc)}},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # ── Persist RazorpayOrder record ──────────────────────────────────
        rzp_order_record = RazorpayOrder.objects.create(
            patient=target_patient_user, # Associates with the actual patient
            consultation=consultation,
            razorpay_order_id=rzp_order["id"],
            amount=amount_inr,
            amount_in_paise=amount_paise,
            currency=currency,
            receipt=receipt,
            notes=notes,
            status="created",
            order_response=rzp_order,
        )

        logger.info(
            "Razorpay order created: %s for patient %s (₹%s)",
            rzp_order["id"],
            request.user.id,
            amount_inr,
        )

        return Response(
            {
                "success": True,
                "data": {
                    "order_id": rzp_order["id"],
                    "amount": amount_paise,
                    "amount_inr": float(amount_inr),
                    "currency": currency,
                    "key_id": settings.RAZORPAY_KEY_ID,   # frontend needs this
                    "receipt": receipt,
                    "notes": notes,
                    "razorpay_order_db_id": rzp_order_record.id,
                },
                "message": "Razorpay order created successfully",
                "timestamp": timezone.now().isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class RazorpayVerifyPaymentView(APIView):
    """
    POST /api/payments/razorpay/verify-payment/

    Called by the frontend AFTER the customer completes the Razorpay checkout.
    Verifies the HMAC-SHA256 signature, then creates/updates your Payment record.

    Request body:
        razorpay_order_id    (str, required)
        razorpay_payment_id  (str, required)
        razorpay_signature   (str, required)

    Response:
        {
            "success": true,
            "data": {
                "payment_id":          "PAY001",   // internal payment ID
                "razorpay_payment_id": "pay_XXX",
                "status":              "completed"
            }
        }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        order_id  = request.data.get("razorpay_order_id")
        payment_id = request.data.get("razorpay_payment_id")
        signature  = request.data.get("razorpay_signature")

        # ── Basic validation ──────────────────────────────────────────────
        missing = [k for k, v in {
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        }.items() if not v]

        if missing:
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "MISSING_FIELDS",
                        "message": f"Missing required fields: {', '.join(missing)}",
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Find our RazorpayOrder record ─────────────────────────────────
        try:
            # If admin, allow finding any order. Otherwise, only patient's own orders.
            if request.user.role in ('admin', 'superadmin'):
                rzp_order_record = RazorpayOrder.objects.get(
                    razorpay_order_id=order_id,
                )
            else:
                rzp_order_record = RazorpayOrder.objects.get(
                    razorpay_order_id=order_id,
                    patient=request.user,
                )
        except RazorpayOrder.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "error": {"code": "ORDER_NOT_FOUND", "message": "Razorpay order not found"},
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # ── Guard: already verified ───────────────────────────────────────
        if rzp_order_record.is_verified:
            return Response(
                {
                    "success": True,
                    "data": {
                        "payment_id": rzp_order_record.payment.id if rzp_order_record.payment else None,
                        "razorpay_payment_id": rzp_order_record.razorpay_payment_id,
                        "status": "completed",
                    },
                    "message": "Payment already verified",
                    "timestamp": timezone.now().isoformat(),
                },
                status=status.HTTP_200_OK,
            )

        # ── Verify HMAC signature ─────────────────────────────────────────
        if not _verify_razorpay_signature(order_id, payment_id, signature):
            rzp_order_record.status = "failed"
            rzp_order_record.save()
            logger.warning(
                "Razorpay signature verification FAILED for order %s (patient %s)",
                order_id,
                request.user.id,
            )
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "SIGNATURE_INVALID",
                        "message": "Payment signature verification failed. Possible tampering detected.",
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Fetch payment details from Razorpay ───────────────────────────
        try:
            rzp_payment_details = _fetch_razorpay_payment(payment_id)
        except Exception as exc:
            logger.error("Failed to fetch Razorpay payment details: %s", exc)
            rzp_payment_details = {}

        # ── Create internal Payment record ────────────────────────────────
        method_map = {
            "card": "card",
            "upi": "upi",
            "netbanking": "net_banking",
            "wallet": "wallet",
            "emandate": "bank_transfer",
        }
        rzp_method = rzp_payment_details.get("method", "card")
        internal_method = method_map.get(rzp_method, "card")

        # Check for existing pending payment for this consultation to avoid duplicates
        payment = None
        if rzp_order_record.consultation:
            payment = Payment.objects.filter(
                consultation=rzp_order_record.consultation,
                status='pending'
            ).first()

        if payment:
            # Update existing payment
            payment.payment_method = internal_method
            payment.payment_method_details = rzp_payment_details
            payment.status = "completed"
            payment.gateway_name = "razorpay"
            payment.gateway_transaction_id = payment_id
            payment.gateway_response = rzp_payment_details
            payment.processed_at = timezone.now()
            payment.completed_at = timezone.now()
            payment.save()
        else:
            # Create new internal Payment record
            payment = Payment.objects.create(
                patient=rzp_order_record.patient, # Use patient from the order record
                doctor=rzp_order_record.consultation.doctor if rzp_order_record.consultation else None,
                consultation=rzp_order_record.consultation,
                amount=rzp_order_record.amount,
                currency=rzp_order_record.currency,
                payment_type="consultation",
                description=rzp_order_record.notes.get("description", "Consultation Payment"),
                payment_method=internal_method,
                payment_method_details=rzp_payment_details,
                status="completed",
                gateway_name="razorpay",
                gateway_transaction_id=payment_id,
                gateway_response=rzp_payment_details,
                net_amount=rzp_order_record.amount,
                processed_at=timezone.now(),
                completed_at=timezone.now(),
            )

        # ── Update Consultation record status ───────────────────────────
        if rzp_order_record.consultation:
            cons = rzp_order_record.consultation
            cons.payment_status = 'paid'
            cons.is_paid = True
            cons.payment_method = internal_method
            cons.save()

        # ── Update RazorpayOrder record ───────────────────────────────────
        rzp_order_record.razorpay_payment_id = payment_id
        rzp_order_record.razorpay_signature  = signature
        rzp_order_record.status              = "paid"
        rzp_order_record.is_verified         = True
        rzp_order_record.payment             = payment
        rzp_order_record.payment_response    = rzp_payment_details
        rzp_order_record.save()

        # ── Create transaction log ────────────────────────────────────────
        PaymentTransaction.objects.create(
            payment=payment,
            transaction_type="payment",
            amount=payment.amount,
            gateway_transaction_id=payment_id,
            gateway_response=rzp_payment_details,
            is_successful=True,
        )

        logger.info(
            "Razorpay payment verified: order=%s payment=%s amount=₹%s",
            order_id,
            payment_id,
            payment.amount,
        )

        return Response(
            {
                "success": True,
                "data": {
                    "payment_id": payment.id,
                    "razorpay_order_id": order_id,
                    "razorpay_payment_id": payment_id,
                    "amount": float(payment.amount),
                    "currency": payment.currency,
                    "status": "completed",
                    "payment_method": internal_method,
                    "completed_at": payment.completed_at.isoformat(),
                },
                "message": "Payment verified and recorded successfully",
                "timestamp": timezone.now().isoformat(),
            },
            status=status.HTTP_200_OK,
        )


@method_decorator(csrf_exempt, name="dispatch")
class RazorpayWebhookView(APIView):
    """
    POST /api/payments/razorpay/webhook/

    Razorpay server-to-server webhook handler.
    Set this URL in your Razorpay Dashboard → Webhooks.

    Supported events:
        payment.captured   → mark payment completed
        payment.failed     → mark payment failed
        refund.created     → log refund event
        order.paid         → alternative capture event

    Authentication: No JWT – uses X-Razorpay-Signature header.
    For production: set RAZORPAY_WEBHOOK_SECRET in .env and Dashboard.
    """
    permission_classes = []   # Razorpay calls this, not a logged-in user

    def post(self, request):
        # ── Signature verification ────────────────────────────────────────
        signature = request.headers.get("X-Razorpay-Signature", "")
        raw_body  = request.body

        if not _verify_webhook_signature(raw_body, signature):
            logger.warning("Razorpay webhook: invalid signature")
            return Response({"success": False, "error": "Invalid webhook signature"},
                            status=status.HTTP_400_BAD_REQUEST)

        # ── Parse payload ─────────────────────────────────────────────────
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            return Response({"success": False, "error": "Invalid JSON"},
                            status=status.HTTP_400_BAD_REQUEST)

        event   = payload.get("event", "")
        entity  = payload.get("payload", {})

        logger.info("Razorpay webhook received: event=%s", event)

        try:
            if event == "payment.captured":
                self._handle_payment_captured(entity)

            elif event == "payment.failed":
                self._handle_payment_failed(entity)

            elif event == "order.paid":
                self._handle_order_paid(entity)

            elif event == "refund.created":
                self._handle_refund_created(entity)

            else:
                logger.info("Razorpay webhook: unhandled event '%s'", event)

        except Exception as exc:
            logger.exception("Error handling Razorpay webhook event '%s': %s", event, exc)
            # Return 200 anyway so Razorpay doesn't retry indefinitely
            return Response({"success": True, "message": "Webhook received (error logged)"},
                            status=status.HTTP_200_OK)

        return Response({"success": True, "message": "Webhook processed"},
                        status=status.HTTP_200_OK)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_payment_captured(self, entity: dict):
        """payment.captured – payment was authorised and captured."""
        payment_entity = entity.get("payment", {}).get("entity", {})
        rzp_payment_id = payment_entity.get("id")
        rzp_order_id   = payment_entity.get("order_id")

        if not rzp_order_id:
            return

        try:
            rzp_record = RazorpayOrder.objects.get(razorpay_order_id=rzp_order_id)
        except RazorpayOrder.DoesNotExist:
            logger.warning("Webhook: RazorpayOrder not found for order_id=%s", rzp_order_id)
            return

        # Update only if not already verified through the verify API
        if not rzp_record.is_verified:
            rzp_record.razorpay_payment_id = rzp_payment_id
            rzp_record.status = "paid"
            rzp_record.payment_response = payment_entity
            rzp_record.save()

        # Update linked internal payment if it exists
        if rzp_record.payment:
            payment = rzp_record.payment
            payment.status = "completed"
            payment.gateway_response = payment_entity
            payment.processed_at = timezone.now()
            payment.completed_at = timezone.now()
            payment.save()
        
        # ── Update Consultation record status ───────────────────────────
        if rzp_record.consultation:
            cons = rzp_record.consultation
            cons.payment_status = 'paid'
            cons.is_paid = True
            cons.save()

        logger.info("Webhook: payment.captured handled for order %s", rzp_order_id)

    def _handle_payment_failed(self, entity: dict):
        """payment.failed – payment attempt failed."""
        payment_entity = entity.get("payment", {}).get("entity", {})
        rzp_order_id   = payment_entity.get("order_id")

        if not rzp_order_id:
            return

        try:
            rzp_record = RazorpayOrder.objects.get(razorpay_order_id=rzp_order_id)
            rzp_record.status = "failed"
            rzp_record.payment_response = payment_entity
            rzp_record.save()

            if rzp_record.payment:
                rzp_record.payment.status = "failed"
                rzp_record.payment.failure_reason = payment_entity.get("error_description", "")
                rzp_record.payment.save()
        except RazorpayOrder.DoesNotExist:
            pass

        logger.info("Webhook: payment.failed handled for order %s", rzp_order_id)

    def _handle_order_paid(self, entity: dict):
        """order.paid – fired when the order amount is fully paid."""
        order_entity   = entity.get("order", {}).get("entity", {})
        payment_entity = entity.get("payment", {}).get("entity", {})
        rzp_order_id   = order_entity.get("id")

        if not rzp_order_id:
            return

        try:
            rzp_record = RazorpayOrder.objects.get(razorpay_order_id=rzp_order_id)
            rzp_record.status = "paid"
            rzp_record.payment_response = {
                "order": order_entity,
                "payment": payment_entity,
            }
            rzp_record.save()

            if rzp_record.payment:
                rzp_record.payment.status = "completed"
                rzp_record.payment.completed_at = timezone.now()
                rzp_record.payment.save()
        except RazorpayOrder.DoesNotExist:
            pass

        logger.info("Webhook: order.paid handled for order %s", rzp_order_id)

    def _handle_refund_created(self, entity: dict):
        """refund.created – log the refund event."""
        refund_entity  = entity.get("refund", {}).get("entity", {})
        rzp_payment_id = refund_entity.get("payment_id")
        logger.info(
            "Webhook: refund.created for payment %s – ₹%s",
            rzp_payment_id,
            refund_entity.get("amount", 0) / 100,
        )
        # You can update PaymentRefund record here if needed


class RazorpayRefundView(APIView):
    """
    POST /api/payments/razorpay/refund/

    Initiate a refund for a verified Razorpay payment.
    Only admin/superadmin can call this.

    Request body:
        razorpay_order_id  (str, required)
        amount             (number, optional) – partial refund amount in INR.
                                                Omit for full refund.
        reason             (str, optional)

    Response:
        { "success": true, "data": { "refund_id": "rfnd_XXX", ... } }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role not in ("admin", "superadmin"):
            return Response(
                {"success": False, "error": {"code": "PERMISSION_DENIED",
                                             "message": "Only admins can initiate refunds"}},
                status=status.HTTP_403_FORBIDDEN,
            )

        order_id = request.data.get("razorpay_order_id")
        if not order_id:
            return Response(
                {"success": False, "error": {"code": "MISSING_FIELD",
                                             "message": "razorpay_order_id is required"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            rzp_record = RazorpayOrder.objects.get(
                razorpay_order_id=order_id, is_verified=True
            )
        except RazorpayOrder.DoesNotExist:
            return Response(
                {"success": False, "error": {"code": "ORDER_NOT_FOUND",
                                             "message": "Verified Razorpay order not found"}},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Determine refund amount (default full)
        amount_raw  = request.data.get("amount")
        reason      = request.data.get("reason", "Refund requested by admin")

        if amount_raw:
            amount_inr   = Decimal(str(amount_raw))
            amount_paise = int(amount_inr * 100)
        else:
            amount_inr   = rzp_record.amount
            amount_paise = rzp_record.amount_in_paise

        notes = {"reason": reason, "initiated_by": str(request.user.id)}

        try:
            refund_response = _initiate_razorpay_refund(
                payment_id=rzp_record.razorpay_payment_id,
                amount_paise=amount_paise,
                notes=notes,
            )
        except requests.HTTPError as exc:
            try:
                error_detail = exc.response.json()
            except Exception:
                error_detail = str(exc)
            return Response(
                {"success": False, "error": {"code": "RAZORPAY_ERROR",
                                             "message": "Refund failed",
                                             "detail": error_detail}},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # Update internal Payment status
        if rzp_record.payment:
            rzp_record.payment.status = (
                "refunded" if amount_paise == rzp_record.amount_in_paise
                else "partially_refunded"
            )
            rzp_record.payment.save()

        logger.info(
            "Razorpay refund initiated: refund_id=%s order=%s amount=₹%s",
            refund_response.get("id"),
            order_id,
            amount_inr,
        )

        return Response(
            {
                "success": True,
                "data": {
                    "refund_id": refund_response.get("id"),
                    "razorpay_order_id": order_id,
                    "razorpay_payment_id": rzp_record.razorpay_payment_id,
                    "amount_refunded": float(amount_inr),
                    "currency": rzp_record.currency,
                    "refund_response": refund_response,
                },
                "message": "Refund initiated successfully",
                "timestamp": timezone.now().isoformat(),
            },
            status=status.HTTP_200_OK,
        )


class RazorpayOrderStatusView(APIView):
    """
    GET /api/payments/razorpay/order-status/<order_id>/

    Check the current status of a Razorpay order.
    The patient can only see their own orders.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, order_id):
        qs = RazorpayOrder.objects.filter(razorpay_order_id=order_id)

        # Patients can only query their own orders
        if request.user.role == "patient":
            qs = qs.filter(patient=request.user)

        try:
            rzp_record = qs.get()
        except RazorpayOrder.DoesNotExist:
            return Response(
                {"success": False, "error": {"code": "ORDER_NOT_FOUND",
                                             "message": "Order not found"}},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {
                "success": True,
                "data": {
                    "razorpay_order_id":   rzp_record.razorpay_order_id,
                    "razorpay_payment_id": rzp_record.razorpay_payment_id,
                    "amount":              float(rzp_record.amount),
                    "currency":            rzp_record.currency,
                    "status":              rzp_record.status,
                    "is_verified":         rzp_record.is_verified,
                    "payment_id":          rzp_record.payment.id if rzp_record.payment else None,
                    "created_at":          rzp_record.created_at.isoformat(),
                    "updated_at":          rzp_record.updated_at.isoformat(),
                },
                "message": "Order status retrieved",
                "timestamp": timezone.now().isoformat(),
            },
            status=status.HTTP_200_OK,
        )
