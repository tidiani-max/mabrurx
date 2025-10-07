# main/views.py
import datetime
import logging

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

from firebase_admin import firestore, get_app

logger = logging.getLogger(__name__)
db = None

# --- Firestore Initialization (safe) ---
try:
    firebase_app = get_app()
    db = firestore.client(firebase_app)
except Exception as e:
    logger.error(f"Failed to init Firestore: {e}")
    db = None

# ---------------------------
# Template / Public Views
# ---------------------------
def home(request):
    return render(request, "home.html")


def package(request):
    return render(request, "packages.html")


def login(request):
    return render(request, "login.html")


def register(request):
    return render(request, "register.html")


def register_Pilgrim_form(request):
    return render(request, "register_Pilgrim_form.html")


def government_dashboard(request):
    return render(request, "government_dashboard.html")


def pilgrim_detail_page(request, uid):
    return render(request, "pilgrim_detail_page.html", {"pilgrim_uid": uid})


# ---------------------------
# Agency dashboard (HTML) — uses DRF JWT cookie or Authorization header
# ---------------------------
def agency_dashboard(request):
    """
    Renders HTML for the agency dashboard.
    It expects the user to be authenticated with role travel_agency.
    We support:
      - Authorization header Bearer <access_token>
      - or cookie 'access_token' (SimpleJWT)
    """
    jwt_authenticator = JWTAuthentication()
    user_uid = None
    user_role = None

    # 1) Try Authorization header
    try:
        auth_tuple = jwt_authenticator.authenticate(request)
        if auth_tuple:
            user_obj, validated_token = auth_tuple
            # we used SimpleUser with .id earlier — JWT token contains 'uid' claim we set
            user_uid = validated_token.get("uid") or getattr(user_obj, "id", None) or validated_token.get("user_id")
            user_role = validated_token.get("role")
    except Exception:
        # ignore and fallback to cookie
        pass

    # 2) Fallback to cookie access_token
    if not user_uid:
        access_token = request.COOKIES.get("access_token")
        if access_token:
            try:
                # reuse JWTAuthentication to validate cookie token
                validated = jwt_authenticator.get_validated_token(access_token)
                user_uid = validated.get("uid") or validated.get("user_id")
                user_role = validated.get("role")
            except Exception:
                user_uid = None
                user_role = None

    if not user_uid or user_role != "agency":
        return redirect("login")


    # Query pilgrims collection by agency_UID
    pilgrims = []
    try:
        pilgrims_ref = db.collection("pilgrims").where("agency_UID", "==", user_uid)
        docs = pilgrims_ref.stream()
        for d in docs:
            item = d.to_dict()
            item["uid"] = d.id

            # Ensure all expected keys exist
            item.setdefault("tripPeriod", "-")
            item.setdefault("hajjStatus", "-")
            item.setdefault("umrahStatus", "-")
            item.setdefault("riskLevel", "-")
            item.setdefault("address", {
                "street": "",
                "kecamatan": "",
                "kelurahanDesa": "",
                "kotaKabupaten": "",
                "provinsi": "",
                "rtRw": "",
                "postalCode": "",
            })
            item.setdefault("passportNumber", "-")
            item.setdefault("birthDate", "-")
            item.setdefault("gender", "-")
            
            pilgrims.append(item)

    except Exception as e:
        logger.exception("Failed to fetch pilgrims for agency_dashboard")
        pilgrims = []

    # Apply simple filters coming from query params (client-side)
    periode = request.GET.get("periode")
    status_filter = request.GET.get("status")
    search = request.GET.get("search")

    if periode and periode != "Semua Periode":
        pilgrims = [p for p in pilgrims if p.get("tripPeriod") == periode or p.get("periode") == periode]
    if status_filter and status_filter != "Semua Status":
        pilgrims = [p for p in pilgrims if p.get("hajjStatus") == status_filter or p.get("umrahStatus") == status_filter]
    if search:
        pilgrims = [p for p in pilgrims if search.lower() in p.get("fullName", "").lower()
                                      or search in p.get("phoneNumber", "")]

    return render(request, "agency_dashboard.html", {
        "pilgrims": pilgrims,
        "periode": periode,
        "status": status_filter,
        "search": search,
    })


# ---------------------------
# API: Register Pilgrim (agency only)
# ---------------------------
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from firebase_admin import auth as firebase_auth
import datetime, logging

logger = logging.getLogger(__name__)

@api_view(["POST"])
@authentication_classes([])  # IMPORTANT: prevent DRF global authenticators from running here
@permission_classes([]) 
def register_pilgrim(request):
    """
    Register a pilgrim on behalf of a travel agency.
    This view validates the JWT manually (no Django ORM / no request.user lookup),
    then writes everything to Firestore.
    """
    # 1) Extract token (Authorization header "Bearer <token>" or cookie "access_token")
    auth_header = request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION", "")
    raw_token = None
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split("Bearer ")[1].strip()
    elif request.COOKIES.get("access_token"):
        raw_token = request.COOKIES.get("access_token")

    if not raw_token:
        return Response({"error": "Missing access token"}, status=401)

    # 2) Validate token signature & expiry (but DO NOT resolve Django user)
    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(raw_token)
    except Exception as e:
        logger.exception("Token validation failed")
        return Response({"error": "Invalid or expired token"}, status=401)

    # 3) Read claims from token
    agency_uid = validated_token.get("uid") or validated_token.get("user_id")
    agency_role = validated_token.get("role")

    # accept either normalized 'agency' or older 'travel_agency' if used elsewhere
    if agency_role not in ("agency", "travel_agency"):
        return Response({"detail": "Only travel agencies may register pilgrims."}, status=403)

    data = request.data
    national_id = data.get("nationalID") or data.get("nik")
    if not national_id:
        return Response({"error": "nationalID (NIK) is required"}, status=400)

    # 4) Build canonical pilgrim UID (prefer real Firebase UID when email+password provided)
    pilgrim_uid = None
    try:
        email = data.get("email")
        password = data.get("password")
        if email and password:
            try:
                user_record = firebase_auth.create_user(
                    email=email,
                    password=password,
                    display_name=data.get("fullName"),
                    phone_number=data.get("phoneNumber")
                )
                pilgrim_uid = user_record.uid
            except Exception:
                # if creation fails (e.g. email exists), try to fetch existing user
                try:
                    existing = firebase_auth.get_user_by_email(email)
                    pilgrim_uid = existing.uid
                except Exception as e2:
                    logger.exception("Failed to create or fetch Firebase user for pilgrim")
                    return Response({"error": f"Failed to create/fetch pilgrim auth user: {e2}"}, status=400)
        else:
            # fallback: use provided national ID as UID (ensure your system expects this)
            pilgrim_uid = str(national_id)
    except Exception as e:
        logger.exception("Error while determining pilgrim UID")
        return Response({"error": f"UID creation error: {e}"}, status=500)

    # 5) Write Firestore documents (users/{uid} and pilgrims/{uid})
    try:
        users_ref = db.collection("users").document(pilgrim_uid)
        user_profile = {
            "uid": pilgrim_uid,
            "role": "pilgrim",
            "fullName": data.get("fullName", ""),
            "email": data.get("email", ""),
            "phoneNumber": data.get("phoneNumber", ""),
            "createdBy": agency_uid,
            "createdAt": datetime.datetime.utcnow(),
        }
        users_ref.set(user_profile, merge=True)

        pilgrims_ref = db.collection("pilgrims").document(pilgrim_uid)
        pilgrim_doc = {
    "uid": pilgrim_uid,
    "agency_UID": agency_uid,
    "nationalID": national_id,
    "passportNumber": data.get("passportNumber"),
    "phoneNumber": data.get("phoneNumber"),
    "fullName": data.get("fullName"),
    "tripType": data.get("tripType"),
    "tripPeriod": data.get("tripPeriod"),
    "tripStatus": data.get("tripStatus", "Not Started"),
    "dateOfBirth": data.get("birthDate"),
    "gender": data.get("gender"),
    "provinsi": data.get("provinsi"),
    "medicalRiskLevel": data.get("risk_level", "LOW"),
    "address": {
        "street": data.get("street"),
        "kecamatan": data.get("kecamatan"),
        "kelurahanDesa": data.get("kelurahanDesa"),
        "kotaKabupaten": data.get("kotaKabupaten"),
        "provinsi": data.get("provinsi"),
        "rtRw": data.get("rtRw"),
        "postalCode": data.get("postalCode"),
        },
        "createdAt": datetime.datetime.utcnow(),
        }
        pilgrim_doc = {k: v for k, v in pilgrim_doc.items() if v is not None}
        pilgrims_ref.set(pilgrim_doc, merge=True)
    except Exception as e:
        logger.exception("Failed writing core Firestore docs")
        return Response({"error": f"Firestore write error: {e}"}, status=500)

    # 6) Optional: medical subcollection
    try:
        medical_conditions = data.get("medical_conditions")
        risk_level = data.get("risk_level", "Low")
        allergies_raw = data.get("allergies")
        exam_date = data.get("exam_date")

        if any([medical_conditions, risk_level != "Low", allergies_raw, exam_date]):
            allergies_list = [a.strip() for a in allergies_raw.split(",")] if allergies_raw else []
            medical_data = {
                "conditionName": data.get("conditionName", "None reported"),
                "allergies": [a.strip() for a in data.get("allergies", "").split(",") if a.strip()],
                "riskLevel": data.get("risk_level", "Low"),
                "examDate": data.get("exam_date") or datetime.datetime.utcnow(),
                "bloodType": data.get("bloodType"),
                "medicalNotes": data.get("medical_notes"),
                "createdAt": datetime.datetime.utcnow(),
            }
            pilgrims_ref.collection("medical").add(medical_data)

            pilgrims_ref.collection("medical").add(medical_data)
    except Exception:
        logger.exception("Medical subcollection write failed (continuing)")

    # 7) Optional: logs (only one set should be provided by frontend)
    try:
        for log in data.get("hajjLogs", []):
            pilgrims_ref.collection("logs").add({
                "type": "hajj",
                "activityName": log.get("activityName"),
                "activityStatus": log.get("activityStatus", "not_started"),
                "completionTime": log.get("completionTime") or None,
                "updatedBy": log.get("updatedBy") or "agency",
            })
    except Exception:
        logger.exception("Hajj logs write failed (continuing)")

    try:
        for log in data.get("umrahLogs", []):
            pilgrims_ref.collection("logs").add({
                "type": "umrah",
                "activityName": log.get("activityName"),
                "activityStatus": log.get("activityStatus", "not_started"),
                "completionTime": log.get("completionTime") or None,
                "updatedBy": log.get("updatedBy") or "agency",
            })
    except Exception:
        logger.exception("Umrah logs write failed (continuing)")
        logger.exception("Umrah logs write failed (continuing)")

    return Response({
        "message": "Pilgrim registered successfully",
        "uid": pilgrim_uid,
        "agency_uid": agency_uid
    }, status=201)


# ---------------------------
# API: List agency pilgrims (JSON)
# ---------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_agency_pilgrims(request):
    """
    List pilgrims registered by the authenticated travel agency.
    Query params:
      - periode (tripPeriod)
      - status
    """
    token_claims = request.auth
    agency_uid = token_claims.get("uid") or token_claims.get("user_id")
    agency_role = token_claims.get("role")

    if agency_role != "travel_agency":
        return Response({"detail": "Access denied"}, status=403)

    periode_filter = request.query_params.get("periode")
    status_filter = request.query_params.get("status")

    try:
        pilgrims_ref = db.collection("pilgrims").where("agency_UID", "==", agency_uid)
        if periode_filter:
            pilgrims_ref = pilgrims_ref.where("tripPeriod", "==", periode_filter)
        docs = pilgrims_ref.stream()

        pilgrims_data = []
        for doc in docs:
            d = doc.to_dict()
            pilgrims_data.append({
                "uid": doc.id,
                "fullName": d.get("fullName", "N/A"),
                "phoneNumber": d.get("phoneNumber", "N/A"),
                "tripPeriod": d.get("tripPeriod", "N/A"),
                "medicalRiskLevel": d.get("medicalRiskLevel", "N/A"),
                "hajjStatus": d.get("hajjStatus", "Pending"),
                "umrahStatus": d.get("umrahStatus", "Pending"),
                "provinsi": d.get("provinsi"),
            })

        return Response(pilgrims_data, status=200)

    except Exception as e:
        logger.exception("Error fetching pilgrims")
        return Response({"error": "Failed to fetch pilgrim list"}, status=500)


# ---------------------------
# API: Pilgrim detail (JSON)
# ---------------------------
# main/views.py (Add the helper function inside the file)
# ... imports ...
# db = None (already defined)

# Helper function to fetch pilgrim data from Firestore
def _fetch_pilgrim_details(uid, requester_uid, requester_role):
    """
    Fetches pilgrim details and performs authorization check.
    Returns (data, status_code, error_message).
    """
    if not db:
        return None, 500, "Database not initialized."

    try:
        pilgrim_doc_ref = db.collection("pilgrims").document(uid)
        snap = pilgrim_doc_ref.get()
        if not snap.exists:
            return None, 404, "Pilgrim not found."

        data = snap.to_dict()

        # --- 1. Authorization Check ---
        pilgrim_agency_uid = data.get("agency_UID")
        # Check: Is the requester the agency that registered the pilgrim?
        if requester_role == "agency" and pilgrim_agency_uid != requester_uid:
            # You might also want to check if the requester_role is 'government'
            # and allow access if so. Assuming 'government' role can see all.
            if requester_role != "government": 
                return None, 403, "Access denied."

        result = data.copy()
        result["uid"] = uid

        # --- 2. Medical Info (Latest) ---
        medical_snap = pilgrim_doc_ref.collection("medical").order_by(
            "createdAt", direction=firestore.Query.DESCENDING
        ).limit(1).get()

        if medical_snap:
            result["medical"] = medical_snap[0].to_dict()
            result["medical"]["riskLevel"] = data.get("medicalRiskLevel")

        # --- 3. Logs (Hajj/Umrah) ---
        hajj_logs = []
        umrah_logs = []
        # Your existing log fetching logic...
        for l in pilgrim_doc_ref.collection("logs").order_by("completionTime").stream():
             entry = l.to_dict()
             entry["id"] = l.id
             
             # Assuming 'type' field exists in log document for better separation
             if entry.get("type") == "hajj":
                 hajj_logs.append({"activity": entry.get("activityName"), "timestamp": entry.get("completionTime")})
             elif entry.get("type") == "umrah":
                 umrah_logs.append({"activity": entry.get("activityName"), "timestamp": entry.get("completionTime")})
             # Fallback/Guessing based on your existing weak logic
             elif data.get("tripType") == "HAJJ" and 'Hajj' in entry.get('activityName', ''):
                 hajj_logs.append({"activity": entry.get("activityName"), "timestamp": entry.get("completionTime")})
             elif data.get("tripType") == "UMRAH" and 'Umrah' in entry.get('activityName', ''):
                 umrah_logs.append({"activity": entry.get("activityName"), "timestamp": entry.get("completionTime")})
             else: # Default for non-specific logs
                (hajj_logs if data.get("tripType") == "HAJJ" else umrah_logs).append({
                    "activity": entry.get("activityName"), "timestamp": entry.get("completionTime")
                })
        
        result["hajjLogs"] = hajj_logs
        result["umrahLogs"] = umrah_logs

        # --- 4. Agency Info ---
        if pilgrim_agency_uid:
            agency_snap = db.collection("agencies").document(pilgrim_agency_uid).get()
            if agency_snap.exists:
                agency_data = agency_snap.to_dict()
                result["agency"] = {
                    "name": agency_data.get("agencyName"),
                    "registration": agency_data.get("businessLicenseNumber"),
                    "filter": agency_data.get("licenseStatus")
                }

        # --- 5. Death Report Check (KEMATIAN) ---
        death_reports = db.collection("reports").where("pilgrim_UID", "==", uid).where("reportType", "==", "KEMATIAN").limit(1).get()

        if death_reports:
            death_report = death_reports[0].to_dict()
            result["deathInfo"] = {
                "date": death_report.get("incidentDate") or death_report.get("createdAt"),
                "location": death_report.get("location"),
                "cause": death_report.get("cause")
            }

        return result, 200, None

    except Exception as e:
        logger.exception(f"Error fetching pilgrim detail for UID {uid}")
        return None, 500, str(e)


# ---------------------------
# Template / Public Views
# ---------------------------
# ... (other views) ...

# In your views.py (where pilgrim_detail_page is defined)
from django.shortcuts import redirect, render
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
# Assuming get_tokens_for_user is available/imported from your auth_views.py
# from .auth_views import get_tokens_for_user # <-- UNCOMMENT/ADAPT THIS

# --- REFRESH HELPER (Needed if you cannot import it) ---
class SimpleUser:
    def __init__(self, uid):
        self.id = uid

def _refresh_access_token(refresh_token_string):
    """Takes a refresh token string, returns a new (access, refresh) tuple or None."""
    try:
        refresh = RefreshToken(refresh_token_string)
        # Note: calling str(refresh.access_token) implicitly uses the refresh token to get a new access token
        return str(refresh.access_token), str(refresh)
    except Exception as e:
        print(f"Token refresh failed: {e}")
        return None, None
# ----------------------------------------------------


# Assuming this code is in a views.py file.
# You MUST ensure these imports are at the top of the file:
import datetime # Needed for max_age in cookie setting
from django.shortcuts import redirect, render
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken # 👈 CRITICAL IMPORT

# ----------------------------------------------------------------
# Helper Function Definition (MUST be defined or imported)
# ----------------------------------------------------------------
def _refresh_access_token(refresh_token_string):
    """
    Takes a refresh token string, attempts to refresh it.
    Returns (new_access_token, new_refresh_token) or (None, None) on failure.
    """
    try:
        # Create a RefreshToken object from the string
        refresh = RefreshToken(refresh_token_string)
        
        # Accessing refresh.access_token performs the refresh logic
        new_access = str(refresh.access_token)
        # Note: Some configurations rotate the refresh token; returning the new refresh token is safest.
        new_refresh = str(refresh) 
        
        return new_access, new_refresh
    except Exception as e:
        # Token is invalid, blacklisted, or expired (long life expired)
        print(f"Token refresh failed: {e}")
        return None, None
# ----------------------------------------------------------------


def pilgrim_detail_page(request, uid):
    """
    Renders HTML for the pilgrim detail page, includes token refresh logic.
    """
    jwt_authenticator = JWTAuthentication()
    user_uid = None
    user_role = None
    new_access_token = None
    new_refresh_token = None # Store the potentially new refresh token

    # 1. Attempt to authenticate with existing tokens (Header or Cookie)
    try:
        # This checks the Authorization header primarily
        auth_tuple = jwt_authenticator.authenticate(request)
        if auth_tuple:
            user_obj, validated_token = auth_tuple
            user_uid = validated_token.get("uid") or validated_token.get("user_id")
            user_role = validated_token.get("role")
    except Exception:
        # Auth failed (token missing or expired). Proceed to check refresh token.
        pass

    # 2. If Auth failed, attempt to use the Refresh Token
    if not user_uid:
        refresh_token = request.COOKIES.get("refresh_token")
        
        if refresh_token:
            # Use the local helper function to try the refresh
            new_access_token, new_refresh_token = _refresh_access_token(refresh_token)
            
            if new_access_token:
                # If refresh succeeded, extract claims from the old refresh token payload
                try:
                    # Get the claims directly from the refresh token's payload
                    refresh_token_obj = RefreshToken(refresh_token)
                    user_uid = refresh_token_obj.payload.get("uid") or refresh_token_obj.payload.get("user_id")
                    user_role = refresh_token_obj.payload.get("role")
                    
                    print("Token successfully refreshed and user claims retrieved.")
                    
                except Exception as e:
                    # This happens if the old refresh token payload can't be read (should be rare)
                    print(f"Failed to extract claims from refresh token payload: {e}")
                    user_uid = None # Force redirect if we can't get the UID

    # 3. Final Authentication Check & Redirect
    if not user_uid:
        print("Redirecting to login: User unauthenticated or refresh failed.")
        response = redirect("login")
        # Clear cookies on final failure for security
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

    # 4. Fetch data using the helper function (unchanged)
    pilgrim_data, status_code, error_message = _fetch_pilgrim_details(uid, user_uid, user_role)

    # 5. Handle Errors (unchanged)
    if status_code != 200:
        context = {
             "error_message": error_message or "Failed to load pilgrim details.",
             "status_code": status_code,
             "pilgrim_uid": uid,
        }
        return render(request, "pilgrim_detail_page.html", context, status=status_code)

    # 6. Render Success and Set New Cookies
    context = {
        "pilgrim_uid": uid,
        "pilgrim": pilgrim_data,
        "is_agency_user": user_role == "agency",
    }
    response = render(request, "pilgrim_detail_page.html", context)

    # CRITICAL: If a new access token was generated, set the new cookie
    if new_access_token:
        print("Setting new access token cookie in the response.")
        response.set_cookie(
            key='access_token',
            value=new_access_token,
            httponly=True,
            path='/',
            samesite='Lax',
            # Set max_age to match your short access token life (e.g., 5-15 minutes)
            max_age=300, 
        )
        
    # OPTIONAL: Set a new refresh token if rotation is enabled in SIMPLE_JWT settings
    if new_refresh_token and new_refresh_token != request.COOKIES.get("refresh_token"):
        print("Setting new refresh token cookie in the response.")
        refresh_max_age = int(datetime.timedelta(days=30).total_seconds())
        response.set_cookie(
            key='refresh_token',
            value=new_refresh_token,
            httponly=True,
            path='/',
            samesite='Lax',
            max_age=refresh_max_age,
        )

    return response




import datetime
import pytz
import logging
from django.shortcuts import render
# Mock imports for demonstration. In a real project, these must be imported correctly.
# from django.conf import settings 
# from firebase_admin import firestore # Assuming you use firestore

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

# --- MOCKING REQUIRED GLOBAL/CONFIG VARIABLES ---
# Replace these with your actual database client and settings-based timezone
# Example: TIMEZONE = pytz.timezone(settings.TIME_ZONE)
TIMEZONE = pytz.timezone("Asia/Riyadh") # Example Hajj location timezone
db = None # Placeholder for your initialized Firestore client instance
logger = logging.getLogger(__name__)

# --- 1. VIEW TO RENDER THE HTML FORM (Mapped to /laporan/new) ---
def register_laporan_page(request):
    """
    Renders the death report registration HTML form for agencies (GET request).
    The template 'register_laporan.html' must be available in the template directories.
    """
    return render(request, "report_death.html")
# ------------------------------------------------------------------


# --- 2. API VIEW TO PROCESS THE DATA (Mapped to /api/report/death/<str:pilgrim_uid>/) ---
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def register_death_report(request, pilgrim_uid):
    """
    Allows an authenticated agency to submit a KEMATIAN report (POST request).
    
    Required data: incidentDate (ISO 8601 string, e.g., '2025-01-20T10:30:00+07:00'), 
    location, cause.
    """
    if db is None:
        logger.error("Firestore client (db) is not initialized.")
        return Response({"error": "Server configuration error."}, status=500)

    token_claims = request.auth
    requester_uid = token_claims.get("uid") or token_claims.get("user_id")
    requester_role = token_claims.get("role")
    
    # 1. Check Role
    if requester_role != "agency":
        return Response({"error": "Only agencies can register reports."}, status=403)

    data = request.data
    
    # Required Fields for Death Report
    incident_date_raw = data.get("incidentDate")
    location = data.get("location")
    cause = data.get("cause")
    
    if not all([incident_date_raw, location, cause]):
        return Response({"error": "Missing required fields: incidentDate, location, and cause."}, status=400)

    # --- TIMEZONE AND DATETIME CONVERSION FIX ---
    incident_datetime_utc = None
    try:
        # 1. Parse the string into a datetime object
        dt = datetime.datetime.fromisoformat(incident_date_raw)
        
        # 2. Localize or Convert to UTC
        if dt.tzinfo is None:
            # If the date string is naive, assume it's in the server's configured TIMEZONE
            dt = TIMEZONE.localize(dt)
        
        # 3. Convert to UTC (Firestore best practice for consistent storage)
        incident_datetime_utc = dt.astimezone(pytz.utc)
        
    except ValueError as e:
        logger.error(f"Incident date parsing error: {e} for input: {incident_date_raw}")
        return Response({"error": "Invalid date format for incidentDate. Please use a valid ISO 8601 format."}, status=400)
    
    # --- END TIMEZONE FIX ---

    try:
        # Fetch Pilgrim Document
        pilgrim_doc = db.collection("pilgrims").document(pilgrim_uid).get()
        if not pilgrim_doc.exists:
            return Response({"error": "Pilgrim not found."}, status=404)

        pilgrim_data = pilgrim_doc.to_dict()
        
        # 2. Check Ownership
        if pilgrim_data.get("agency_UID") != requester_uid:
            return Response({"error": "Access denied. Cannot report on another agency's pilgrim."}, status=403)

        # 3. Create Report Document
        report_data = {
            "agency_UID": requester_uid,
            "pilgrim_UID": pilgrim_uid,
            "reportType": "KEMATIAN",
            "incidentDate": incident_datetime_utc, 
            "location": location,
            "cause": cause,
            "govStatus": "PENDING_REVIEW",
            # Use current UTC time for consistent creation timestamp
            "createdAt": datetime.datetime.now(pytz.utc), 
            "reporterUID": requester_uid
        }
        
        # NOTE: report_ref[1].id is specific to certain Firestore library wrappers, 
        # ensure your db.collection("reports").add() call returns the ID correctly.
        report_ref = db.collection("reports").add(report_data)
        report_id = report_ref[1].id
        
        # 4. Update Pilgrim Document 
        pilgrim_doc.reference.update({
            "isDeceased": True,
            "deathReportUID": report_id,
            "medicalRiskLevel": "CRITICAL"
        })

        return Response({
            "message": "Death report successfully submitted for government review.",
            "report_id": report_id,
            "incident_time_utc": incident_datetime_utc.isoformat(), 
        }, status=201)

    except Exception as e:
        logger.exception(f"Error registering death report for {pilgrim_uid}")
        return Response({"error": f"Failed to submit report: {e}"}, status=500)




# main/views.py (continued)

# ---------------------------------------------
# NEW API: Government Dashboard Data (Government Only)
# ---------------------------------------------
# main/views.py (Add to your existing file)
import datetime
import logging
from django.shortcuts import render, redirect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from firebase_admin import firestore
# Assume 'db' and 'logger' are already imported/initialized at the top of your file

# Helper to calculate time difference for the activity feed
def time_ago(dt):
    """Converts a datetime to a user-friendly 'X hours/days ago' string."""
    if not dt:
        return "N/A"
    
    # Ensure dt is a timezone-aware datetime object
    if isinstance(dt, firestore.firestore.DatetimeWithNanoseconds):
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)

    now = datetime.datetime.utcnow()
    diff = now - dt
    
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    elif diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    else:
        return "Just now"


# ---------------------------
# HTML View: Government Dashboard
# ---------------------------
# Assuming imports:
# from rest_framework_simplejwt.authentication import JWTAuthentication
# from django.shortcuts import redirect
# from your_app.utils import db, firestore, time_ago # assuming these exist
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import redirect

def government_dashboard(request):
    """
    Renders HTML for the government dashboard.
    It expects the user to be authenticated with role 'government'.
    """
    
    
    jwt_authenticator = JWTAuthentication()
    user_uid = None
    user_role = None

    # 1) Try Authorization header (Standard JWT approach)
    try:
        auth_tuple = jwt_authenticator.authenticate(request)
        if auth_tuple:
            user_obj, validated_token = auth_tuple
            # Extract user_uid and role from the token claims
            user_uid = validated_token.get("uid") or validated_token.get("user_id")
            user_role = validated_token.get("role")
    except Exception:
        # Ignore and fallback to cookie
        pass

    # 2) Fallback to cookie 'access_token'
    if not user_uid:
        access_token = request.COOKIES.get("access_token")
        if access_token:
            try:
                # Reuse JWTAuthentication to validate cookie token
                validated = jwt_authenticator.get_validated_token(access_token)
                user_uid = validated.get("uid") or validated.get("user_id")
                user_role = validated.get("role")
            except Exception:
                user_uid = None
                user_role = None

    # --- SECURITY CHECK ---
    # Redirect if not logged in (no UID) or if role is incorrect
    if not user_uid or user_role != "government":
        # Clear potentially invalid token/cookies if necessary (optional but secure)
        response = redirect("login")
        response.delete_cookie("access_token")
        # response.delete_cookie("refresh_token") # If you use refresh token
        return response

    # If authentication and role check passed:
    # (Optional: fetch government user details if needed for template display)
    user_context = {"full_name": f"Gov Admin ({user_uid})"} # Placeholder
    
    return render(request, "government_dashboard.html", {"user": user_context})

# The 'government_dashboard_api' view logic for fetching data is correct
# for a secure REST API endpoint and does not need modification for this HTML request.