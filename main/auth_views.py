# main/auth_views.py
import logging
import datetime

from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from firebase_admin import auth as firebase_auth, firestore
from google.cloud.firestore_v1 import SERVER_TIMESTAMP

logger = logging.getLogger(__name__)
db = firestore.client()

# ----------------------------------------------------------------
# Helper class + token generator (same idea as before)
# ----------------------------------------------------------------
class SimpleUser:
    """Wrapper so RefreshToken.for_user accepts a minimal user-like object"""
    def __init__(self, uid):
        # SimpleJWT expects an `id` attribute for the user object used here
        self.id = uid


def get_tokens_for_user(user_dict):
    """
    user_dict should contain at least {'uid': <uid>, 'role': <role>}
    Returns refresh + access tokens (strings)
    """
    simple_user = SimpleUser(user_dict['uid'])
    refresh = RefreshToken.for_user(simple_user)

    # Put important claims on refresh (access gets them via refresh access token)
    refresh['uid'] = user_dict['uid']
    refresh['role'] = user_dict.get('role')

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


# ----------------------------------------------------------------
# REGISTER USER (travel_agency / government)
# ----------------------------------------------------------------


logger = logging.getLogger(__name__)




@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """
    Register travel_agency or government user.
    - If the Firebase Auth email already exists, we fetch the existing UID and
      continue to create/update Firestore documents (users/{uid}, agencies/{uid} or government_profiles/{uid}).
    - If the email does not exist, create the Auth user then create Firestore docs.
    """
   

    data = request.data
    role = data.get("role")
    email = data.get("email")
    password = data.get("password")
    fullName = data.get("fullName")

    if role not in ["travel_agency", "government"]:
        return Response({"error": "Invalid role (must be travel_agency or government)"}, status=400)

    if not email or not fullName:
        return Response({"error": "email and fullName are required"}, status=400)

    # normalize role for Firestore
    normalized_role = "agency" if role == "travel_agency" else "government"

    created_in_auth = False
    try:
        # Try to create the Firebase Auth user (preferred)
        try:
            user_record = firebase_auth.create_user(
                email=email,
                password=password,
                display_name=fullName,
                phone_number=data.get("phoneNumber")
            )
            uid = user_record.uid
            created_in_auth = True
        except Exception as e:
            # If email exists in Auth, recover by fetching the user
            err_str = str(e)
            if "EMAIL_EXISTS" in err_str or "already exists" in err_str.lower():
                try:
                    existing = firebase_auth.get_user_by_email(email)
                    uid = existing.uid
                    created_in_auth = False
                    # Optionally update password if provided (admin action)
                    if password:
                        try:
                            firebase_auth.update_user(uid, password=password)
                        except Exception:
                            logger.exception("Failed to update password for existing user (continuing)")
                except Exception as ee:
                    logger.exception("Email exists but cannot fetch existing user")
                    return Response({"error": "Email exists but admin cannot fetch existing user: " + str(ee)}, status=400)
            else:
                logger.exception("Unexpected error creating auth user")
                return Response({"error": str(e)}, status=400)

        # 2) Ensure users/{uid} doc (minimal profile) - merge so we don't overwrite useful data
        user_doc = {
            "uid": uid,
            "email": email,
            "role": normalized_role,
            "fullName": fullName,
            "phoneNumber": data.get("phoneNumber"),
            "createdAt": SERVER_TIMESTAMP,
        }
        db.collection("users").document(uid).set(user_doc, merge=True)

        # 3) Role-specific collection
        if normalized_role == "agency":
            address = {
                "street": data.get("street"),
                "rtRw": data.get("rtRw"),
                "kelurahanDesa": data.get("kelurahanDesa"),
                "kecamatan": data.get("kecamatan"),
                "kotaKabupaten": data.get("kotaKabupaten"),
                "provinsi": data.get("provinsi"),
                "postalCode": data.get("postalCode"),
            }
            agency_doc = {
                "agencyName": data.get("agencyName"),
                "businessLicenseNumber": data.get("businessLicenseNumber"),
                "licenseExpiryDate": data.get("licenseExpiryDate"),
                "address": address,
                "mainContactName": data.get("mainContactName"),
                "agencyPhoneNumber": data.get("phoneNumber"),
                "licenseStatus": data.get("licenseStatus", "Aktif"),
                "createdAt": SERVER_TIMESTAMP,
            }
            db.collection("agencies").document(uid).set(agency_doc, merge=True)

        else:  # government
            gov_doc = {
                "ministryName": data.get("ministryName"),
                "employeeId": data.get("employeeId"),
                "designation": data.get("designation"),
                "clearanceLevel": data.get("clearanceLevel"),
                "status": data.get("status", "active"),
                "createdAt": SERVER_TIMESTAMP,
            }
            db.collection("government_profiles").document(uid).set(gov_doc, merge=True)

        # Response: differentiate between newly created auth user vs existing auth user recovered
        if created_in_auth:
            return Response({"uid": uid, "message": "User created in Auth and Firestore profile saved"}, status=201)
        else:
            return Response({"uid": uid, "message": "Email already existed in Auth; Firestore profile created/updated"}, status=200)

    except Exception as final_e:
        logger.exception("Register failed")
        return Response({"error": str(final_e)}, status=500)


# ----------------------------------------------------------------
# LOGIN USER (Firebase Auth + Firestore Role)
# ----------------------------------------------------------------
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    """
    NOTE: Secure password verification should be done on the frontend using Firebase SDK.
    This endpoint assumes frontend obtained a Firebase ID token OR does a "email/password" sign-in
    and sends the ID token to backend. But to keep the earlier approach compatible, this function:
      - looks up firebase user by email (ensures exists)
      - looks up users/{uid} to get role
      - returns SimpleJWT tokens (refresh/access) for your Django protected endpoints
    Expected JSON: { "email": "...", "password": "..." }
    """
    data = request.data
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=400)

    try:
        # 1) ensure Firebase Auth has the email
        try:
            firebase_user = firebase_auth.get_user_by_email(email)
            firebase_uid = firebase_user.uid
        except Exception:
            return Response({"error": "Invalid email or password."}, status=401)

        # 2) load users/{uid}
        user_doc_snap = db.collection("users").document(firebase_uid).get()
        if not user_doc_snap.exists:
            return Response({"error": "Account not registered in system."}, status=401)

        user = user_doc_snap.to_dict()
        user['uid'] = user_doc_snap.id

        # 3) generate SimpleJWT tokens
        tokens = get_tokens_for_user({'uid': user['uid'], 'role': user.get('role')})

        # 4) set cookie and return tokens + user info
        
        response = Response({
            "message": "Login successful",
            "user": {"uid": user['uid'], "role": user.get('role'), "fullName": user.get('fullName')},
            "tokens": tokens
        }, status=200)

        # Set access token cookie (httpOnly)
        response.set_cookie(
            key='access_token',
            value=tokens['access'],
            httponly=True,
            path='/',
            samesite='Lax',
            max_age=3600,
        )
                # 4) set cookie and return tokens + user info
        response_data = {
            "message": "Login successful",
            "user": {
                "uid": user['uid'],
                "role": user.get('role'),
                "fullName": user.get('fullName')
            },
            "tokens": tokens
        }

        print(">>> LOGIN RESPONSE DATA:", response_data)   # 👈 Debug here
        print(">>> User role:", user.get("role"))          # 👈 Specific role debug

        response = Response(response_data, status=200)

        # Set access token cookie (httpOnly)
        response.set_cookie(
            key='access_token',
            value=tokens['access'],
            httponly=True,
            path='/',
            samesite='Lax',
            max_age=3600,
        )

        return response


        return response

    except Exception as e:
        logger.exception("Login failed")
        return Response({"error": "Server error during login."}, status=500)


# ----------------------------------------------------------------
# LOGOUT USER
# ----------------------------------------------------------------
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response({"error": "refresh_token required"}, status=400)

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception("Logout failed")
            return Response({"error": "Invalid token or server error."}, status=400)
