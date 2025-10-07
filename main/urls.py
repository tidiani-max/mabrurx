# main/urls.py
from django.urls import path
from . import views, auth_views

urlpatterns = [
    # ================================
    # Template views
    # ================================
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('agency_dashboard/', views.agency_dashboard, name='agency_dashboard'),
    path('package/', views.package, name='package'),
    path('register_Pilgrim_form/', views.register_Pilgrim_form, name='register_Pilgrim_form'),
    
    # FIX: Updated to match the frontend link structure: /pilgrim/detail/<uid>/
    path("pilgrim/detail/<str:uid>/", views.pilgrim_detail_page, name="pilgrim_detail_page"),
    
    path('government_dashboard/', views.government_dashboard, name='government_dashboard'),

    # ================================
    # API endpoints
    # ================================
    path('api/register_user/', auth_views.register_user, name='api_register_user'),
    path('api/auth/login/', auth_views.login_user, name='api_login'),
    path('api/auth/logout/', auth_views.LogoutView.as_view(), name='api_logout'),
    
    # 2. Backend API Route (to receive the form submission)
    path('laporan/new', views.register_laporan_page, name='register_laporan_page'),
    
    # 2. Backend API Route (Handles POST request from the form submission)
    path('api/report/death/<str:pilgrim_uid>/', views.register_death_report, name='api_register_death_report'),
    path('api/government/data/', views.government_dashboard, name='api_government_data'),
    
    # Pilgrim endpoints
    path('api/pilgrims/register/', views.register_pilgrim, name='api_register_pilgrim'),
    path('api/list_pilgrims/', views.list_agency_pilgrims, name='api_list_pilgrims'),
    path("api/pilgrim_detail/<str:uid>/", views.pilgrim_detail_page, name="api_pilgrim_detail"),
]