from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, LoginView, LogoutView, CurrentUserView, AdminUserView,
    TaskViewSet, TeamMemberViewSet, ChecklistItemViewSet, AttachmentViewSet,
    DashboardStatsView, TaskExportView, TaskChecklistListView, UserReportView
)

# Create a router and register our ViewSets with it.
router = DefaultRouter()
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'users', TeamMemberViewSet, basename='user')
router.register(r'checklist', ChecklistItemViewSet, basename='checklist')
router.register(r'attachments', AttachmentViewSet, basename='attachment')

urlpatterns = [
    # ==============================
    # 1. Authentication Endpoints
    # ==============================
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/me/', CurrentUserView.as_view(), name='current-user'),

    # ==============================
    # 2. Dashboard Analytics
    # ==============================
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),

    # ==============================
    # 3. Export (Must be before router)
    # ==============================
    # We define this specifically here so it doesn't get caught by the router's
    # 'tasks/<id>/' pattern.
    path('tasks/export/', TaskExportView.as_view(), name='task-export'),

    # User report export endpoint
    path('users/report/', UserReportView.as_view(), name='user-report'),

    # ==============================
    # 4. ViewSet Routers (CRUD)
    # ==============================
    # This automatically generates:
    # /tasks/ -> List/Create
    # /tasks/{id}/ -> Retrieve/Update/Delete
    # /users/ -> List (Team Members)
    # /checklist/ -> CRUD for items
    # /attachments/ -> CRUD for files
    path('', include(router.urls)),

    # Nested route for checklist items under a specific task
    path('tasks/<int:task_pk>/checklist/', TaskChecklistListView.as_view(), name='task-checklist-list'),

    # Admin endpoint to make users admin
    path('users/<int:user_id>/make-admin/', AdminUserView.as_view(), name='make-admin'),
]