from django.db.models import Count, Q, Case, When, IntegerField
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

from .models import Task, ChecklistItem, Attachment
from .serializers import (
    TaskSerializer, UserSerializer, ChecklistItemSerializer, 
    AttachmentSerializer, RegisterSerializer, LoginSerializer
)

# Use the custom user model
User = get_user_model()

# =============================================================
# 1. AUTHENTICATION VIEWS
# =============================================================

class RegisterView(generics.CreateAPIView):
    """
    Handles user registration/signup. Publicly accessible initially,
    but can be restricted once superusers exist.
    """
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        # Allow registration only if no superusers exist, or if an admin is already logged in
        if User.objects.filter(is_superuser=True).exists() and not request.user.is_authenticated:
            return Response(
                {"detail": "Registration is currently closed."},
                status=status.HTTP_403_FORBIDDEN
            )
        # If registration is allowed, by default the new user is a team member (not admin)
        return super().post(request, *args, **kwargs)


class LoginView(APIView):
    """
    Handles user login, authentication, and token generation. Publicly accessible.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer # For swagger/schema documentation

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(username=username, password=password)

        if user:
            # Get or create token (using DRF Token authentication)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'username': user.username,
                'is_admin': user.is_admin,
            }, status=status.HTTP_200_OK)
        
        return Response(
            {"detail": "Invalid credentials. Please try again."},
            status=status.HTTP_401_UNAUTHORIZED
        )


class LogoutView(APIView):
    """
    Handles user logout by deleting the authentication token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Delete the user's token to log them out
        try:
            request.user.auth_token.delete()
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK
            )
        except:
            return Response(
                {"detail": "Error logging out."},
                status=status.HTTP_400_BAD_REQUEST
            )


class CurrentUserView(generics.RetrieveAPIView):
    """
    Returns the details of the currently logged-in user.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class AdminUserView(APIView):
    """
    Allows superusers to make other users admin (is_admin=True).
    """
    permission_classes = [IsAuthenticated]  # Any authenticated user can access, we check for superuser inside

    def patch(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if request.user is a Django superuser
        if not request.user.is_superuser:
            return Response(
                {"detail": "Only superusers can make other users admin."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Set the custom is_admin field
        user.is_admin = True
        user.save()

        return Response(
            {"detail": f"User {user.username} is now an admin."},
            status=status.HTTP_200_OK
        )


# =============================================================
# 2. USER/TEAM MANAGEMENT VIEWS
# =============================================================

class TeamMemberViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Provides read-only access to all users (Team Members).
    Accessible by authenticated users for assignment/team list.
    """
    queryset = User.objects.all().order_by('username')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


# =============================================================
# 3. TASK CRUD & FILTERS VIEWS
# =============================================================

class TaskViewSet(viewsets.ModelViewSet):
    """
    Provides CRUD operations for Tasks and handles complex filtering.
    """
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Prefetch related data to avoid N+1 queries
        queryset = Task.objects.select_related('created_by').prefetch_related(
            'assigned_to',
            'checklist',
            'attachments'
        ).order_by('-created_at')

        user = self.request.user

        # Admin View: Show all tasks
        if user.is_admin:
            return queryset

        # Team Member View: Show all tasks (as per requirements)
        return queryset.all()

    def perform_create(self, serializer):
        """Sets the created_by field to the currently logged-in user."""
        user = self.request.user
        # Only admin users (custom is_admin field) or Django superusers should be able to create tasks
        if not (user.is_admin or user.is_superuser):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only administrators can create tasks.")
        serializer.save(created_by=self.request.user)

    
# =============================================================
# 4. SUB-FEATURE VIEWS (NESTED CRUD)
# =============================================================

class TaskChecklistListView(generics.ListCreateAPIView):
    """
    List all checklist items for a specific task or create new checklist items.
    """
    serializer_class = ChecklistItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        task_pk = self.kwargs['task_pk']
        user = self.request.user

        # Get the specific task
        try:
            task = Task.objects.get(pk=task_pk)
        except Task.DoesNotExist:
            from django.http import Http404
            raise Http404("Task not found")

        # Check if user has permission to access this task
        if not user.is_admin and task not in Task.objects.filter(assigned_to=user):
            from django.core.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to access this task")

        # Return checklist items for this task
        return ChecklistItem.objects.filter(task=task)

    def perform_create(self, serializer):
        task_pk = self.kwargs['task_pk']
        try:
            task = Task.objects.get(pk=task_pk)
        except Task.DoesNotExist:
            from django.core.exceptions import ValidationError
            raise ValidationError({"task": "Task not found"})

        # Check if user has permission to modify this task
        user = self.request.user
        if not user.is_admin and task not in Task.objects.filter(assigned_to=user):
            from django.core.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to modify this task")

        serializer.save(task=task)


class ChecklistItemViewSet(viewsets.ModelViewSet):
    """
    CRUD for checklist items. Allows updating status of an item.
    """
    serializer_class = ChecklistItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Only show checklist items associated with tasks the user can see
        user = self.request.user
        if user.is_admin:
            return ChecklistItem.objects.all()
        return ChecklistItem.objects.filter(task__assigned_to=user).distinct()

    # Custom action to quickly toggle completion status
    @action(detail=True, methods=['patch'])
    def toggle_complete(self, request, pk=None):
        try:
            item = self.get_object()
        except ChecklistItem.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        item.is_completed = not item.is_completed
        item.save()
        return Response(ChecklistItemSerializer(item).data)


class AttachmentViewSet(viewsets.ModelViewSet):
    """
    CRUD for task attachments (files and links).
    """
    serializer_class = AttachmentSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Only show attachments for tasks the user can see
        user = self.request.user
        if user.is_admin:
            return Attachment.objects.all()
        return Attachment.objects.filter(task__assigned_to=user).distinct()


# =============================================================
# 5. DASHBOARD ANALYTICS VIEWS
# =============================================================

class DashboardStatsView(APIView):
    """
    API to provide task counts for the dashboard statistics cards.
    Handles filtering based on Admin vs. Team Member role.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        
        # Start with the base queryset for the current user's scope
        if user.is_admin:
            base_queryset = Task.objects.all()
        else:
            base_queryset = Task.objects.filter(assigned_to=user)

        # 1. Quick Task Summary (Top Cards)
        total_count = base_queryset.count()
        pending_count = base_queryset.filter(status='PENDING').count()
        in_progress_count = base_queryset.filter(status='IN_PROGRESS').count()
        completed_count = base_queryset.filter(status='COMPLETED').count()

        # 2. Distribution Chart Data (by Status)
        status_distribution = base_queryset.values('status').annotate(count=Count('status'))
        
        # 3. Priority Chart Data (by Priority)
        priority_distribution = base_queryset.values('priority').annotate(count=Count('priority'))

        # 4. Recent Tasks (Bottom Table)
        # Uses the TaskSerializer for detailed output
        recent_tasks = base_queryset.order_by('-created_at')[:10]
        recent_tasks_data = TaskSerializer(recent_tasks, many=True).data

        return Response({
            'stats': {
                'total': total_count,
                'pending': pending_count,
                'in_progress': in_progress_count,
                'completed': completed_count,
            },
            'status_distribution': status_distribution,
            'priority_distribution': priority_distribution,
            'recent_tasks': recent_tasks_data,
        }, status=status.HTTP_200_OK)


# =============================================================
# 6. REPORTING VIEWS (DOWNLOAD REPORTS)
# =============================================================

class TaskExportView(APIView):
    """
    Generates an exportable CSV/Excel report of all tasks.
    Only accessible by Admins.
    """
    permission_classes = [IsAuthenticated] # Check custom admin status inside

    def get(self, request):
        # Check if user is admin or superuser
        if not (request.user.is_admin or request.user.is_superuser):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only administrators can export tasks.")
        # Implementation Note:
        # 1. Query the desired Task data (e.g., all tasks).
        tasks = Task.objects.all().order_by('id')

        # 2. Prepare the HTTP Response headers for file download.
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="task_report.csv"'

        writer = csv.writer(response)

        # Headers for the CSV file
        writer.writerow([
            'Task ID', 'Title', 'Priority', 'Status',
            'Due Date', 'Created By', 'Assigned To',
            'Checklist Items', 'Completed Checklists',
            'Attachment Count'
        ])

        # Write data rows
        for task in tasks:
            assigned_members = ", ".join([user.username for user in task.assigned_to.all()])
            checklist_total = task.checklist.count()
            checklist_completed = task.checklist.filter(is_completed=True).count()

            writer.writerow([
                task.id,
                task.title,
                task.priority,
                task.status,
                task.due_date,
                task.created_by.username,
                assigned_members,
                checklist_total,
                checklist_completed,
                task.attachments.count()
            ])

        # The frontend requirement specifies Excel, but a CSV file
        # is the most straightforward way to implement server-side
        # file generation without external libraries like pandas or openpyxl.
        # Most spreadsheet programs (Excel, Sheets) easily open CSV files.

        return response


class UserReportView(APIView):
    """
    Generates an exportable CSV report of users and their task statistics.
    Shows username, email, and task distribution (total, pending, in progress, completed).
    Only accessible by Admins.
    """
    permission_classes = [IsAuthenticated] # Check custom admin status inside

    def get(self, request):
        # Check if user is admin or superuser
        if not (request.user.is_admin or request.user.is_superuser):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only administrators can export user reports.")

        # Import required modules
        import csv
        from django.http import HttpResponse
        from django.db.models import Count, Q

        # Get all active users
        users = User.objects.all()

        # Create the HTTP response with CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="user_task_report.csv"'

        writer = csv.writer(response)

        # Write header row
        writer.writerow([
            'Username',
            'Email',
            'Total Tasks Assigned',
            'Pending Tasks',
            'In Progress Tasks',
            'Completed Tasks'
        ])

        # Generate task statistics for each user
        for user in users:
            # Get all tasks assigned to this user
            user_tasks = Task.objects.filter(assigned_to=user)

            # Calculate task counts by status
            total_tasks = user_tasks.count()
            pending_tasks = user_tasks.filter(status='PENDING').count()
            inprogress_tasks = user_tasks.filter(status='IN_PROGRESS').count()
            completed_tasks = user_tasks.filter(status='COMPLETED').count()

            # Write the user's data row
            writer.writerow([
                user.username,
                user.email,
                total_tasks,
                pending_tasks,
                inprogress_tasks,
                completed_tasks
            ])

        return response
