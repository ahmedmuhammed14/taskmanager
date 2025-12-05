from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from .models import Task, ChecklistItem, Attachment

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for displaying User details (e.g., in Team Members list or 'Assigned To' fields).
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile_picture', 'is_admin']


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for User Registration (Sign Up).
    Handles password creation securely.
    """
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user


class ChecklistItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChecklistItem
        fields = ['id', 'text', 'is_completed']


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ['id', 'task', 'link', 'uploaded_at']


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login authentication.
    """
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if not user:
                raise serializers.ValidationError('Invalid credentials. Please try again.')

            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Both username and password are required.')


class TaskSerializer(serializers.ModelSerializer):
    """
    Main serializer for Tasks.
    - specific handling for 'assigned_to' to allow writing IDs but reading Objects.
    - nested checklist and attachments for easy frontend consumption.
    """
    # For reading: Nest the full user details
    assigned_to_details = UserSerializer(source='assigned_to', many=True, read_only=True)
    # For writing: Accept a list of User IDs
    assigned_to = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        many=True,
        write_only=True
    )

    created_by = UserSerializer(read_only=True)

    # Read-only nested fields (so we can see them in the task detail)
    # To add items, we will use the specific API endpoints (e.g., /api/tasks/1/checklist/)
    checklist = ChecklistItemSerializer(many=True, read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'priority', 'status',
            'start_date', 'due_date',
            'created_by', 'assigned_to', 'assigned_to_details',
            'checklist', 'attachments',
            'created_at'
        ]

    def to_representation(self, instance):
        """
        Custom representation to merge assigned_to_details into the main assigned_to field for the frontend.
        """
        representation = super().to_representation(instance)
        # Replace the list of IDs with the list of User objects
        representation['assigned_to'] = representation.pop('assigned_to_details')
        return representation