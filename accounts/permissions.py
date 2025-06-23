from rest_framework.permissions import BasePermission


class IsStudent(BasePermission):
    """Allows access only to students."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "student"


class IsStaff(BasePermission):
    """Allows access only to staff (tutors)."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "staff"


class IsAdmin(BasePermission):
    """Allows access only to admins."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"


class IsStaffOrAdmin(BasePermission):
    """Allows access to staff and admins."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ["staff", "admin"]


class IsStudentOrStaff(BasePermission):
    """Allows access to students and staff."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ["student", "staff"]
