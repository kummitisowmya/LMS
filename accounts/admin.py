from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

class CustomUserAdmin(UserAdmin):
    model = User

    list_display = (
        "email", "first_name", "last_name", "role",
        "mobile_number", "date_of_birth", "is_active", "is_staff"
    )
    list_filter = ("role", "is_active", "is_staff")
    search_fields = ("email", "first_name", "last_name", "mobile_number")
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {
            "fields": (
                "first_name", "last_name", "date_of_birth", "mobile_number"
            )
        }),
        ("Permissions", {
            "fields": (
                "role", "is_active", "is_staff", "is_superuser", "groups", "user_permissions"
            )
        }),
        ("Important Dates", {"fields": ("last_login",)}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email", "first_name", "last_name", "date_of_birth", "mobile_number",
                "role", "password1", "password2", "is_active", "is_staff", "is_superuser"
            ),
        }),
    )

    def has_change_permission(self, request, obj=None):
        return True

admin.site.register(User, CustomUserAdmin)
