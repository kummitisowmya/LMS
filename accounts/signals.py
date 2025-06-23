from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import Group
from .models import User

@receiver(post_save, sender=User)
def assign_user_group(sender, instance, created, **kwargs):
    if created:
        if instance.role == "student":
            group, _ = Group.objects.get_or_create(name="Students")
            instance.groups.add(group)
        elif instance.role == "staff":
            group, _ = Group.objects.get_or_create(name="Staff")
            instance.groups.add(group)
        elif instance.role == "admin":
            group, _ = Group.objects.get_or_create(name="Admins")
            instance.groups.add(group)
