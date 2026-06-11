"""Management command to create initial admin user."""
from django.core.management.base import BaseCommand
from authentication.models import CustomUser


class Command(BaseCommand):
    help = 'Create initial admin user for CloudSec'

    def handle(self, *args, **options):
        if not CustomUser.objects.filter(username='admin').exists():
            user = CustomUser.objects.create_superuser(
                username='admin',
                email='admin@cloudsec.com',
                password='Admin@123',
                first_name='System',
                last_name='Admin',
            )
            user.role = 'admin'
            user.status = 'active'
            user.email_verified = True
            user.is_active = True
            user.save()
            self.stdout.write(self.style.SUCCESS(
                'Admin created: username=admin, password=Admin@123'
            ))
        else:
            self.stdout.write(self.style.WARNING('Admin user already exists.'))
