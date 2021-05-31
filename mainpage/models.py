from django.core.validators import validate_email
from django.db import models


class ProgramWork(models.Model):
    program_name = models.CharField(max_length=100, blank=False, unique=False)
    program_picture = models.ImageField(upload_to="downloadimagesprogram/", blank=False, unique=False)
    program_describe = models.CharField(max_length=500, blank=False, unique=False)
    program_during = models.CharField(max_length=50, blank=False, unique=False)
    program_employment = models.CharField(max_length=50, blank=False, unique=False)
    program_direction = models.CharField(max_length=500, blank=False, unique=False)
    program_requirement = models.CharField(max_length=500, blank=False, unique=False)
    program_contact = models.CharField(max_length=100, blank=False, unique=False)
    program_timing = models.CharField(max_length=50, blank=False, unique=False)
    program_paying = models.CharField(max_length=50, blank=False, unique=False)
    program_count_favourite = models.IntegerField(unique=False, default=0)

    objects: models.Manager()

    def __str__(self):
        return self.program_name


class Users(models.Model):
    user_name = models.CharField(max_length=50, blank=False, unique=False)
    user_address = models.CharField(max_length=50, blank=False, validators=[validate_email], unique=True)
    user_username = models.CharField(max_length=30, blank=False, unique=True)
    user_password = models.BinaryField(max_length=60, blank=False)
    user_status = models.BooleanField(default='False')

    objects: models.Manager()

    def __str__(self):
        return self.user_username


class Favorites(models.Model):
    id = models.AutoField(primary_key=True)
    program_id = models.IntegerField(unique=False)
    user_id = models.IntegerField(unique=False)

    objects: models.Manager()

    def __str__(self):
        return self
