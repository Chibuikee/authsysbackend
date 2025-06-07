from django.db import models


class AbstractDateTime(models.Model):
    """Abstracts a timestamped model with date_created and date_modified"""

    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
