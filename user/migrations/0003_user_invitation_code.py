# Generated by Django 4.2.6 on 2023-10-16 04:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_rename_email_user_username'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='invitation_code',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
