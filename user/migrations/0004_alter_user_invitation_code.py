# Generated by Django 4.2.6 on 2023-10-16 04:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_user_invitation_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='invitation_code',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
