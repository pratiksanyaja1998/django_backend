# Generated by Django 4.2.6 on 2023-10-12 14:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='email',
            new_name='username',
        ),
    ]
