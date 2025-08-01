# Generated by Django 4.2 on 2024-08-07 19:03

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oauth2', '0003_public_client_options'),
    ]

    operations = [
        migrations.CreateModel(
            name='AwsAccount',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('arn', models.CharField(help_text='AWS User or Role ARN', max_length=255, unique=True)),
                ('general_type', models.CharField(blank=True, max_length=15, null=True)),
                ('account_id', models.CharField(blank=True, max_length=12, null=True)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('autoprovision_user', models.BooleanField(default=True, help_text='Automatically create acting user on first use')),
                ('acting_user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
                ('max_token_lifetime', models.IntegerField(default=3600, blank=True, help_text="Maximum access token lifetime in seconds")),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='oauth2.client')),
                ('scope', models.ManyToManyField(help_text='Scopes to be applied to tokens', to='oauth2.scope')),
            ],
            options={
                'db_table': 'oauth2_awsaccount',
                'unique_together': {('general_type', 'account_id', 'name')},
            },
        ),
    ]
