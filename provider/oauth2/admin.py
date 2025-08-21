from django.contrib import admin
from django.contrib import messages
from django.utils.safestring import mark_safe

from provider.oauth2 import models
from provider.oauth2.forms import ClientSecretAdminCreateForm


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'token_prefix', 'expires',)
    raw_id_fields = ('user',)


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'access_token', 'user', 'client', 'expired')
    raw_id_fields = ('user',)


class GrantAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'code', 'expires',)
    raw_id_fields = ('user',)


class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'redirect_uri', 'client_id',
                    'client_type', 'auto_authorize')
    raw_id_fields = ('user',)


class ClientSecretAdmin(admin.ModelAdmin):
    list_display = ('client_name', 'client_id', 'secret_prefix', 'description', 'expiration_date')

    def get_form(self, request, obj=None, change=None, **kwargs):
        kwargs["form"] = ClientSecretAdminCreateForm
        return super().get_form(request, obj=obj, change=change, **kwargs)

    def save_form(self, request, form, change):
        if form.plain_client_secret:
            messages.info(request, mark_safe(f"New client secret created for client {form.instance.client.client_id}: {form.plain_client_secret}<br/>This will not be shown again."))
        return super().save_form(request, form, change)

    def client_id(self, obj):
        return obj.client.client_id

    def client_name(self, obj):
        return obj.client.name


class AuthorizedClientAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'authorized_at')
    raw_id_fields = ('user',)


class AwsAccountAdmin(admin.ModelAdmin):
    list_display = ('arn', 'client', 'max_token_lifetime')
    raw_id_fields = ('acting_user',)


admin.site.register(models.AccessToken, AccessTokenAdmin)
admin.site.register(models.Grant, GrantAdmin)
admin.site.register(models.Client, ClientAdmin)
admin.site.register(models.ClientSecret, ClientSecretAdmin)
admin.site.register(models.AuthorizedClient, AuthorizedClientAdmin)
admin.site.register(models.AwsAccount, AwsAccountAdmin)
admin.site.register(models.RefreshToken, RefreshTokenAdmin)
admin.site.register(models.Scope)
