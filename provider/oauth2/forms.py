import logging
from io import StringIO
from urllib import request
from urllib.error import HTTPError
from xml.etree import ElementTree

from django import forms
from django.contrib.auth import authenticate
from django.conf import settings
from django.utils.translation import gettext as _
from django.utils import timezone
from provider.constants import RESPONSE_TYPE_CHOICES, PKCE, PUBLIC
from provider.forms import OAuthForm, OAuthValidationError
from provider.utils import now, ArnHelper, make_client_secret
from provider.oauth2.models import Client, Grant, RefreshToken, Scope, ClientSecret

log = logging.getLogger('provider.oauth2')

DEFAULT_SCOPE = getattr(settings, 'OAUTH2_DEFAULT_SCOPE', 'read')


class ClientForm(forms.ModelForm):
    """
    Form to create new consumers.
    """
    class Meta:
        model = Client
        fields = ('name', 'url', 'redirect_uri', 'client_type')

    def save(self, user=None, **kwargs):
        self.instance.user = user
        return super(ClientForm, self).save(**kwargs)


class ClientAuthForm(forms.Form):
    """
    Client authentication form. Required to make sure that we're dealing with a
    real client. Form is used in :attr:`provider.oauth2.backends` to validate
    the client.
    """
    client_id = forms.CharField()
    client_secret = forms.CharField()

    def clean(self):

        data = self.cleaned_data
        client = None
        try:
            client = Client.objects.get(
                client_id=data.get('client_id'),
                client_secret=data.get('client_secret'),
            )
        except Client.DoesNotExist:
            try:
                client_secret = ClientSecret.objects.get_by_secret(
                    data.get('client_id'),
                    data.get('client_secret'),
                )
                client = client_secret.client
            except ClientSecret.DoesNotExist:
                pass

        if not client:
            raise forms.ValidationError(_("Client could not be validated with key pair."))

        data['client'] = client
        return data


class PkceClientAuthForm(forms.Form):
    """
    Client authentication form. Required to make sure that we're dealing with a
    real client. Form is used in :attr:`provider.oauth2.backends` to validate
    the client.
    """
    client_id = forms.CharField()
    code_verifier = forms.CharField()
    code = forms.CharField()

    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id=data.get('client_id'), client_type=PKCE)
            grant = Grant.objects.get(client=client, code=data.get('code'))
            if not grant.verify_code_challenge(data.get('code_verifier')):
                raise forms.ValidationError(_("Invalid PKCE grant"))

        except Client.DoesNotExist:
            raise forms.ValidationError(_("Client does not support PKCE"))
        except Grant.DoesNotExist:
            raise forms.ValidationError(_("Invalid PKCE grant"))

        data['client'] = client
        return data



class ScopeModelChoiceField(forms.ModelMultipleChoiceField):

    # widget = forms.TextInput

    def to_python(self, value):
        if isinstance(value, str):
            return [s for s in value.split(' ') if s != '']
        elif isinstance(value, list):
            value_list = list()
            for item in value:
                value_list.extend(self.to_python(item))
            return value_list
        else:
            return value

    def clean(self, value):
        if self.required and not value:
            raise forms.ValidationError(self.error_messages['required'],
                                        code='required')
        value_list = self.to_python(value)
        return super(ScopeModelChoiceField, self).clean(value_list)


class ScopeModelMixin(object):
    def clean_scope(self):
        default = Scope.objects.filter(name__in=DEFAULT_SCOPE.split(' '))
        scope_qs = self.cleaned_data.get('scope', default)
        if scope_qs:
            return scope_qs
        else:
            return default


class AuthorizationRequestForm(ScopeModelMixin, OAuthForm):
    """
    This form is used to validate the request data that the authorization
    endpoint receives from clients.

    Included data is specified in :rfc:`4.1.1`.
    """
    # Setting all required fields to false to explicitly check by hand
    # and use custom error messages that can be reused in the OAuth2
    # protocol
    response_type = forms.CharField(required=False)
    """
    ``"code"`` or ``"token"`` depending on the grant type.
    """

    redirect_uri = forms.URLField(required=False)
    """
    Where the client would like to redirect the user
    back to. This has to match whatever value was saved while creating
    the client.
    """

    state = forms.CharField(required=False)
    """
    Opaque - just pass back to the client for validation.
    """

    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)
    """
    The scope that the authorization should include.
    """

    def clean_response_type(self):
        """
        :rfc:`3.1.1` Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')

        if not response_type:
            raise OAuthValidationError({'error': 'invalid_request',
                'error_description': "No 'response_type' supplied."})

        types = response_type.split(" ")

        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise OAuthValidationError({
                    'error': 'unsupported_response_type',
                    'error_description': u"'%s' is not a supported response "
                        "type." % type})

        return response_type

    def clean_redirect_uri(self):
        """
        :rfc:`3.1.2` The redirect value has to match what was saved on the
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if not redirect_uri == self.client.redirect_uri:
                raise OAuthValidationError({
                    'error': 'invalid_request',
                    'error_description': _("The requested redirect didn't "
                        "match the client settings.")})

        return redirect_uri


class AuthorizationPkceRequestForm(AuthorizationRequestForm):
    code_challenge = forms.CharField(required=False)
    code_challenge_method = forms.CharField(required=False)

    def clean_code_challenge(self):
        code_challenge = self.cleaned_data.get('code_challenge')
        if not code_challenge:
            raise OAuthValidationError({
                'error': 'invalid_request',
                'error_description': _("No 'code_challenge' supplied"),
            })
        return code_challenge

    def clean_code_challenge_method(self):
        method = self.cleaned_data.get('code_challenge_method') or 'plain'
        if method not in ['plain', 'S256']:
            raise OAuthValidationError({
                'error': 'invalid_request',
                'error_description': f"{method} is not a supported code_challenge_method",
            })
        if method == 'plain' and not self.client.allow_plain_pkce:
            raise OAuthValidationError({
                'error': 'invalid_request',
                'error_description': 'client does not allow code_challenge_method=plain',
            })
        return method



class AuthorizationForm(ScopeModelMixin, OAuthForm):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def save(self, **kwargs):
        authorize = self.cleaned_data.get('authorize')

        if not authorize:
            return None

        grant = Grant(**kwargs)
        grant.save()
        grant.scope.set(self.cleaned_data.get('scope'))
        return grant


class RefreshTokenGrantForm(ScopeModelMixin, OAuthForm):
    """
    Checks and returns a refresh token.
    """
    refresh_token = forms.CharField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def clean_refresh_token(self):
        token = self.cleaned_data.get('refresh_token')

        if not token:
            raise OAuthValidationError({'error': 'invalid_request'})

        try:
            token = RefreshToken.objects.get_by_token(token=token,
                expired=False, client=self.client)
        except RefreshToken.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})

        return token

    def clean(self):
        """
        Make sure that the scope is less or equal to the previous scope!
        """
        data = self.cleaned_data

        want_scope = data.get('scope') or None
        refresh_token = data.get('refresh_token')
        access_token = getattr(refresh_token, 'access_token', None) if \
            refresh_token else \
            None
        if refresh_token and want_scope:
            want_scope = {s.name for s in want_scope}
            has_scope = {s.name for s in access_token.scope.all()}
            if want_scope.issubset(has_scope):
                return data
        raise OAuthValidationError({'error': 'invalid_grant'})


class AuthorizationCodeGrantForm(ScopeModelMixin, OAuthForm):
    """
    Check and return an authorization grant.
    """
    code = forms.CharField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)
    code_verifier = forms.CharField(required=False)

    def clean_code(self):
        code = self.cleaned_data.get('code')

        if not code:
            raise OAuthValidationError({'error': 'invalid_request'})

        try:
            self.cleaned_data['grant'] = Grant.objects.get(
                code=code, client=self.client, expires__gt=now())
        except Grant.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})

        return code

    def clean(self):
        """
        Make sure that the scope is less or equal to the scope allowed on the
        grant!
        """
        data = self.cleaned_data
        want_scope = data.get('scope') or None
        grant = data.get('grant')
        if want_scope and grant:
            has_scope = {s.name for s in grant.scope.all()}
            want_scope = {s.name for s in want_scope}
            if want_scope.issubset(has_scope):
                return data
        raise OAuthValidationError({'error': 'invalid_grant'})


class PasswordGrantForm(ScopeModelMixin, OAuthForm):
    """
    Validate the password of a user on a password grant request.
    """
    username = forms.CharField(required=False)
    password = forms.CharField(required=False)
    scope = ScopeModelChoiceField(queryset=Scope.objects.all(), required=False)

    def clean_username(self):
        username = self.cleaned_data.get('username')

        if not username:
            raise OAuthValidationError({'error': 'invalid_request'})

        return username

    def clean_password(self):
        password = self.cleaned_data.get('password')

        if not password:
            raise OAuthValidationError({'error': 'invalid_request'})

        return password

    def clean(self):
        data = self.cleaned_data

        user = authenticate(username=data.get('username'),
            password=data.get('password'))

        if user is None:
            raise OAuthValidationError({'error': 'invalid_grant'})

        data['user'] = user
        return data


class PublicPasswordGrantForm(PasswordGrantForm):
    client_id = forms.CharField(required=True)
    grant_type = forms.CharField(required=True)

    def clean_grant_type(self):
        grant_type = self.cleaned_data.get('grant_type')

        if grant_type != 'password':
            raise OAuthValidationError({'error': 'invalid_grant'})

        return grant_type

    def clean(self):
        data = super(PublicPasswordGrantForm, self).clean()

        try:
            client = Client.objects.get(client_id=data.get('client_id'))
        except Client.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_client'})

        if client.client_type != PUBLIC:
            raise OAuthValidationError({'error': 'invalid_client'})

        data['client'] = client
        return data


class AwsGrantForm(OAuthForm):
    grant_type = forms.CharField(required=True)
    region = forms.CharField(required=True)
    post_body = forms.CharField(required=True)
    headers_json = forms.JSONField(required=True)

    def clean_grant_type(self):
        grant_type = self.cleaned_data.get('grant_type')

        if grant_type != 'aws_identity':
            raise OAuthValidationError({'error': 'invalid_grant'})

        return grant_type

    def clean(self):
        region = self.cleaned_data['region']

        sts_url = f"https://sts.{region}.amazonaws.com/"

        post_body = self.cleaned_data['post_body']
        headers_json = self.cleaned_data['headers_json']

        req = request.Request(sts_url, data=post_body.encode('utf-8'), headers=headers_json, method='POST')
        try:
            response = request.urlopen(req)
        except HTTPError as e:
            log.info("Error calling GetCallerIdentity for aws_identity grant: %s", e)
            raise OAuthValidationError({'error': 'invalid_grant'})

        xmldata = response.read()

        et = ElementTree.parse(StringIO(xmldata.decode('utf-8')))
        root = et.getroot()
        result = root.find('{https://sts.amazonaws.com/doc/2011-06-15/}GetCallerIdentityResult')
        caller_arn = result.find('{https://sts.amazonaws.com/doc/2011-06-15/}Arn').text
        self.cleaned_data['arn_string'] = caller_arn
        self.cleaned_data['arn'] = ArnHelper(caller_arn)
        return self.cleaned_data


class PublicClientForm(OAuthForm):
    client_id = forms.CharField(required=True)
    grant_type = forms.CharField(required=True)
    code = forms.CharField(required=True)
    redirect_uri = forms.CharField(required=False)

    def clean_grant_type(self):
        grant_type = self.cleaned_data.get('grant_type')

        if grant_type != 'authorization_code':
            raise OAuthValidationError({'error': 'invalid_grant'})

        return grant_type

    def clean(self):
        data = super().clean()
        try:
            client = Client.objects.get(
                client_id=data.get('client_id'),
                client_type=PUBLIC,
                allow_public_token=True,
            )
        except Client.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_client'})
        now = timezone.now().astimezone(timezone.get_current_timezone())
        try:
            redirect_uri = data.get('redirect_uri')
            grant = Grant.objects.get(
                client=client,
                code=data['code'],
            )
            if grant.redirect_uri and grant.redirect_uri != data.get('redirect_uri'):
                raise OAuthValidationError({
                    'error': 'invalid_grant',
                    'debug': f'redirect_uri: {redirect_uri}',
                })
            if grant.expires < now:
                raise OAuthValidationError({
                    'error': 'invalid_grant',
                    'debug': f'expries: {grant.expires}, now: {now}',
                })
        except Grant.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})

        data['client'] = client
        data['grant'] = grant
        return data


class ClientSecretAdminCreateForm(forms.ModelForm):
    class Meta:
        model = ClientSecret
        fields = ['description', 'client', 'expiration_date']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.plain_client_secret = None
        if not self.instance.secret_first6 or not self.instance.secret_hash:
            new_secret, first6, secret_hash = make_client_secret()
            self.plain_client_secret = new_secret
            self.instance.secret_first6 = first6
            self.instance.secret_hash = secret_hash
