from django.core.management import BaseCommand
from django.contrib.auth.hashers import make_password

from provider.oauth2.models import AccessToken, RefreshToken
from provider.constants import TOKEN_PREFIX_LENGTH


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--save', action='store_true', default=False,
                            help="Save changes (defaults to showing what would be migrated otherwise)")

    def handle(self, *args, **options):
        if not options.get('save'):
            self.stderr.write("Token migration changes will be shown, but not saved. Run with --save to actually migrate.")
        at_qs = AccessToken.objects.filter(token_prefix__isnull=True)
        self.stdout.write(f"Found {at_qs.count()} AccessTokens to migrate.")
        for access_token in at_qs:
            prefix = access_token.token[:TOKEN_PREFIX_LENGTH]
            hashed = make_password(access_token.token)
            self.stdout.write(f"   Converting AccessToken {prefix}: {hashed}\n")
            access_token.token_prefix = prefix
            access_token.token = hashed
            if options.get('save'):
                access_token.save()


        rt_qs = RefreshToken.objects.filter(token_prefix__isnull=True, expired=False)
        self.stdout.write(f"Found {rt_qs.count()} RefreshTokens to migrate.")
        for refresh_token in rt_qs:
            prefix = refresh_token.token[:TOKEN_PREFIX_LENGTH]
            hashed = make_password(refresh_token.token)
            self.stdout.write(f"   Converting AccessToken {prefix}: {hashed}\n")
            refresh_token.token_prefix = prefix
            refresh_token.token = hashed
            if options.get('save'):
                refresh_token.save()
