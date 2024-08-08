import os
import requests
import json

from datetime import datetime
from urllib import request

# aws-v4-signature==2.0
from awsv4sign import generate_http11_header

service = 'sts'
region = 'us-west-2'
access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
session_token = os.environ.get('AWS_SESSION_TOKEN', '')

url = 'https://sts.{region}.amazonaws.com/'.format(region=region)
httpMethod = 'post'
canonicalHeaders = {
    'host': f'sts.{region}.amazonaws.com',
    'x-amz-date': datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
    'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
}
if session_token:
    canonicalHeaders['x-amz-security-token'] = session_token

payload_str = "Action=GetCallerIdentity&Version=2011-06-15&"

headers = generate_http11_header(
    service, region, access_key, secret_key,
    url, 'post', canonicalHeaders, {},
    '', payload_str
)

token_request_args = {
    "grant_type": "aws_identity",
    "region": region,
    "post_body": payload_str,
    "headers_json": json.dumps(headers),
}

print(json.dumps(headers, indent=4))

# req = request.Request("https://sts.us-west-2.amazonaws.com/", data=payload_str.encode('utf-8'), headers=headers, method='POST')
# response = request.urlopen(req)

token_response = requests.post("http://localhost:8000/oauth2/access_token",
                               data=token_request_args)

token_info = token_response.json()

print(token_info)
