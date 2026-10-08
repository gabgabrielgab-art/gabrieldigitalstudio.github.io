#!/usr/bin/env python3
# Recomputes the CSP script hashes in index.html. Run after editing any inline <script>.
import re, hashlib, base64, sys
p = sys.argv[1]; s = open(p, encoding='utf-8').read()
bodies = re.findall(r'<script>(.*?)</script>', s, re.S)          # inline, untyped scripts only
hashes = ' '.join("'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode() for b in bodies)
csp = ("default-src 'self'; "
       f"script-src 'self' {hashes} https://www.googletagmanager.com; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; "
       "img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com; "
       "connect-src 'self' https://api.web3forms.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; "
       "media-src 'self'; frame-src https://www.googletagmanager.com; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests")
tag = f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
s2, n = re.subn(r'<!--CSP-->|<meta http-equiv="Content-Security-Policy" content="[^"]*">', tag, s, count=1)
assert n == 1
open(p, 'w', encoding='utf-8').write(s2)
print(len(bodies), 'inline scripts hashed')
