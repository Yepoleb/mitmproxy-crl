from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime

import flask

from mitmproxy.addons import asgiapp
from mitmproxy import ctx

APP_HOST = "crl.yepoleb.at"
APP_PORT = 80

app = flask.Flask(__name__)

cached_crl = None

@app.route("/dummy.crl")
def dummycrl():
    global cached_crl
    try:
        if cached_crl is None:
            certstore = ctx.master.addons.get("tlsconfig").certstore
            ca_cert = certstore.default_ca._cert
            ca_privkey = certstore.default_privatekey
            crl_builder = x509.CertificateRevocationListBuilder()
            crl_builder = crl_builder.issuer_name(ca_cert.issuer)
            datetime_now = datetime.datetime.now(datetime.timezone.utc)
            crl_builder = crl_builder.last_update(datetime_now)
            # probably a good enough timeframe
            datetime_next_week = datetime_now + datetime.timedelta(days=30)
            crl_builder = crl_builder.next_update(datetime_next_week)
            crl_builder = crl_builder.add_extension(
                x509.CRLNumber(10), # meaningless number
                False
            )
            crl = crl_builder.sign(private_key=ca_privkey, algorithm=hashes.SHA256())
            cached_crl = crl.public_bytes(serialization.Encoding.DER)
    except Exception as e:
          ctx.log.error(repr(e))
          raise
    return cached_crl, {"Content-Type": "application/pkix-crl"}

class Crl(asgiapp.WSGIApp):
    name = "crl"

    def __init__(self):
        super().__init__(app, APP_HOST, APP_PORT)

    def load(self, loader):
        return

    def configure(self, updated):
        self.host = APP_HOST
        self.port = APP_PORT



