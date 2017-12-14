from __future__ import absolute_import

import os
from urllib import quote, unquote
from io import BytesIO
try:
    from urllib2 import urlopen, HTTPError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import HTTPError

from thumbor.context import RequestParameters
from thumbor.handlers.imaging import ImagingHandler
from thumbor.url import Url
from thumbor.utils import logger
import tornado.gen as gen
import tornado
from tornado import httputil

from wand.image import Image, Color
from libthumbor import CryptoURL
from tc_core.web import RequestParser

from tc_pdf.pdf import PDF


class PDFRequestParameters(RequestParameters):
    def __init__(self, **kwargs):
        pdf = kwargs.pop('pdf')
        RequestParameters.__init__(self, **kwargs)
        self.pdf_url = pdf


class PDFHandler(ImagingHandler):
    # unique pattern to identify pdf resource route
    pdf = r'pdf/(?P<pdf>.+)'

    @classmethod
    def regex(cls, has_unsafe_or_hash=True):
        reg = ['/?']

        if has_unsafe_or_hash:
            reg.append(Url.unsafe_or_hash)
        reg.append(Url.debug)
        reg.append(Url.meta)
        reg.append(Url.trim)
        reg.append(Url.crop)
        reg.append(Url.fit_in)
        reg.append(Url.dimensions)
        reg.append(Url.halign)
        reg.append(Url.valign)
        reg.append(Url.smart)
        reg.append(Url.filters)
        reg.append(cls.pdf)

        return ''.join(reg)

    @gen.coroutine
    def get(self, **kwargs):
        # check if request is valid
        yield gen.maybe_future(self.check_pdf(kwargs.copy()))

        pdf = PDF(self.context)
        pdf_path = kwargs.pop('pdf')
        url_parts, pdf_url = pdf.url_parts(pdf_path)
        preview_path = pdf_path.replace('/pdf/', '').replace('.pdf', '.png')

        crypto = CryptoURL(key=self.context.server.security_key)
        options = {k: v for k, v in kwargs.items() if v and k != 'hash'}
        preview_url = crypto.generate(image_url=preview_path, **options)
        kwargs['hash'] = RequestParser.path_to_parameters(preview_url)['hash']

        # Patch the request uri to allow normal thumbor operations
        self.request.uri = preview_url
        self.request.path = preview_url

        kwargs['request'] = self.request
        kwargs['image'] = preview_path
        self.context.request = RequestParameters(**kwargs)

        # Check if preview image already exists
        path = quote(kwargs['image'].encode('utf-8'))
        exists = yield gen.maybe_future(pdf.get(path))
        if not exists:
            # create a new preview
            data = yield self.create_preview(pdf_url)
            if not data:
                logger.error('Failed to create pdf preview...')
                raise tornado.web.HTTPError(400)
            # store it in storage
            yield gen.maybe_future(pdf.put(path, data))

        # set valid file name in headers
        name = os.path.basename(kwargs.get('image', None))
        if name:
            self.set_header(
                'Content-Disposition',
                'inline; filename="{name}"'.format(
                    name=name
                )
            )

        # Call the original ImageHandler.get method to serve the image.
        super(PDFHandler, self).get(**kwargs)

    @gen.coroutine
    def create_preview(self, url, resolution=200):
        out_io = BytesIO()
        try:
            response = urlopen(url)
            if response.code == 200:
                with(Image(blob=response.read(), resolution=resolution)) as source:
                    single_image = source.sequence[0]  # Just work on first page
                    with Image(single_image) as i:
                        i.format = 'png'
                        i.background_color = Color('white')  # Set white background.
                        i.alpha_channel = 'remove'  # Remove transparency and replace with bg.
                        i.save(file=out_io)
                        raise gen.Return(out_io.getvalue())
        except HTTPError as e:
            logger.error('STATUS: %s - Failed to get pdf from url %s' % (str(e.code), url))
            valid_status_code = httputil.responses.get(e.code)
            if valid_status_code:
                self._error(e.code)
            else:
                raise tornado.web.HTTPError(400)
        finally:
            out_io.close()

    @gen.coroutine  # NOQA
    def check_pdf(self, kw):
        if self.context.config.MAX_ID_LENGTH > 0:
            # Check if pdf with an uuid exists in storage
            exists = yield gen.maybe_future(
                self.context.modules.storage.exists(kw['pdf'][:self.context.config.MAX_ID_LENGTH]))
            if exists:
                kw['pdf'] = kw['pdf'][:self.context.config.MAX_ID_LENGTH]

        url = self.request.path

        kw['pdf'] = quote(kw['pdf'].encode('utf-8'))
        if not self.validate(kw['pdf']):
            self._error(400, 'No original pdf was specified in the given URL')
            return

        kw['request'] = self.request
        self.context.request = PDFRequestParameters(**kw)

        has_none = not self.context.request.unsafe and not self.context.request.hash
        has_both = self.context.request.unsafe and self.context.request.hash

        if has_none or has_both:
            self._error(400, 'URL does not have hash or unsafe, or has both: %s' % url)
            return

        if self.context.request.unsafe and not self.context.config.ALLOW_UNSAFE_URL:
            self._error(400, 'URL has unsafe but unsafe is not allowed by the config: %s' % url)
            return

        if self.context.config.USE_BLACKLIST:
            blacklist = yield self.get_blacklist_contents()
            if self.context.request.pdf_url in blacklist:
                self._error(400, 'Source pdf url has been blacklisted: %s' % self.context.request.pdf_url)
                return

        url_signature = self.context.request.hash
        if url_signature:
            signer = self.context.modules.url_signer(self.context.server.security_key)

            try:
                quoted_hash = quote(self.context.request.hash)
            except KeyError:
                self._error(400, 'Invalid hash: %s' % self.context.request.hash)
                return

            url_to_validate = url.replace('/%s/' % self.context.request.hash, '') \
                .replace('/%s/' % quoted_hash, '')

            valid = signer.validate(unquote(url_signature), url_to_validate)

            if not valid and self.context.config.STORES_CRYPTO_KEY_FOR_EACH_IMAGE:
                # Retrieves security key for this pdf if it has been seen before
                security_key = yield gen.maybe_future(
                    self.context.modules.storage.get_crypto(self.context.request.pdf_url))
                if security_key is not None:
                    signer = self.context.modules.url_signer(security_key)
                    valid = signer.validate(url_signature, url_to_validate)

            if not valid:
                self._error(400, 'Malformed URL: %s' % url)
                return
