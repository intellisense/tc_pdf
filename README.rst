Thumbor / PDF Preview
=====================

This extension provides preview for PDF.

Features
--------

Given a PDF URL return preview image of first page

Installation
------------

- Prerequisite: Following system libraries are required:

        - `ImageMagick <https://www.imagemagick.org/script/index.php>`_
        - `Ghostscript <https://www.ghostscript.com/>`_

- Install using ``pip``

    .. code-block:: bash

        $ pip install tc_pdf

- Register the extension within Thumbor's configuration file

    .. code-block:: bash

        COMMUNITY_EXTENSIONS = [
            'tc_pdf',
            ...
        ]

- Launch thumbor with the Thumbor Community custom application:

    .. code-block:: bash

        $ thumbor -a tc_core.app.App

Usage
-----

``tc_pdf`` handler route requires ``/pdf/`` in URL after all filters but before the resource URL part e.g.

    .. code-block::

        http://<thumbor_server>/unsafe/240x240/smart/pdf/localhost:8000/media/document/test.pdf

If you are using `libthumbor <https://github.com/thumbor/libthumbor>`_ to generate URLs then you can use this patch for ``CryptoURL`` class and then use it like this:

    .. code-block::
    
        from crypto import CryptoURL
        
        crypto = CryptoURL(key='my-security-key')

        encrypted_url = crypto.generate(
            width=300,
            height=200,
            smart=True,
            image_url='/path/to/my/pdf_file.pdf',
            pdf=True, # <-- Pass this
        )
