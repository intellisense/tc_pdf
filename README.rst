Thumbor / PDF Preview
=====================

This extension provides preview for PDF.

Features
--------

Given a PDF URL return preview image of first page

Installation
------------
- Install using ``pip``

    .. code-block:: bash

        $ pip install tc_pdf

- Register the extension within Thumbor's configuration file

    .. code-block:: bash

        COMMUNITY_EXTENSIONS = [
            'tc_shortener',
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
