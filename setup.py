# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


setup(
    name='tc_pdf',
    version='0.0.3',
    url='http://github.com/intellisense/tc_pdf',
    license='MIT',
    author='Aamir Rind',
    author_email='aamir.adnan.rind@gmail.com',
    description='PDF Preview',
    long_description=open('README.rst').read(),
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=[
        'libthumbor',
        'tc_core',
        'thumbor',
        'tornado',
        'Wand'
    ],
    extras_require={
        'tests': [
            'coverage',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
