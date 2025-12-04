#!/usr/bin/env python3
"""
Setup script para BNVD CLI
Instale com: pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name='bnvd-cli',
    version='1.0.0',
    description='Interface de linha de comando para o Banco Nacional de Vulnerabilidades Ciberneticas',
    long_description=open('README.md', encoding='utf-8').read() if __file__ != 'cli/setup.py' else '',
    author='BNVD Team',
    author_email='contato@bnvd.org',
    url='https://github.com/azurejoga/bnvd',
    license='MIT',
    py_modules=['bnvd_cli'],
    install_requires=[
        'requests>=2.28.0',
    ],
    entry_points={
        'console_scripts': [
            'bnvd-cli=bnvd_cli:main',
            'bnvd=bnvd_cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
    ],
    python_requires='>=3.8',
)
