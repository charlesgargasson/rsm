from setuptools import setup, find_packages

setup(
    name='rsm',
    version='1.1.1',
    packages=find_packages(),
    install_requires=[
    ],
    entry_points={
        'console_scripts': [
            'rsm=src.cli:main',
            'rsmserver=src.srv:main',
        ],
    },
)
