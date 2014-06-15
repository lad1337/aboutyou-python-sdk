from setuptools import setup
# from pip.req import parse_requirements

import aboutyou.api


with open('README.rst') as src:
  long_description = src.read()


setup(
  name='aboutyou',
  packages=['aboutyou'],
  version=aboutyou.api.VERSION,
  install_requires=['pylibmc>=1.3.0', 'PyYAML'],
  description='A connection to the aboutyou.de shop.',
  long_description=long_description,
  author='Arne Simon',
  author_email='arne.simon@slice-dice.de',
  license='MIT',
  url='https://bitbucket.org/slicedice/aboutyou-shop-sdk-python/overview',
  download_url='https://bitbucket.org/slicedice/aboutyou-shop-sdk-python/downloads',
  keywords=['aboutyou', 'shop', 'collins', 'api'],
  classifiers=[
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.4',
    'Topic :: Internet',
    'Topic :: Office/Business',
  ]
)
