from setuptools import setup, find_packages

setup(
    name="bnvd",
    version="1.0.1",
    author="Juan Mathews Rebello Santos",
    author_email="contato@bnvd.org",
    description="Cliente Python para a API do Banco Nacional de Vulnerabilidades Digitais bnvd.org",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/azurejoga/bnvd",  # ou outro repositório
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests"
    ],
)
