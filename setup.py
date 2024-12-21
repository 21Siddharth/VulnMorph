from setuptools import setup, find_packages

setup(
    name="vuln_morph",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
    ],
    entry_points={
        "console_scripts": [
            "vuln_morph=vuln_morph.scanner:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool to scan for XSS, SQL Injection, and Open Ports vulnerabilities.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ankit/vulnerability_scanner",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
