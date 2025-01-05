from setuptools import setup, find_packages

setup(
    name="vulnmorph",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
    ],
    packages=find_packages(),
    author="Team VulnMorph",
    author_email="https://ankitsinghtd.in",
    description="A tool to scan for XSS, SQL Injection, and Open Ports vulnerabilities.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ankitsinghtd/VulnMorph",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)