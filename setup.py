from setuptools import setup, find_packages

setup(
    name="ai-compliance-scanner",
    version="0.1.0",
    author="DUGI",
    author_email="",
    description="CLI tool to scan AI projects for EU AI Act and GDPR compliance gaps",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ddugi/ai-compliance-scanner",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "ai-compliance-scanner=scanner.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
