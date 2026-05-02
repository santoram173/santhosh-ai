from setuptools import setup, find_packages

setup(
    name="santhosh-ai",
    version="2.0.0",
    description="Santhosh AI — Security & Fraud Intelligence Platform CLI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Santhosh AI Team",
    url="https://github.com/santhosh-ai/santhosh-ai",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.7.1",
        "pydantic-settings>=2.2.1",
        "PyYAML>=6.0.1",
        "requests>=2.31.0",
        "rich>=13.7.1",
    ],
    entry_points={
        "console_scripts": [
            "santhosh=cli.santhosh:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="security fraud-detection static-analysis vulnerability-scanner ai",
)
