from setuptools import setup, find_packages

setup(
    name="argus-osint",
    version="2.1.0",
    description="Argus OSINT — evidence-first orchestration with conservative identity correlation",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx[socks]>=0.27", "requests>=2.31", "dnspython>=2.6",
        "phonenumbers>=8.13", "mmh3>=4.1", "beautifulsoup4>=4.12",
        "PyYAML>=6.0", "rich>=13.7",
    ],
    entry_points={"console_scripts": ["argus=argus.cli:main"]},
)
