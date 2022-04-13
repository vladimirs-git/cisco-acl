"""Package setup"""

import pathlib

from setuptools import setup, find_packages  # type: ignore

import cisco_acl as packet

VERSION = "0.0.3"
PACKAGE = packet.__title__
PACKAGE_ = packet.__title__.lower().replace("-", "_")  # PEP 503 normalization
ROOT = pathlib.Path(__file__).parent.resolve()

if __name__ == "__main__":
    setup(
        name=PACKAGE_,
        packages=[PACKAGE_],
        version=VERSION,
        license=packet.__license__,
        description=packet.__summary__,
        long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
        long_description_content_type="text/markdown",
        author=packet.__author__,
        author_email=packet.__email__,
        url=packet.__url__,
        download_url=packet.__download_url__,
        keywords="cisco, nexus, acl, ios, nx-os, networking, telecommunication",
        python_requires=">=3.8",
        install_requires=["netaddr==0.8.0"],
        classifiers=[
            "Development Status :: 3 - Alpha",
            # "Development Status :: 4 - Beta",
            # "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            # "Operating System :: Cisco IOS",
            # "Operating System :: Cisco NX-OS",
            "Topic :: System :: Networking",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3.8",
        ],
    )