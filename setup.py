"""Package setup"""

import pathlib

from setuptools import setup  # type: ignore

import cisco_acl as package

VERSION = "0.1.1"
PACKAGE = package.__title__
PACKAGE_ = package.__title__.lower().replace("-", "_")  # PEP 503 normalization
ROOT = pathlib.Path(__file__).parent.resolve()
README = "README.rst"

if __name__ == "__main__":
    setup(
        name=PACKAGE_,
        packages=[PACKAGE_],
        package_data={PACKAGE_: ["py.typed"]},
        version=VERSION,
        description=package.__summary__,
        license=package.__license__,
        long_description=open(README).read(),
        long_description_content_type="text/x-rst",
        author=package.__author__,
        author_email=package.__email__,
        url=package.__url__,
        download_url=package.__download_url__,
        keywords="cisco, nexus, acl, ios, nx-os, networking, telecommunication",
        python_requires=">=3.8",
        install_requires=[],
        classifiers=[
            # "Development Status :: 3 - Alpha",
            # "Development Status :: 4 - Beta",
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            # "Operating System :: Cisco IOS",
            # "Operating System :: Cisco NX-OS",
            "Topic :: System :: Networking",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3.8",
            "Natural Language :: English",
        ],
    )
