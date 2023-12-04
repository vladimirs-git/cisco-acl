"""unittests package"""
import re
from pathlib import Path

from vhelpers import vdate, vdict, vpath, vre

ROOT = Path(__file__).parent.parent
PYPROJECT_D = vdict.pyproject_d(ROOT)


def test__version__readme():
    """Version in README, URL."""
    expected = PYPROJECT_D["tool"]["poetry"]["version"]
    package = PYPROJECT_D["tool"]["poetry"]["name"].replace("_", "-")
    readme = PYPROJECT_D["tool"]["poetry"]["readme"]
    readme_text = Path.joinpath(ROOT, readme).read_text(encoding="utf-8")
    url_toml = "pyproject.toml project.urls.DownloadURL"
    url_text = PYPROJECT_D["tool"]["poetry"]["urls"]["Download URL"]

    for source, text in [
        (readme, readme_text),
        (url_toml, url_text),
    ]:
        regexes = [fr"{package}.+/(.+?)\.tar\.gz", fr"{package}@(.+?)$"]
        versions = [v for s in regexes for v in re.findall(s, text, re.M)]
        assert expected in versions, f"version {expected} not in {source}"


def test__version__changelog():
    """Version in CHANGELOG."""
    path = Path.joinpath(ROOT, "CHANGELOG.rst")
    text = path.read_text(encoding="utf-8")
    regex = r"(.+)\s\(\d\d\d\d-\d\d-\d\d\)$"
    actual = vre.find1(regex, text, re.M)

    expected = PYPROJECT_D["tool"]["poetry"]["version"]
    assert actual == expected, f"version in {path=}"


def test__last_modified_date():
    """Last modified date in CHANGELOG."""
    path = Path.joinpath(ROOT, "CHANGELOG.rst")
    text = path.read_text(encoding="utf-8")
    regex = r".+\((\d\d\d\d-\d\d-\d\d)\)$"
    actual = vre.find1(regex, text, re.M)
    files = vpath.get_files(ROOT, ext=".py")
    expected = vdate.last_modified(files)
    assert actual == expected, "last modified file"
