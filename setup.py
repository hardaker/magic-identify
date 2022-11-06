import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    required = f.read().splitlines()

setuptools.setup(
    name="magic-identify",
    version="0.2.1",
    author="Wes Hardaker",
    author_email="opensource@hardakers.net",
    description="A python module and command to try really hard to get a mime-type for a file",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hardaker/magic-identify",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            # migrating to pdb prefixes
            'magic-identify = magicidentify.tools.magicidentifycli:main',
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires = '>=3.6',
    install_requires=required,
    test_suite='nose.collector',
    tests_require=['nose'],
)
