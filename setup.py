from setuptools import find_packages, setup


setup(
    name="osinter",
    version="1.0.0",
    description="osinter — Complete OSINT Framework",
    long_description="A complete, production-ready OSINT reconnaissance framework in Python.",
    long_description_content_type="text/plain",
    author="osinter contributors",
    packages=find_packages(exclude=("tests",)),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "osinter=osinter.cli:main",
        ]
    },
)
