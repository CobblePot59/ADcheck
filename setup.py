from setuptools import setup, find_packages


with open('README.md', 'r') as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [l.strip() for l in f.readlines()]

setup(
    name="ADcheck",
    version=0.1,
    description="ADcheck, Assess the security of your Active Directory with few or all privileges.",
    url="https://github.com/CobblePot59/ADcheck",
    author="CobblePot59",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(include=['adcheck', 'adcheck.*']),
    license="GPL3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ADcheck=adcheck.app:main',
        ]
    }
)