from setuptools import setup, find_packages
setup(
    name = "dotiptables",
    version = "1",
    packages = find_packages(),
    install_requires=open('requirements.txt').readlines(),

    package_data = {
        'dotiptables': [ 'templates/*', ],
        },

    entry_points = {
        'console_scripts': [
            'dotiptables = dotiptables.dotiptables:main',
            ],
        },
)

