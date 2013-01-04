from setuptools import setup, find_packages
setup(
    name = "dotiptables",
    author = 'Lars Kellogg-Stedman',
    author_email = 'lars@oddbit.com',
    url = 'http://github.com/larsks/dot-iptables',
    version = "1",
    packages = [ 'dotiptables' ],
    install_requires=open('requirements.txt').readlines(),

    package_data = {
        'dotiptables': [
            'templates/*',
            ],
        },

    entry_points = {
        'console_scripts': [
            'dotiptables = dotiptables.dotiptables:main',
            ],
        },
)

