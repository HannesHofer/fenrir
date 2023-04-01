from setuptools import setup

setup(
    name='fenrir',
    version='0.2.0',
    long_description=__doc__,
    description='use Fenrir to route configured network devices trough configured VPN tunnel',
    authors=['Hannes Hofer <Hannes.Hofer@gmail.com>'],
    packages=['fenrir'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['cryptography', 'pyroute2', 'python_iptables', 'requests', 'scapy'],
    entry_points={'console_scripts': ['fenrir = fenrir.fenrir:main', ]},
)
