from setuptools import setup
import fenrircore

setup(
    name='fenrircore',
    version=fenrircore.__version__,
    description='use Fenrir to route configured network devices trough configured VPN tunnel',
    long_description="""Fenrir provides a user friendly way to route all traffic from configured trough a VPN tunnel.

This is done via ARP Spoofing. Determined default GW on inputinterface is spoofed to configured device.
    """,
    authors=['Hannes Hofer <Hannes.Hofer@gmail.com>'],
    packages=['fenrircore'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['cryptography', 'pyroute2', 'python_iptables', 'requests', 'scapy'],
    entry_points={'console_scripts': ['fenrir = fenrircore.fenrir:main', ]},
    project_urls={
        'Source': 'https://github.com/HannesHofer/fenrir',
        'Tracker': 'https://github.com/HannesHofer/fenrir/issues'
    }
)
