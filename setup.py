from setuptools import setup
import fenrir

setup(
    name='fenrir',
    version=fenrir.__version__,
    long_description=__doc__,
    description='use Fenrir to route configured network devices trough configured VPN tunnel',
    authors=['Hannes Hofer <Hannes.Hofer@gmail.com>'],
    packages=['fenrir'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['cryptography', 'pyroute2', 'python_iptables', 'requests', 'scapy'],
    entry_points={'console_scripts': ['fenrir = fenrir.fenrir:main', ]},
    project_urls={
        'Source': 'https://github.com/HannesHofer/fenrir',
        'Tracker': 'https://github.com/HannesHofer/fenrir/issues'
    }
)
