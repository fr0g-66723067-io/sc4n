from setuptools import setup
from setuptools.command.install import install


class Install(install):
    def run(self):
        import os
        os.system("id")
        install.run(self)


setup(name="evil", version="1.0", cmdclass={"install": Install})
