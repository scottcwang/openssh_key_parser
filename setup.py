import setuptools  # type: ignore

with open('README.md', 'r', encoding='utf8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="openssh_key_parser",
    version="0.0.4",
    author="Scott C Wang",
    author_email="wangsc@cs.wisc.edu",
    description="Parse and pack OpenSSH private and public key files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/scottcwang/openssh_key_parser",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
    install_requires=[
        'bcrypt>=3.0.0',
        'cryptography'
    ]
)
