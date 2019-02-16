import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="heavenlyglory",
    version="1.0",
    author="LambdaFunction",
    author_email="datlambdafunction@gmail.com",
    description="Perform a masscan and send the results to nmap",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lambdaf/heavenlyglory",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
)
