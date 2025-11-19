from setuptools import setup, find_packages

setup(
    name="spectraine-backend",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi==0.104.1",
        "uvicorn==0.24.0", 
        "pydantic==2.5.0",
        "boto3==1.34.0",
        "python-dotenv==1.0.0",
    ],
    python_requires=">=3.8",
)