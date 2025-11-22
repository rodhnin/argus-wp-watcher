"""
Argus - WordPress Security Scanner
Setup script for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    requirements = [
        line.strip() 
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
else:
    requirements = [
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "dnspython>=2.4.0",
        "PyYAML>=6.0.1",
        "Jinja2>=3.1.2",
        "jsonschema>=4.19.0",
        "colorama>=0.4.6",
    ]

# Optional AI dependencies
extras_require = {
    "ai": [
        "langchain>=0.1.0",
        "openai>=1.0.0",
    ],
    "dev": [
        "pytest>=7.4.0",
        "pytest-cov>=4.1.0",
        "black>=23.0.0",
        "flake8>=6.1.0",
        "mypy>=1.5.0",
    ],
    "docs": [
        "mkdocs>=1.5.0",
        "mkdocs-material>=9.4.0",
    ]
}

# 'all' includes everything
extras_require["all"] = list(set(sum(extras_require.values(), [])))

setup(
    name="argus-wp-watcher",
    version="0.1.0",
    author="Rodney Dhavid Jimenez Chacin (rodhnin)",
    description="WordPress security scanner with AI-powered analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rodhnin/argus-wp-watcher",
    project_urls={
        "Contact": "https://rodhnin.com",
        "Bug Reports": "https://github.com/rodhnin/argus-wp-watcher/issues",
        "Source": "https://github.com/rodhnin/argus-wp-watcher",
        "Documentation": "https://github.com/rodhnin/argus-wp-watcher/tree/main/docs",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docker", "examples"]),
    include_package_data=True,
    package_data={
        "argus": [
            "config/*.yaml",
            "config/prompts/*.txt",
            "schema/*.json",
            "templates/*.j2",
            "db/*.sql",
            "assets/*.txt",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    keywords="wordpress security scanner penetration-testing vulnerability assessment",
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require=extras_require,
    entry_points={
        "console_scripts": [
            "argus=argus.cli:main",
        ],
    },
    zip_safe=False,
    license="MIT",
)