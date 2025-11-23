# Contributing to Argus

Thank you for your interest in contributing to **Argus WordPress Security Scanner**! We welcome contributions from the community to help make Argus better for everyone.

## 📜 Code of Conduct

By participating in this project, you agree to:

-   **Be respectful** of differing viewpoints and experiences
-   **Accept constructive criticism** gracefully
-   **Focus on what is best** for the community and the project
-   **Use Argus ethically** - only on authorized targets with proper consent

## 🚀 Getting Started

### Prerequisites

-   **Python 3.10+** (3.11+ recommended)
-   **Git** for version control
-   **Docker** (optional, for testing lab)
-   Basic understanding of web security and WordPress

### Development Setup

1. **Fork and clone the repository**:

    ```bash
    git clone https://github.com/YOUR_USERNAME/argus-wp-watcher.git
    cd argus-wp-watcher
    ```

2. **Create a virtual environment**:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4. **Install development dependencies**:

    ```bash
    pip install pytest pytest-cov black flake8 mypy
    ```

5. **Run tests to verify setup**:

    ```bash
    pytest tests/
    ```

6. **Set up the testing lab** (optional):
    ```bash
    cd docker
    ./deploy.sh
    # Select option 2 (Testing Lab)
    ```

## 🐛 Reporting Bugs

If you find a bug, please create an issue with:

-   **Clear title** describing the problem
-   **Steps to reproduce** the issue
-   **Expected behavior** vs actual behavior
-   **Environment details** (OS, Python version, Argus version)
-   **Logs or screenshots** if applicable

**Security Vulnerabilities**

**DO NOT** open public issues for security vulnerabilities!

Contact me on [https://rodhnin.com](https://rodhnin.com).

**Template**:

```markdown
### Bug Description

A clear description of what the bug is.

### Steps to Reproduce

1. Run command: `python -m argus --target ...`
2. Observe error at phase X
3. See logs showing...

### Expected Behavior

What should happen.

### Actual Behavior

What actually happens.

### Environment

-   OS: Ubuntu 22.04
-   Python: 3.11.5
-   Argus: 0.1.0
```

## 💡 Suggesting Features

We welcome feature requests! Please:

1. **Check existing issues** to avoid duplicates
2. **Create a detailed proposal** explaining:
    - The problem your feature solves
    - How it would work
    - Potential implementation approach
    - Any security/ethical considerations
3. **Wait for discussion** before starting implementation

## 🔨 Contributing Code

### Branching Strategy

-   **main** - stable production code
-   **develop** - integration branch for features
-   **feature/\*** - new features
-   **fix/\*** - bug fixes
-   **docs/\*** - documentation updates

### Workflow

1. **Create a feature branch**:

    ```bash
    git checkout -b feature/your-feature-name
    ```

2. **Make your changes** following our code standards (see below)

3. **Write tests** for new functionality:

    ```bash
    # Add tests in tests/
    pytest tests/test_your_feature.py
    ```

4. **Run the full test suite**:

    ```bash
    pytest tests/ -v --cov=argus
    ```

5. **Check code style**:

    ```bash
    black argus/ tests/
    flake8 argus/ tests/
    mypy argus/
    ```

6. **Commit your changes**:

    ```bash
    git add .
    git commit -m "feat: add new vulnerability scanner for X"
    ```

7. **Push to your fork**:

    ```bash
    git push origin feature/your-feature-name
    ```

8. **Create a Pull Request** from your fork to the main repository

### Commit Message Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

-   **feat**: New feature
-   **fix**: Bug fix
-   **docs**: Documentation changes
-   **test**: Test additions or changes
-   **refactor**: Code refactoring
-   **perf**: Performance improvements
-   **chore**: Maintenance tasks

**Examples**:

```
feat: add XML-RPC brute force detection
fix: resolve false positives in plugin detection
docs: update Docker deployment instructions
test: add tests for consent token validation
```

## 📝 Code Style Guidelines

### Python Style

-   Follow **PEP 8** style guide
-   Use **type hints** for function signatures
-   Maximum line length: **88 characters** (Black default)
-   Use **docstrings** for all public functions/classes

**Example**:

```python
def scan_target(target_url: str, aggressive: bool = False) -> ScanResult:
    """
    Scan a WordPress target for vulnerabilities.

    Args:
        target_url: The URL to scan (must be WordPress)
        aggressive: Enable aggressive scanning modes

    Returns:
        ScanResult object containing findings

    Raises:
        ValueError: If target_url is invalid
        ConsentError: If consent token not found in aggressive mode
    """
    # Implementation here
    pass
```

### Code Organization

-   **One class per file** (unless tightly coupled)
-   **Logical module structure**:
    -   `argus/core/` - Core functionality (config, logging, database)
    -   `argus/scanners/` - Individual scanner modules
    -   `argus/reporters/` - Report generation
    -   `argus/ai/` - AI integration
    -   `argus/utils/` - Utility functions

### Error Handling

-   Use **specific exceptions** over generic ones
-   Provide **meaningful error messages**
-   Log errors appropriately

```python
# Good
raise ConsentTokenError(f"Consent token not found on {target_url}")

# Bad
raise Exception("Error")
```

### Testing

-   **Minimum 80% code coverage** for new code
-   Use **pytest** for all tests
-   Mock external dependencies (HTTP requests, file I/O)
-   Test edge cases and error conditions

**Example test**:

```python
import pytest
from argus.scanners.wordpress import WordPressDetector

def test_wordpress_detection_success():
    """Test successful WordPress detection."""
    detector = WordPressDetector("https://example.com")
    result = detector.detect()
    assert result.is_wordpress is True
    assert result.version == "6.0"

def test_wordpress_detection_invalid_url():
    """Test error handling for invalid URLs."""
    with pytest.raises(ValueError):
        WordPressDetector("not-a-url")
```

## 📚 Documentation

-   **Update README.md** if you add new features
-   **Add docstrings** to all public APIs
-   **Update CHANGELOG.md** for notable changes
-   **Create examples** for complex features
-   **Update type hints** when changing signatures

## 🔍 Pull Request Process

1. **Ensure all tests pass** and coverage is adequate
2. **Update documentation** as needed
3. **Link related issues** in the PR description
4. **Provide a clear description** of changes
5. **Request review** from maintainers
6. **Address feedback** promptly
7. **Squash commits** before merge (if requested)

### PR Template

```markdown
## Description

Brief description of changes

## Type of Change

-   [ ] Bug fix
-   [ ] New feature
-   [ ] Breaking change
-   [ ] Documentation update

## Testing

-   [ ] All tests pass
-   [ ] New tests added for new functionality
-   [ ] Manual testing completed

## Checklist

-   [ ] Code follows style guidelines
-   [ ] Documentation updated
-   [ ] CHANGELOG.md updated
-   [ ] No breaking changes (or documented)
```

## 🔐 Security Considerations

When contributing to a security tool:

-   **Never commit credentials** or API keys
-   **Sanitize example outputs** in documentation
-   **Consider rate limiting** for any new network operations
-   **Validate user input** thoroughly
-   **Document security implications** of new features

---

## 📞 Questions?

-   **General questions**: Open a GitHub Discussion
-   **Bug reports**: Open a GitHub Issue
-   **Project maintainer**: [rodhnin](https://github.com/rodhnin) | [https://rodhnin.com](https://rodhnin.com)

---

## 📜 License

By contributing to Asterion, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for helping make WordPress security auditing more accessible!** 🛡️

Part of the **Argos Security Suite**:

-   🔥 [Hephaestus](https://github.com/rodhnin/hephaestus-server-forger) - Vulnerability Database Manager
-   🐂 [Asterion](https://github.com/rodhnin/asterion-network-minotaur) - Network Security Auditor
-   🔮 [Pythia](https://github.com/rodhnin/pythia-sql-clairvoyance) - SQL Injection Detection Scanner
-   👁️ **Argus** - WordPress Security Scanner(this project)
