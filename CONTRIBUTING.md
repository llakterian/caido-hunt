# Contributing to Caido Hunt

First off, thank you for considering contributing to Caido Hunt! It's people like you that make Caido Hunt such a great tool for the security community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)

## 🤝 Code of Conduct

By participating in this project, you are expected to uphold our code of conduct:

- **Be Respectful**: Treat everyone with respect and kindness
- **Be Constructive**: Provide constructive feedback and criticism
- **Be Collaborative**: Work together towards common goals
- **Be Professional**: Maintain professionalism in all interactions
- **Be Ethical**: Use this tool responsibly and legally

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- A GitHub account
- Familiarity with web security concepts

### First Time Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/caido-hunt.git
   cd caido-hunt
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/llakterian/caido-hunt.git
   ```

4. **Create a virtual environment**:
   ```bash
   python -m venv caido-env
   source caido-env/bin/activate  # Linux/macOS
   # OR
   caido-env\Scripts\activate     # Windows
   ```

5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-cov black flake8  # Development tools
   ```

## 💡 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**Great Bug Reports Include:**
- Clear, descriptive title
- Detailed steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Screenshots or logs (if applicable)
- Sample code or target (if safe to share)

**Bug Report Template:**
```markdown
**Description**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. With target '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.2]
- Caido Hunt Version: [e.g., 2.0.0]

**Additional Context**
Any other context about the problem.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues.

**Great Enhancement Suggestions Include:**
- Clear, descriptive title
- Detailed explanation of the proposed feature
- Use cases and benefits
- Potential implementation approach
- Examples from other tools (if applicable)

### Your First Code Contribution

Unsure where to begin? Look for issues labeled:
- `good first issue` - Simple issues for beginners
- `help wanted` - Issues where we need community help
- `documentation` - Documentation improvements

### Pull Requests

We actively welcome your pull requests! See the [Pull Request Process](#pull-request-process) section below.

## 🛠️ Development Setup

### Project Structure

```
caido-hunt/
├── caido_hunt/           # Main package
│   ├── core/            # Core scanning engine
│   ├── modules/         # Vulnerability detection modules
│   └── utils/           # Utility functions
├── tests/               # Test files
├── docs/                # Documentation
├── scripts/             # Utility scripts
└── reports/             # Generated reports
```

### Running the Scanner Locally

```bash
# Run the main scanner
python caido_hunt/main_scanner_fixed.py http://testphp.vulnweb.com --verbose

# Run the ultimate scanner
python ultimate_scanner_challenge.py http://testphp.vulnweb.com --verbose

# Run the GUI
python simple_gui.py --port 5000
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=caido_hunt --cov-report=html

# Run specific test file
pytest tests/test_scanner_core.py
```

## 📐 Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- **Line Length**: Maximum 100 characters (not 79)
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Prefer double quotes for strings
- **Naming Conventions**:
  - `snake_case` for functions and variables
  - `PascalCase` for classes
  - `UPPER_CASE` for constants

### Code Formatting

We use **Black** for automatic code formatting:

```bash
# Format all Python files
black .

# Check formatting without changing files
black --check .
```

### Linting

We use **Flake8** for linting:

```bash
# Run flake8
flake8 caido_hunt/ tests/

# With custom configuration
flake8 --max-line-length=100 --exclude=caido-env caido_hunt/
```

### Type Hints

Use type hints for function signatures:

```python
def test_xss(url: str, param: str) -> List[Vulnerability]:
    """Test for XSS vulnerabilities."""
    pass
```

### Documentation

- **Docstrings**: Use for all public functions, classes, and modules
- **Comments**: Explain complex logic, not obvious code
- **Format**: Use Google-style docstrings

**Example Docstring:**
```python
def scan_target(target: str, config: Dict[str, Any]) -> List[Vulnerability]:
    """
    Scan a target URL for vulnerabilities.

    Args:
        target: The target URL to scan
        config: Configuration dictionary with scan parameters

    Returns:
        List of discovered vulnerabilities

    Raises:
        ValueError: If target URL is invalid
        ConnectionError: If target is unreachable
    """
    pass
```

## 🧪 Testing Guidelines

### Writing Tests

- Write tests for all new features
- Maintain or improve code coverage
- Use descriptive test names
- Include both positive and negative test cases

**Example Test:**
```python
def test_xss_detection_basic_payload():
    """Test XSS detection with basic payload."""
    scanner = Scanner("http://example.com")
    payload = "<script>alert('xss')</script>"
    result = scanner.test_xss("http://example.com/search", "q", payload)
    assert result is not None
    assert result.type == VulnerabilityType.XSS_REFLECTED
```

### Test Categories

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test module interactions
3. **Functional Tests**: Test complete features end-to-end

### Mocking External Requests

Use `unittest.mock` or `responses` library to mock HTTP requests:

```python
import responses

@responses.activate
def test_scanner_with_mock():
    responses.add(
        responses.GET,
        "http://example.com",
        body="<html>Test</html>",
        status=200
    )
    # Your test code here
```

## 📝 Commit Guidelines

### Commit Message Format

Use clear, descriptive commit messages:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(xss): add DOM-based XSS detection module

Implemented new detection logic for DOM-based XSS vulnerabilities
using JavaScript analysis and context-aware payloads.

Closes #123
```

```
fix(scanner): resolve false positive in SQL injection detection

Modified the SQL injection detection to reduce false positives by
implementing better response analysis and error pattern matching.

Fixes #456
```

### Commit Best Practices

- Write in present tense ("add feature" not "added feature")
- Use imperative mood ("move cursor to..." not "moves cursor to...")
- Keep the subject line under 50 characters
- Separate subject from body with a blank line
- Wrap the body at 72 characters
- Reference issues and pull requests

## 🔄 Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following coding standards

4. **Test your changes**:
   ```bash
   pytest tests/
   black --check .
   flake8 caido_hunt/
   ```

5. **Commit your changes** with clear messages

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting the PR

1. **Open a Pull Request** against the `main` branch
2. **Fill out the PR template** completely
3. **Link related issues** using keywords (Fixes #123, Closes #456)
4. **Request review** from maintainers

### PR Requirements

Your PR must:
- ✅ Pass all automated tests
- ✅ Include tests for new features
- ✅ Update documentation if needed
- ✅ Follow coding standards
- ✅ Have a clear description
- ✅ Reference related issues

### PR Review Process

1. **Automated Checks**: CI/CD runs tests automatically
2. **Code Review**: Maintainers review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, maintainers will merge

### After Your PR is Merged

1. Delete your feature branch
2. Sync your fork with upstream
3. Celebrate! 🎉

## 🔒 Security Vulnerabilities

**DO NOT** report security vulnerabilities through GitHub issues.

Please see our [Security Policy](SECURITY.md) for responsible disclosure.

## 📚 Additional Resources

### Documentation

- [README.md](README.md) - Project overview
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [SECURITY.md](SECURITY.md) - Security policy
- [GitHub Wiki](https://github.com/llakterian/caido-hunt/wiki) - Detailed guides

### Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bug Bounty Methodology](https://www.bugcrowd.com/resources/guides/)

### Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Email**: llakterian@gmail.com (for security or private matters)

## 🎯 Areas We Need Help

We're particularly interested in contributions for:

- 🔍 **New Vulnerability Detection Modules**
- 🧪 **Test Coverage Improvements**
- 📚 **Documentation and Tutorials**
- 🌐 **Internationalization (i18n)**
- 🎨 **GUI Improvements**
- ⚡ **Performance Optimizations**
- 🔧 **Bug Fixes**

## 🏆 Recognition

Contributors are recognized in several ways:

- Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Mentioned in release notes
- GitHub contributor badge
- Our eternal gratitude! 🙏

## ❓ Questions?

Don't hesitate to ask questions! You can:

- Open an issue with the `question` label
- Start a discussion on GitHub Discussions
- Email: llakterian@gmail.com

## 📄 License

By contributing to Caido Hunt, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for contributing to Caido Hunt!**

Built with ❤️ by [Llakterian](https://github.com/llakterian) and the community.

*Happy hunting (and coding)! 🎯*