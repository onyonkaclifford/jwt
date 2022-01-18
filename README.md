[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/onyonkaclifford/jwt/blob/main/LICENSE)

JSON web tokens implemented in different languages

# Python

[![python tests](https://github.com/onyonkaclifford/jwt/actions/workflows/python_tests.yml/badge.svg)](https://github.com/onyonkaclifford/jwt/actions/workflows/python_tests.yml)
[![python lint](https://github.com/onyonkaclifford/jwt/actions/workflows/python_lint.yml/badge.svg)](https://github.com/onyonkaclifford/jwt/actions/workflows/python_lint.yml)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Code style: flake8](https://img.shields.io/badge/code%20style-flake8-orange.svg)](https://gitlab.com/pycqa/flake8)

### Example usage
```python
from python.src import JWT, keys_utils

# Example 1 (HMAC)
secret_key = "secret key"
jwt = JWT.encode({"sample": "claim"}, secret_key, 234.23, 300000)
claims = JWT.decode(jwt, secret_key)

# Example 2 (RSA)
private_key, public_key = keys_utils.generate_rsa_keys()
jwt = JWT.encode({"sample": "claim"}, private_key, 234.23, 300000, algorithm="RS256")
claims = JWT.decode(jwt, public_key)
```

### Tests
- Install testing tools: `pip install pytest pytest-cov`
- Make python/ the root directory: `cd python`
- Run tests and generate a coverage report: `pytest tests/ --cov=src/  --cov-report term-missing`

### Code formatting and styling

Isort, black and flake8 are used to perform code formatting and styling. To automate this task, pre-commit hooks are
used.

- Install the git hook scripts: `pre-commit install`
- (optional) Run against all the files: `pre-commit run --all-files`

The installed pre-commit hooks will automatically ensure use of a consistent code format and style whenever one commits
changes using git. For full documentation, view the [pre-commit docs](https://pre-commit.com/).
