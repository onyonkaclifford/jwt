[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/onyonkaclifford/jwt/blob/main/LICENSE)

JSON web tokens implemented in different languages

# Python

[![python tests](https://github.com/onyonkaclifford/jwt/actions/workflows/python_tests.yml/badge.svg?branch=main)](https://github.com/onyonkaclifford/jwt/actions/workflows/python_tests.yml)
[![python lint](https://github.com/onyonkaclifford/jwt/actions/workflows/python_lint.yml/badge.svg?branch=main)](https://github.com/onyonkaclifford/jwt/actions/workflows/python_lint.yml)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Code style: flake8](https://img.shields.io/badge/code%20style-flake8-orange.svg)](https://gitlab.com/pycqa/flake8)

Change directory: `cd python/`

### Example usage

```python
from src import JWT, keys_utils

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
- Run tests and generate a coverage report: `pytest tests/ --cov=src/ --cov-report term-missing`

### Linting

Isort, black and flake8 are used for linting. To automate this task, pre-commit hooks are used.

- Install the git hook scripts: `pre-commit install`
- (optional) Run against all the files: `pre-commit run --all-files`

For full documentation, view the [pre-commit docs](https://pre-commit.com/).

# JavaScript

[![javascript tests](https://github.com/onyonkaclifford/jwt/actions/workflows/javascript_tests.yml/badge.svg?branch=main)](https://github.com/onyonkaclifford/jwt/actions/workflows/javascript_tests.yml)
[![javascript lint](https://github.com/onyonkaclifford/jwt/actions/workflows/javascript_lint.yml/badge.svg?branch=main)](https://github.com/onyonkaclifford/jwt/actions/workflows/javascript_lint.yml)
[![eslint-standard-style](<https://img.shields.io/badge/code%20style-eslint_(standard)-d4d4f7.svg>)](https://github.com/eslint/eslint)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

Change directory: `cd javascript/`

### Example usage

```javascript
import { JWT } from "./src/jwt.js";
import { generateRSAKeys } from "./src/keys_utils.js";

// Example 1 (HMAC)
const secretKey = "secret key";
const jwt = JWT.encode({ sample: "claim" }, secretKey, 234.23, 300000);
const claims = JWT.decode(jwt, secretKey);

// Example 2 (RSA)
const { privateKey, publicKey } = generateRSAKeys();
const jwt = JWT.encode(
  { sample: "claim" },
  privateKey,
  234.23,
  300000,
  undefined,
  "RS256"
);
const claims = JWT.decode(jwt, publicKey);
```

### Tests

- Run tests and generate a coverage report: `npm run testESModule`

### Linting

ESLint and prettier are used for linting. To automate this task, pre-commit hooks are used.

- Install the git hook scripts: `pre-commit install`
- (optional) Run against all the files: `pre-commit run --all-files`

For full documentation, view the [pre-commit docs](https://pre-commit.com/).
