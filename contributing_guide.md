# Contributing to Flipper Zero Firmware Next

Thank you for your interest in contributing to Flipper Zero Firmware Next! This document provides comprehensive guidelines for contributing to ensure high-quality, secure, and maintainable code.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## 🤝 Code of Conduct

This project adheres to a professional code of conduct. By participating, you agree to:

- **Be Respectful**: Treat all community members with respect and professionalism
- **Be Inclusive**: Welcome diverse perspectives and backgrounds
- **Be Constructive**: Provide helpful feedback and suggestions
- **Be Collaborative**: Work together towards common goals
- **Be Responsible**: Take ownership of your contributions and their security implications

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed:

```bash
# Essential tools
git (>= 2.30)
gcc-arm-none-eabi (>= 10.3)
python3 (>= 3.8)
cmake (>= 3.20)
ninja-build

# Code quality tools
clang-format (>= 12.0)
clang-tidy (>= 12.0)
cppcheck (>= 2.6)
valgrind (Linux only)

# Optional but recommended
ccache (for faster builds)
doxygen (for documentation)
graphviz (for documentation diagrams)
```

### Environment Setup

1. **Fork and Clone**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/flipper-zero-firmware-next.git
   cd flipper-zero-firmware-next
   
   # Add upstream remote
   git remote add upstream https://github.com/original-owner/flipper-zero-firmware-next.git
   ```

2. **Install Dependencies**
   ```bash
   # Run setup script
   ./scripts/setup.sh
   
   # Install pre-commit hooks
   pip3 install pre-commit
   pre-commit install
   ```

3. **Verify Setup**
   ```bash
   # Run build test
   ./fbt test_build
   
   # Run code quality checks
   ./fbt lint
   ```

## 🔄 Development Workflow

### Branch Strategy

We use **GitFlow** with security enhancements:

- **`main`**: Production-ready code, protected branch
- **`develop`**: Integration branch for features
- **`feature/feature-name`**: New feature development
- **`security/issue-description`**: Security fixes (high priority)
- **`hotfix/issue-description`**: Critical production fixes
- **`release/version-number`**: Release preparation

### Creating a Feature Branch

```bash
# Update your local repository
git checkout develop
git pull upstream develop

# Create feature branch
git checkout -b feature/descriptive-feature-name

# Push to your fork
git push -u origin feature/descriptive-feature-name
```

### Development Process

1. **Design Phase**
   - Document your approach in the issue or RFC
   - Consider security implications
   - Design modular, testable components

2. **Implementation Phase**
   - Write clean, documented code
   - Follow coding standards
   - Implement comprehensive tests
   - Add security measures where applicable

3. **Testing Phase**
   - Run all tests locally
   - Test on actual hardware when possible
   - Verify performance requirements
   - Security testing for sensitive components

4. **Documentation Phase**
   - Update API documentation
   - Add usage examples
   - Update relevant guides

## 📝 Coding Standards

### C/C++ Guidelines

#### Code Style
```c
// Use clang-format for automatic formatting
// Configuration in .clang-format

// Function naming: snake_case
int calculate_checksum(const uint8_t* data, size_t length);

// Type naming: PascalCase with suffix
typedef struct {
    uint32_t id;
    char name[64];
} DeviceInfo_t;

// Constants: UPPER_SNAKE_CASE
#define MAX_BUFFER_SIZE 1024
#define DEFAULT_TIMEOUT_MS 5000

// Variables: snake_case
uint32_t device_count = 0;
bool is_connected = false;
```

#### Security Practices
```c
// Input validation
bool validate_input(const char* input, size_t max_length) {
    if (!input || strlen(input) > max_length) {
        return false;
    }
    // Additional validation logic
    return true;
}

// Secure memory handling
void secure_memcpy(void* dest, const void* src, size_t n) {
    if (!dest || !src || n == 0) return;
    
    memcpy(dest, src, n);
    // Clear source if sensitive
    if (is_sensitive_data(src)) {
        explicit_bzero((void*)src, n);
    }
}

// Error handling
typedef enum {
    RESULT_OK = 0,
    RESULT_ERROR_INVALID_PARAM,
    RESULT_ERROR_OUT_OF_MEMORY,
    RESULT_ERROR_SECURITY_VIOLATION
} Result_t;
```

#### Memory Management
```c
// Always check allocations
void* safe_malloc(size_t size) {
    if (size == 0 || size > MAX_ALLOCATION_SIZE) {
        return NULL;
    }
    
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);  // Zero initialization
    }
    return ptr;
}

// Paired allocation/deallocation
typedef struct {
    void* data;
    size_t size;
} Buffer_t;

Buffer_t* buffer_create(size_t size) {
    Buffer_t* buffer = safe_malloc(sizeof(Buffer_t));
    if (!buffer) return NULL;
    
    buffer->data = safe_malloc(size);
    if (!buffer->data) {
        free(buffer);
        return NULL;
    }
    
    buffer->size = size;
    return buffer;
}

void buffer_destroy(Buffer_t* buffer) {
    if (!buffer) return;
    
    if (buffer->data) {
        explicit_bzero(buffer->data, buffer->size);
        free(buffer->data);
    }
    free(buffer);
}
```

### Python Guidelines

```python
# Follow PEP 8 and use Black formatter
# Type hints required for all functions

from typing import List, Optional, Dict, Any
import logging

def process_data(
    input_data: List[str], 
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, int]:
    """
    Process input data with optional configuration.
    
    Args:
        input_data: List of strings to process
        options: Optional configuration parameters
        
    Returns:
        Dictionary with processing results
        
    Raises:
        ValueError: If input_data is empty
        SecurityError: If data contains malicious content
    """
    if not input_data:
        raise ValueError("Input data cannot be empty")
    
    # Input validation
    for item in input_data:
        if not validate_input(item):
            raise SecurityError(f"Invalid input detected: {item}")
    
    # Processing logic
    results = {}
    for item in input_data:
        results[item] = len(item)
    
    return results
```

## 🔒 Security Guidelines

### Security Review Requirements

All contributions must undergo security review if they:

- Handle user input or external data
- Implement cryptographic functions
- Manage authentication or authorization
- Access hardware peripherals
- Implement network communication
- Handle file system operations

### Secure Coding Practices

#### Input Validation
```c
// Always validate inputs at boundaries
bool is_valid_device_id(uint32_t device_id) {
    return device_id > 0 && device_id <= MAX_DEVICE_ID;
}

// Sanitize string inputs
char* sanitize_filename(const char* input) {
    if (!input) return NULL;
    
    // Remove dangerous characters
    char* sanitized = strdup(input);
    for (int i = 0; sanitized[i]; i++) {
        if (strchr("./\\<>:|\"*?", sanitized[i])) {
            sanitized[i] = '_';
        }
    }
    return sanitized;
}
```

#### Cryptographic Operations
```c
// Use established libraries, never implement crypto from scratch
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

typedef struct {
    mbedtls_gcm_context ctx;
    uint8_t key[32];  // AES-256 key
    bool initialized;
} CryptoContext_t;

Result_t crypto_encrypt(
    CryptoContext_t* context,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    if (!context || !context->initialized) {
        return RESULT_ERROR_INVALID_PARAM;
    }
    
    // Generate random IV
    uint8_t iv[16];
    if (generate_random(iv, sizeof(iv)) != RESULT_OK) {
        return RESULT_ERROR_SECURITY_VIOLATION;
    }
    
    // Perform encryption
    int ret = mbedtls_gcm_crypt_and_tag(
        &context->ctx,
        MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        iv, sizeof(iv),
        NULL, 0,  // No additional data
        plaintext,
        ciphertext + sizeof(iv),  // Leave space for IV
        16, ciphertext + sizeof(iv) + plaintext_len  // Tag location
    );
    
    if (ret != 0) {
        return RESULT_ERROR_SECURITY_VIOLATION;
    }
    
    // Prepend IV to ciphertext
    memcpy(ciphertext, iv, sizeof(iv));
    *ciphertext_len = sizeof(iv) + plaintext_len + 16;  // IV + data + tag
    
    return RESULT_OK;
}
```

### Security Testing

```bash
# Static analysis
./fbt security_scan

# Dynamic analysis (if applicable)
./fbt fuzzing

# Dependency check
./fbt dependency_check

# Secret scanning
./fbt secret_scan
```

## 🧪 Testing Requirements

### Test Coverage

- **Unit Tests**: Minimum 80% line coverage for new code
- **Integration Tests**: Required for API changes
- **Hardware Tests**: Required for driver modifications
- **Security Tests**: Required for security-sensitive code

### Test Structure

```c
// test_example.c
#include "unity.h"
#include "example_module.h"

void setUp(void) {
    // Initialize test environment
    example_module_init();
}

void tearDown(void) {
    // Clean up
    example_module_deinit();
}

void test_example_function_valid_input(void) {
    // Arrange
    uint32_t input = 42;
    uint32_t expected = 84;
    
    // Act
    uint32_t result = example_double(input);
    
    // Assert
    TEST_ASSERT_EQUAL_UINT32(expected, result);
}

void test_example_function_invalid_input(void) {
    // Test error conditions
    TEST_ASSERT_EQUAL(RESULT_ERROR_INVALID_PARAM, example_double(0));
}

void test_example_function_boundary_conditions(void) {
    // Test boundary values
    TEST_ASSERT_EQUAL(UINT32_MAX - 1, example_double(UINT32_MAX / 2));
}

// Security test example
void test_example_function_security(void) {
    // Test buffer overflow protection
    char large_input[2048];
    memset(large_input, 'A', sizeof(large_input) - 1);
    large_input[sizeof(large_input) - 1] = '\0';
    
    // Should handle gracefully
    TEST_ASSERT_EQUAL(RESULT_ERROR_INVALID_PARAM, 
                     example_process_string(large_input));
}
```

### Running Tests

```bash
# Run all tests
./fbt test

# Run specific test suite
./fbt test applications/main

# Run with coverage
./fbt test_coverage

# Run security tests
./fbt test_security

# Hardware-in-loop tests (requires hardware)
./fbt test_hardware
```

## 📚 Documentation Standards

### Code Documentation

```c
/**
 * @brief Calculate CRC32 checksum for given data
 * 
 * This function computes a CRC32 checksum using the IEEE 802.3 polynomial.
 * The function is thread-safe and can be called from interrupt context.
 * 
 * @param[in] data Pointer to data buffer (must not be NULL)
 * @param[in] length Number of bytes to process (must be > 0)
 * @param[in] initial_crc Initial CRC value (typically 0xFFFFFFFF)
 * 
 * @return CRC32 checksum value
 * 
 * @warning This function does not validate input parameters for performance
 *          reasons. Caller must ensure parameters are valid.
 * 
 * @note Time complexity: O(n) where n is the length parameter
 * 
 * @since v2.0.0
 * 
 * @example
 * @code
 * uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
 * uint32_t crc = calculate_crc32(data, sizeof(data), 0xFFFFFFFF);
 * @endcode
 */
uint32_t calculate_crc32(const uint8_t* data, size_t length, uint32_t initial_crc);
```

### API Documentation

All public APIs require comprehensive documentation including:

- Purpose and behavior
- Parameter descriptions
- Return value explanation
- Error conditions
- Usage examples
- Security considerations
- Performance characteristics
- Thread safety guarantees

## 🔍 Pull Request Process

### Before Submitting

1. **Code Quality Check**
   ```bash
   # Format code
   ./fbt format
   
   # Run linter
   ./fbt lint
   
   # Run tests
   ./fbt test
   
   # Security scan
   ./fbt security_scan
   ```

2. **Documentation Update**
   - Update API documentation
   - Add changelog entry
   - Update README if needed

3. **Self Review**
   - Review your own code for obvious issues
   - Ensure commits are atomic and well-described
   - Verify no sensitive information is included

### Pull Request Template

When creating a PR, include:

```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Security fix
- [ ] Documentation update

## Security Considerations
- [ ] No security implications
- [ ] Security review required
- [ ] Cryptographic changes
- [ ] Input validation changes
- [ ] Authentication/authorization changes

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Hardware testing completed
- [ ] Security testing completed
- [ ] All tests pass

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] No breaking changes (or documented)
- [ ] Tested on actual hardware
```

### Review Process

1. **Automated Checks**: All CI checks must pass
2. **Peer Review**: At least one approving review required
3. **Security Review**: Required for security-sensitive changes
4. **Maintainer Review**: Final approval from maintainer

### Merging Requirements

- All CI checks pass
- Required reviews obtained
- Conflicts resolved
- Documentation complete
- No security issues identified

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template and include:

- **Environment**: Hardware version, firmware version, OS
- **Steps to Reproduce**: Detailed, numbered steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Logs**: Relevant log files or debug output
- **Security Impact**: If this could be a security issue

### Feature Requests

Use the feature request template and include:

- **Problem Statement**: What problem does this solve?
- **Proposed Solution**: How should it work?
- **Alternatives Considered**: Other approaches you've thought about
- **Security Considerations**: Any security implications
- **Implementation Complexity**: Your assessment of difficulty

### Security Issues

**DO NOT** file public issues for security vulnerabilities. Instead:

1. Email: security@your-domain.com
2. Include: Detailed description, reproduction steps, impact assessment
3. Wait for response before public disclosure
4. Follow responsible disclosure guidelines

## 🏆 Recognition

Contributors are recognized through:

- **Contributors File**: Listed in CONTRIBUTORS.md
- **Release Notes**: Significant contributions mentioned
- **Hall of Fame**: Outstanding contributors featured
- **Swag**: Physical rewards for significant contributions

## ❓ Questions?

- **Technical Questions**: Use GitHub Discussions
- **Process Questions**: Contact maintainers
- **Security Questions**: security@your-domain.com
- **General Questions**: support@your-domain.com

Thank you for contributing to Flipper Zero Firmware Next! 🚀