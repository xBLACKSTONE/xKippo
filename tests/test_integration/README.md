# Integration Test Suite

This directory contains comprehensive integration tests for the Honeypot Monitor CLI application.

## Test Structure

### Test Files

- **`test_comprehensive_integration.py`**: Complete end-to-end workflow tests
- **`test_performance_benchmarks.py`**: Performance and scalability tests
- **`test_core_integration.py`**: Core functionality tests (dependency-free)
- **`test_basic_integration.py`**: Basic integration tests
- **`run_integration_tests.py`**: Test runner and orchestration

### Mock Data

- **`mock_data/sample_kippo_logs.py`**: Mock Kippo log generator
- **`mock_data/log_files/`**: Pre-generated test log files

## Test Categories

### End-to-End Workflow Tests

Tests complete user workflows from log ingestion to analysis:

- **Log Processing Workflow**: File monitoring → parsing → analysis → display
- **Session Correlation**: Tracking activities across multiple log entries
- **Export Functionality**: Data export to CSV and JSON formats
- **Configuration Management**: Loading and validation of configuration files

### IRC Integration Tests

Tests IRC notification system with mock servers:

- **Connection Management**: Connect, disconnect, reconnection handling
- **Alert Sending**: Different alert types and message formatting
- **Rate Limiting**: Prevention of channel flooding
- **Error Handling**: Network failures and recovery

### Performance Benchmarks

Tests application performance under various conditions:

- **Parsing Performance**: Speed tests with different dataset sizes
- **Memory Usage**: Memory consumption and leak detection
- **Concurrent Processing**: Multi-threaded performance testing
- **Real-time Monitoring**: Responsiveness to file changes

### Mock Data Scenarios

Realistic test data covering various attack scenarios:

- **Basic Sessions**: Normal honeypot interactions
- **Malicious Activity**: Threat detection test cases
- **Brute Force Attacks**: Multiple login attempts
- **Reconnaissance**: System enumeration activities
- **File Manipulation**: Upload/download operations
- **Persistence Attempts**: Backdoor installation attempts
- **Multiple IPs**: Cross-session correlation testing
- **Malformed Logs**: Error handling validation

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Generate mock data
python3 tests/test_integration/mock_data/sample_kippo_logs.py
```

### Running All Tests

```bash
# Run complete integration test suite
python3 tests/test_integration/run_integration_tests.py

# Run with pytest (if available)
pytest tests/test_integration/ -v
```

### Running Specific Test Categories

```bash
# Run only core integration tests (no external dependencies)
python3 tests/test_integration/test_core_integration.py

# Run performance benchmarks
python3 tests/test_integration/run_integration_tests.py performance

# Run comprehensive tests
python3 tests/test_integration/run_integration_tests.py comprehensive
```

### Running Individual Test Files

```bash
# Core functionality tests
python3 tests/test_integration/test_core_integration.py

# Performance benchmarks
pytest tests/test_integration/test_performance_benchmarks.py -v -s

# Comprehensive integration tests
pytest tests/test_integration/test_comprehensive_integration.py -v
```

## Test Configuration

### Environment Variables

Set these environment variables to customize test behavior:

```bash
# Test data location
export TEST_DATA_DIR="/tmp/honeypot-test-data"

# Mock IRC server settings
export TEST_IRC_SERVER="localhost"
export TEST_IRC_PORT="6667"

# Performance test parameters
export PERF_TEST_ENTRIES="10000"
export PERF_TEST_TIMEOUT="30"
```

### Test Configuration File

Create `tests/test_integration/test_config.yaml` for custom test settings:

```yaml
test_settings:
  mock_data_size: 10000
  performance_timeout: 30
  memory_limit: "500MB"
  
mock_irc:
  enabled: true
  server: "localhost"
  port: 6667
  
performance_tests:
  enabled: true
  large_dataset_size: 50000
  concurrent_threads: 4
```

## Test Results

### Expected Outcomes

**Core Integration Tests:**
- All model imports and creation: ✓ PASS
- Log parser functionality: ✓ PASS (or SKIP if dependencies missing)
- Threat analyzer functionality: ✓ PASS (or SKIP if dependencies missing)
- Configuration management: ✓ PASS (or SKIP if dependencies missing)
- Mock data generation: ✓ PASS
- End-to-end processing: ✓ PASS (or SKIP if dependencies missing)
- Data export functionality: ✓ PASS (or SKIP if dependencies missing)
- Basic performance: ✓ PASS (or SKIP if dependencies missing)

**Performance Benchmarks:**
- Parsing speed: >500 entries/second
- Memory usage: <500MB for large datasets
- Concurrent processing: >1000 entries/second
- Real-time responsiveness: <2 seconds processing delay

**Comprehensive Integration:**
- End-to-end workflows: Complete log processing pipeline
- IRC integration: Mock server communication
- Session correlation: Multi-entry session tracking
- Export functionality: CSV and JSON data export

### Performance Targets

| Test Category | Target | Measurement |
|---------------|--------|-------------|
| Log Parsing | >500 entries/sec | Single-threaded parsing |
| Threat Analysis | >1000 analyses/sec | Threat detection speed |
| Memory Usage | <500MB | Peak memory for 50k entries |
| Real-time Processing | <2 seconds | File change to display |
| Concurrent Processing | >1000 entries/sec | Multi-threaded throughput |

## Troubleshooting Tests

### Common Issues

**Missing Dependencies:**
- Tests will skip gracefully if optional dependencies are missing
- Core functionality tests run without external dependencies
- Install full dependencies for complete test coverage

**Permission Errors:**
```bash
# Ensure test directories are writable
chmod 755 tests/test_integration/mock_data/log_files/
```

**Memory Issues:**
```bash
# Reduce test dataset size
export PERF_TEST_ENTRIES="1000"
```

**Timeout Issues:**
```bash
# Increase test timeout
export PERF_TEST_TIMEOUT="60"
```

### Debug Mode

Run tests with debug output:

```bash
# Enable debug logging
export HONEYPOT_LOG_LEVEL="DEBUG"

# Run with verbose output
python3 tests/test_integration/run_integration_tests.py --verbose

# Run single test with debugging
pytest tests/test_integration/test_core_integration.py::test_model_imports_and_creation -v -s
```

## Continuous Integration

### GitHub Actions

The test suite is designed to run in CI environments:

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests
on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run integration tests
        run: python3 tests/test_integration/run_integration_tests.py
```

### Local CI Simulation

```bash
# Simulate CI environment
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  python:3.8 \
  bash -c "pip install -r requirements.txt && python3 tests/test_integration/run_integration_tests.py"
```

## Test Coverage

The integration test suite provides coverage for:

- **Core Functionality**: 95%+ of critical paths
- **Error Handling**: Exception scenarios and recovery
- **Performance**: Scalability and resource usage
- **Integration Points**: External system interactions
- **User Workflows**: Complete end-to-end scenarios

### Coverage Reports

Generate coverage reports:

```bash
# Run with coverage
pytest tests/test_integration/ --cov=honeypot_monitor --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Contributing

### Adding New Tests

1. **Identify test category**: Core, performance, or comprehensive
2. **Create test file**: Follow naming convention `test_*.py`
3. **Add to test runner**: Update `run_integration_tests.py` if needed
4. **Document test**: Add description and expected outcomes
5. **Update this README**: Document new test capabilities

### Test Guidelines

- **Independence**: Tests should not depend on each other
- **Cleanup**: Always clean up temporary files and resources
- **Mocking**: Use mocks for external dependencies
- **Performance**: Include performance assertions where appropriate
- **Documentation**: Document test purpose and expected behavior

This integration test suite ensures the reliability, performance, and correctness of the Honeypot Monitor CLI application across various deployment scenarios and use cases.