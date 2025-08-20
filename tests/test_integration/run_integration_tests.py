#!/usr/bin/env python3
"""
Integration test runner for honeypot monitor.
Runs comprehensive integration tests and generates reports.
"""

import sys
import os
import time
import subprocess
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from tests.test_integration.mock_data.sample_kippo_logs import MockKippoLogs


class IntegrationTestRunner:
    """Runs and manages integration tests."""
    
    def __init__(self):
        self.test_dir = Path(__file__).parent
        self.project_root = self.test_dir.parent.parent
        self.results = {}
    
    def setup_test_environment(self):
        """Set up test environment and mock data."""
        print("Setting up test environment...")
        
        # Create mock data directory
        mock_data_dir = self.test_dir / "mock_data" / "log_files"
        mock_data_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate mock log files
        scenarios = [
            'basic', 'malicious', 'brute_force', 'reconnaissance',
            'file_manipulation', 'persistence', 'multiple_ips', 'malformed', 'all'
        ]
        
        for scenario in scenarios:
            output_file = mock_data_dir / f"{scenario}_kippo.log"
            MockKippoLogs.create_log_file(scenario, str(output_file))
            print(f"  Created {output_file}")
        
        print("✓ Test environment setup complete")
    
    def run_test_suite(self, test_file, test_name):
        """Run a specific test suite."""
        print(f"\nRunning {test_name}...")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # Run pytest with verbose output
            cmd = [
                sys.executable, "-m", "pytest",
                str(test_file),
                "-v", "-s",
                "--tb=short",
                f"--rootdir={self.project_root}"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_root
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.results[test_name] = {
                'success': result.returncode == 0,
                'duration': duration,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
            if result.returncode == 0:
                print(f"✓ {test_name} passed ({duration:.2f}s)")
            else:
                print(f"✗ {test_name} failed ({duration:.2f}s)")
                print("STDOUT:", result.stdout[-500:] if result.stdout else "None")
                print("STDERR:", result.stderr[-500:] if result.stderr else "None")
            
            return result.returncode == 0
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            self.results[test_name] = {
                'success': False,
                'duration': duration,
                'error': str(e),
                'returncode': -1
            }
            
            print(f"✗ {test_name} error: {e}")
            return False
    
    def run_simple_integration_test(self):
        """Run the simple integration test (no pytest)."""
        print("\nRunning Simple Integration Test...")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # Run the simple integration test directly
            simple_test_file = self.project_root / "test_integration_simple.py"
            
            cmd = [sys.executable, str(simple_test_file)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_root
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.results['Simple Integration'] = {
                'success': result.returncode == 0,
                'duration': duration,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
            if result.returncode == 0:
                print(f"✓ Simple Integration Test passed ({duration:.2f}s)")
                print("Output:", result.stdout[-300:] if result.stdout else "None")
            else:
                print(f"✗ Simple Integration Test failed ({duration:.2f}s)")
                print("STDOUT:", result.stdout[-500:] if result.stdout else "None")
                print("STDERR:", result.stderr[-500:] if result.stderr else "None")
            
            return result.returncode == 0
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            self.results['Simple Integration'] = {
                'success': False,
                'duration': duration,
                'error': str(e),
                'returncode': -1
            }
            
            print(f"✗ Simple Integration Test error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all integration tests."""
        print("Honeypot Monitor - Integration Test Suite")
        print("=" * 60)
        
        # Setup test environment
        self.setup_test_environment()
        
        # Test suites to run
        test_suites = [
            (self.test_dir / "test_comprehensive_integration.py", "Comprehensive Integration Tests"),
            (self.test_dir / "test_performance_benchmarks.py", "Performance Benchmarks"),
        ]
        
        # Run simple integration test first
        self.run_simple_integration_test()
        
        # Run pytest-based test suites
        for test_file, test_name in test_suites:
            if test_file.exists():
                self.run_test_suite(test_file, test_name)
            else:
                print(f"⚠ Test file not found: {test_file}")
                self.results[test_name] = {
                    'success': False,
                    'duration': 0,
                    'error': 'Test file not found',
                    'returncode': -1
                }
        
        # Generate summary report
        self.generate_report()
    
    def generate_report(self):
        """Generate test results report."""
        print("\n" + "=" * 60)
        print("INTEGRATION TEST RESULTS")
        print("=" * 60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for result in self.results.values() if result['success'])
        failed_tests = total_tests - passed_tests
        total_duration = sum(result['duration'] for result in self.results.values())
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Total Duration: {total_duration:.2f}s")
        print()
        
        # Detailed results
        for test_name, result in self.results.items():
            status = "✓ PASS" if result['success'] else "✗ FAIL"
            duration = result['duration']
            print(f"{status} {test_name} ({duration:.2f}s)")
            
            if not result['success']:
                if 'error' in result:
                    print(f"    Error: {result['error']}")
                elif result.get('stderr'):
                    # Show last few lines of stderr
                    stderr_lines = result['stderr'].strip().split('\n')
                    for line in stderr_lines[-3:]:
                        if line.strip():
                            print(f"    {line}")
        
        print("\n" + "=" * 60)
        
        if failed_tests == 0:
            print("🎉 ALL INTEGRATION TESTS PASSED!")
            return True
        else:
            print(f"❌ {failed_tests} TEST(S) FAILED")
            return False
    
    def run_specific_test(self, test_name):
        """Run a specific test by name."""
        test_mapping = {
            'simple': lambda: self.run_simple_integration_test(),
            'comprehensive': lambda: self.run_test_suite(
                self.test_dir / "test_comprehensive_integration.py",
                "Comprehensive Integration Tests"
            ),
            'performance': lambda: self.run_test_suite(
                self.test_dir / "test_performance_benchmarks.py",
                "Performance Benchmarks"
            ),
        }
        
        if test_name in test_mapping:
            self.setup_test_environment()
            success = test_mapping[test_name]()
            self.generate_report()
            return success
        else:
            print(f"Unknown test: {test_name}")
            print(f"Available tests: {', '.join(test_mapping.keys())}")
            return False


def main():
    """Main entry point."""
    runner = IntegrationTestRunner()
    
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        success = runner.run_specific_test(test_name)
    else:
        success = runner.run_all_tests()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())