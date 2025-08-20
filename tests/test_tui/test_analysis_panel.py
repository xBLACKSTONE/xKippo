"""
Tests for the analysis panel TUI component.
"""

import pytest
from datetime import datetime, timedelta
from textual.app import App
from textual.widgets import DataTable

from src.honeypot_monitor.tui.analysis_panel import (
    AnalysisPanel, ThreatCategoryDisplay, PatternAnalysisViewer,
    CustomRuleConfig, ThreatHistoryTracker
)
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment


class TestApp(App):
    """Test app for analysis panel components."""
    
    def compose(self):
        yield AnalysisPanel()


@pytest.fixture
def threat_assessment():
    """Create a sample threat assessment."""
    return ThreatAssessment(
        severity="high",
        category="exploitation",
        confidence=0.85,
        indicators=["Privilege escalation", "Suspicious commands"],
        recommended_action="Investigate immediately"
    )


@pytest.fixture
def sample_pattern():
    """Create a sample pattern detection result."""
    return {
        'type': 'brute_force_attack',
        'source_ip': '192.168.1.100',
        'severity': 'high',
        'confidence': 0.9,
        'description': 'Multiple failed login attempts detected',
        'indicators': ['10 authentication failures', 'Time span: 60s'],
        'entry_count': 10,
        'time_span': 60
    }


class TestThreatCategoryDisplay:
    """Test the threat category display component."""
    
    def test_initialization(self):
        """Test threat category display initialization."""
        display = ThreatCategoryDisplay()
        assert display.threat_data == {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    def test_add_threat(self, threat_assessment):
        """Test adding a threat to the display."""
        display = ThreatCategoryDisplay()
        timestamp = datetime.now()
        
        # Mock the query_one method for testing
        class MockTable:
            def __init__(self):
                self.rows = []
            
            def add_row(self, *args):
                self.rows.append(args)
        
        class MockCollapsible:
            def __init__(self):
                self.title = ""
        
        # Mock the query methods
        def mock_query_one(selector, widget_type=None):
            if "table" in selector:
                return MockTable()
            elif "threats" in selector:
                return MockCollapsible()
        
        display.query_one = mock_query_one
        
        # Add threat
        display.add_threat(threat_assessment, timestamp)
        
        # Verify threat was added to data
        assert len(display.threat_data['high']) == 1
        assert display.threat_data['high'][0] == threat_assessment
    
    def test_clear_threats(self):
        """Test clearing all threats."""
        display = ThreatCategoryDisplay()
        
        # Add some test data
        threat = ThreatAssessment(
            severity="medium",
            category="reconnaissance",
            confidence=0.7,
            indicators=["Test indicator"],
            recommended_action="Monitor"
        )
        display.threat_data['medium'].append(threat)
        
        # Mock the query methods
        class MockTable:
            def clear(self):
                pass
        
        class MockCollapsible:
            def __init__(self):
                self.title = ""
        
        def mock_query_one(selector, widget_type=None):
            if "table" in selector:
                return MockTable()
            elif "threats" in selector:
                return MockCollapsible()
        
        display.query_one = mock_query_one
        
        # Clear threats
        display.clear_threats()
        
        # Verify all data is cleared
        for severity in ['critical', 'high', 'medium', 'low']:
            assert len(display.threat_data[severity]) == 0


class TestPatternAnalysisViewer:
    """Test the pattern analysis viewer component."""
    
    def test_initialization(self):
        """Test pattern analysis viewer initialization."""
        viewer = PatternAnalysisViewer()
        assert viewer.patterns == []
    
    def test_add_pattern(self, sample_pattern):
        """Test adding a pattern to the viewer."""
        viewer = PatternAnalysisViewer()
        
        # Mock the query methods
        class MockTable:
            def __init__(self):
                self.rows = []
            
            def add_row(self, *args):
                self.rows.append(args)
        
        class MockStatic:
            def __init__(self):
                self.content = ""
            
            def update(self, content):
                self.content = content
        
        def mock_query_one(selector, widget_type=None):
            if "table" in selector:
                return MockTable()
            else:
                return MockStatic()
        
        viewer.query_one = mock_query_one
        
        # Add pattern
        viewer.add_pattern(sample_pattern)
        
        # Verify pattern was added
        assert len(viewer.patterns) == 1
        assert viewer.patterns[0] == sample_pattern
    
    def test_clear_patterns(self):
        """Test clearing all patterns."""
        viewer = PatternAnalysisViewer()
        
        # Add test data
        viewer.patterns.append({'type': 'test', 'severity': 'low'})
        
        # Mock the query methods
        class MockTable:
            def clear(self):
                pass
        
        class MockStatic:
            def update(self, content):
                pass
        
        def mock_query_one(selector, widget_type=None):
            if "table" in selector:
                return MockTable()
            else:
                return MockStatic()
        
        viewer.query_one = mock_query_one
        
        # Clear patterns
        viewer.clear_patterns()
        
        # Verify patterns are cleared
        assert len(viewer.patterns) == 0


class TestCustomRuleConfig:
    """Test the custom rule configuration component."""
    
    def test_initialization(self):
        """Test custom rule config initialization."""
        config = CustomRuleConfig()
        assert config.custom_rules == []
    
    def test_load_example_rules(self):
        """Test loading example rules."""
        config = CustomRuleConfig()
        
        # Mock the query methods
        class MockTable:
            def __init__(self):
                self.rows = []
            
            def add_columns(self, *args):
                pass
            
            def add_row(self, *args):
                self.rows.append(args)
        
        def mock_query_one(selector, widget_type=None):
            return MockTable()
        
        config.query_one = mock_query_one
        
        # Load example rules
        config._load_example_rules()
        
        # Verify rules were loaded
        assert len(config.custom_rules) > 0
        assert any(rule['name'] == 'Suspicious Downloads' for rule in config.custom_rules)


class TestThreatHistoryTracker:
    """Test the threat history tracker component."""
    
    def test_initialization(self):
        """Test threat history tracker initialization."""
        tracker = ThreatHistoryTracker()
        assert tracker.threat_history == []
    
    def test_add_threat_event(self, threat_assessment):
        """Test adding a threat event to history."""
        tracker = ThreatHistoryTracker()
        
        # Mock the query methods
        class MockTable:
            def __init__(self):
                self.rows = []
            
            def add_row(self, *args):
                self.rows.append(args)
        
        class MockStatic:
            def update(self, content):
                pass
        
        def mock_query_one(selector, widget_type=None):
            if "table" in selector:
                return MockTable()
            else:
                return MockStatic()
        
        tracker.query_one = mock_query_one
        
        # Add threat event
        tracker.add_threat_event(threat_assessment, "192.168.1.100", "Test threat")
        
        # Verify event was added
        assert len(tracker.threat_history) == 1
        assert tracker.threat_history[0]['source_ip'] == "192.168.1.100"
        assert tracker.threat_history[0]['severity'] == threat_assessment.severity


class TestAnalysisPanel:
    """Test the main analysis panel component."""
    
    def test_initialization(self):
        """Test analysis panel initialization."""
        panel = AnalysisPanel()
        assert panel is not None
    
    def test_add_threat_assessment(self, threat_assessment):
        """Test adding a threat assessment to the panel."""
        panel = AnalysisPanel()
        
        # Mock the query methods for child components
        class MockThreatDisplay:
            def add_threat(self, threat, timestamp):
                self.last_threat = threat
        
        class MockHistoryTracker:
            def add_threat_event(self, threat, source_ip, description):
                self.last_event = (threat, source_ip, description)
        
        def mock_query_one(widget_type):
            if widget_type == ThreatCategoryDisplay:
                return MockThreatDisplay()
            elif widget_type == ThreatHistoryTracker:
                return MockHistoryTracker()
        
        panel.query_one = mock_query_one
        
        # Add threat assessment
        panel.add_threat_assessment(threat_assessment, "192.168.1.100", "Test description")
        
        # This test would need more sophisticated mocking in a real implementation
        # For now, we just verify the method doesn't raise an exception
        assert True
    
    def test_add_pattern(self, sample_pattern):
        """Test adding a pattern to the panel."""
        panel = AnalysisPanel()
        
        # Mock the query method for pattern viewer
        class MockPatternViewer:
            def add_pattern(self, pattern):
                self.last_pattern = pattern
        
        def mock_query_one(widget_type):
            return MockPatternViewer()
        
        panel.query_one = mock_query_one
        
        # Add pattern
        panel.add_pattern(sample_pattern)
        
        # This test would need more sophisticated mocking in a real implementation
        # For now, we just verify the method doesn't raise an exception
        assert True


# Integration tests would require running the actual Textual app
# These would be more complex and might require special testing frameworks
class TestAnalysisPanelIntegration:
    """Integration tests for the analysis panel."""
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_full_panel_functionality(self):
        """Test the full analysis panel in a Textual app context."""
        # This would test the actual TUI functionality
        # Requires setting up a proper Textual testing environment
        pass
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_tab_navigation(self):
        """Test navigation between analysis panel tabs."""
        # This would test tab switching functionality
        pass
    
    @pytest.mark.skip(reason="Requires Textual app testing framework")
    def test_data_table_interactions(self):
        """Test interactions with data tables in the analysis panel."""
        # This would test table selection, sorting, etc.
        pass


if __name__ == "__main__":
    pytest.main([__file__])