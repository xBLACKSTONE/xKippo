"""
Unit tests for ThreatAssessment model.
"""

import pytest
from src.honeypot_monitor.models.threat_assessment import ThreatAssessment


class TestThreatAssessment:
    """Test cases for ThreatAssessment model."""
    
    def test_valid_threat_assessment_creation(self):
        """Test creating a valid threat assessment."""
        threat = ThreatAssessment(
            severity="high",
            category="exploitation",
            confidence=0.8,
            indicators=["suspicious command", "file access"],
            recommended_action="Block IP immediately"
        )
        
        assert threat.severity == "high"
        assert threat.category == "exploitation"
        assert threat.confidence == 0.8
        assert threat.indicators == ["suspicious command", "file access"]
        assert threat.recommended_action == "Block IP immediately"
    
    def test_threat_assessment_with_defaults(self):
        """Test creating a threat assessment with default values."""
        threat = ThreatAssessment(
            severity="low",
            category="reconnaissance",
            confidence=0.3
        )
        
        assert threat.indicators == []
        assert threat.recommended_action == ""
    
    def test_invalid_severity_validation(self):
        """Test validation fails for invalid severity."""
        with pytest.raises(ValueError, match="Invalid severity"):
            ThreatAssessment(
                severity="invalid",
                category="reconnaissance",
                confidence=0.5
            )
    
    def test_invalid_category_validation(self):
        """Test validation fails for invalid category."""
        with pytest.raises(ValueError, match="Invalid category"):
            ThreatAssessment(
                severity="medium",
                category="invalid_category",
                confidence=0.5
            )
    
    def test_invalid_confidence_validation(self):
        """Test validation fails for invalid confidence."""
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            ThreatAssessment(
                severity="medium",
                category="reconnaissance",
                confidence=1.5
            )
        
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            ThreatAssessment(
                severity="medium",
                category="reconnaissance",
                confidence=-0.1
            )
    
    def test_add_indicator(self):
        """Test adding indicators to threat assessment."""
        threat = ThreatAssessment(
            severity="medium",
            category="reconnaissance",
            confidence=0.5
        )
        
        threat.add_indicator("suspicious login")
        threat.add_indicator("port scanning")
        threat.add_indicator("")  # Should be ignored
        threat.add_indicator("suspicious login")  # Duplicate, should not be added again
        threat.add_indicator("   file access   ")  # Should be trimmed
        
        assert threat.indicators == ["suspicious login", "port scanning", "file access"]
    
    def test_get_severity_score(self):
        """Test getting numeric severity score."""
        low_threat = ThreatAssessment("low", "reconnaissance", 0.3)
        medium_threat = ThreatAssessment("medium", "reconnaissance", 0.5)
        high_threat = ThreatAssessment("high", "exploitation", 0.8)
        critical_threat = ThreatAssessment("critical", "exploitation", 0.9)
        
        assert low_threat.get_severity_score() == 1
        assert medium_threat.get_severity_score() == 2
        assert high_threat.get_severity_score() == 3
        assert critical_threat.get_severity_score() == 4
    
    def test_is_high_priority(self):
        """Test checking if threat is high priority."""
        low_threat = ThreatAssessment("low", "reconnaissance", 0.3)
        medium_threat = ThreatAssessment("medium", "reconnaissance", 0.5)
        high_threat = ThreatAssessment("high", "exploitation", 0.8)
        critical_threat = ThreatAssessment("critical", "exploitation", 0.9)
        
        assert low_threat.is_high_priority() is False
        assert medium_threat.is_high_priority() is False
        assert high_threat.is_high_priority() is True
        assert critical_threat.is_high_priority() is True
    
    def test_get_risk_score(self):
        """Test calculating risk score."""
        threat = ThreatAssessment("high", "exploitation", 0.8)
        expected_risk = 3 * 0.8  # severity_score * confidence
        assert threat.get_risk_score() == expected_risk
    
    def test_update_confidence(self):
        """Test updating confidence level."""
        threat = ThreatAssessment("medium", "reconnaissance", 0.5)
        
        threat.update_confidence(0.7)
        assert threat.confidence == 0.7
        
        with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
            threat.update_confidence(1.1)
    
    def test_escalate_severity(self):
        """Test escalating severity level."""
        low_threat = ThreatAssessment("low", "reconnaissance", 0.3)
        low_threat.escalate_severity()
        assert low_threat.severity == "medium"
        
        medium_threat = ThreatAssessment("medium", "reconnaissance", 0.5)
        medium_threat.escalate_severity()
        assert medium_threat.severity == "high"
        
        high_threat = ThreatAssessment("high", "exploitation", 0.8)
        high_threat.escalate_severity()
        assert high_threat.severity == "critical"
        
        # Critical should not escalate further
        critical_threat = ThreatAssessment("critical", "exploitation", 0.9)
        critical_threat.escalate_severity()
        assert critical_threat.severity == "critical"
    
    def test_to_dict_serialization(self):
        """Test converting threat assessment to dictionary."""
        threat = ThreatAssessment(
            severity="high",
            category="exploitation",
            confidence=0.8,
            indicators=["command injection", "file access"],
            recommended_action="Block IP"
        )
        
        expected_dict = {
            'severity': 'high',
            'category': 'exploitation',
            'confidence': 0.8,
            'indicators': ['command injection', 'file access'],
            'recommended_action': 'Block IP'
        }
        
        assert threat.to_dict() == expected_dict
    
    def test_from_dict_deserialization(self):
        """Test creating threat assessment from dictionary."""
        data = {
            'severity': 'high',
            'category': 'exploitation',
            'confidence': 0.8,
            'indicators': ['command injection', 'file access'],
            'recommended_action': 'Block IP'
        }
        
        threat = ThreatAssessment.from_dict(data)
        
        assert threat.severity == 'high'
        assert threat.category == 'exploitation'
        assert threat.confidence == 0.8
        assert threat.indicators == ['command injection', 'file access']
        assert threat.recommended_action == 'Block IP'
    
    def test_json_serialization_roundtrip(self):
        """Test JSON serialization and deserialization."""
        original_threat = ThreatAssessment(
            severity="critical",
            category="persistence",
            confidence=0.9,
            indicators=["backdoor installation", "system modification"],
            recommended_action="Immediate investigation"
        )
        
        # Serialize to JSON and back
        json_str = original_threat.to_json()
        restored_threat = ThreatAssessment.from_json(json_str)
        
        # Compare all fields
        assert restored_threat.severity == original_threat.severity
        assert restored_threat.category == original_threat.category
        assert restored_threat.confidence == original_threat.confidence
        assert restored_threat.indicators == original_threat.indicators
        assert restored_threat.recommended_action == original_threat.recommended_action
    
    def test_create_low_threat_factory(self):
        """Test creating low threat using factory method."""
        threat = ThreatAssessment.create_low_threat("reconnaissance", ["port scan"])
        
        assert threat.severity == "low"
        assert threat.category == "reconnaissance"
        assert threat.confidence == 0.5
        assert threat.indicators == ["port scan"]
        assert threat.recommended_action == "Monitor activity"
    
    def test_create_critical_threat_factory(self):
        """Test creating critical threat using factory method."""
        indicators = ["malware detected", "system compromise"]
        action = "Isolate system immediately"
        
        threat = ThreatAssessment.create_critical_threat("exploitation", indicators, action)
        
        assert threat.severity == "critical"
        assert threat.category == "exploitation"
        assert threat.confidence == 0.9
        assert threat.indicators == indicators
        assert threat.recommended_action == action