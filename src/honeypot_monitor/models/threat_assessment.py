"""
ThreatAssessment data model for honeypot monitoring.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json


@dataclass
class ThreatAssessment:
    """
    Represents a threat assessment for honeypot activity.
    
    Attributes:
        severity: Threat severity level (low, medium, high, critical)
        category: Threat category (reconnaissance, exploitation, persistence)
        confidence: Confidence level in the assessment (0.0 to 1.0)
        indicators: List of threat indicators that triggered this assessment
        recommended_action: Recommended action to take for this threat
    """
    severity: str
    category: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    recommended_action: str = ""
    
    def __post_init__(self):
        """Validate data after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate the threat assessment data for integrity.
        
        Raises:
            ValueError: If validation fails
        """
        # Validate severity
        valid_severities = {'low', 'medium', 'high', 'critical'}
        if not self.severity or self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {valid_severities}")
        
        # Validate category
        valid_categories = {'reconnaissance', 'exploitation', 'persistence', 'lateral_movement', 'exfiltration', 'unknown'}
        if not self.category or self.category not in valid_categories:
            raise ValueError(f"Invalid category: {self.category}. Must be one of {valid_categories}")
        
        # Validate confidence range
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        
        # Validate indicators list
        if self.indicators is None:
            self.indicators = []
        
        # Validate recommended_action
        if self.recommended_action is None:
            self.recommended_action = ""
    
    def add_indicator(self, indicator: str) -> None:
        """
        Add a threat indicator to the assessment.
        
        Args:
            indicator: Threat indicator to add
        """
        if indicator and indicator.strip():
            indicator = indicator.strip()
            if indicator not in self.indicators:
                self.indicators.append(indicator)
    
    def get_severity_score(self) -> int:
        """
        Get a numeric score for the severity level.
        
        Returns:
            Numeric score (1-4) where higher is more severe
        """
        severity_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_scores.get(self.severity, 0)
    
    def is_high_priority(self) -> bool:
        """
        Check if this threat assessment is high priority.
        
        Returns:
            True if severity is high or critical, False otherwise
        """
        return self.severity in {'high', 'critical'}
    
    def get_risk_score(self) -> float:
        """
        Calculate a combined risk score based on severity and confidence.
        
        Returns:
            Risk score (0.0 to 4.0)
        """
        return self.get_severity_score() * self.confidence
    
    def update_confidence(self, new_confidence: float) -> None:
        """
        Update the confidence level.
        
        Args:
            new_confidence: New confidence level (0.0 to 1.0)
            
        Raises:
            ValueError: If confidence is out of range
        """
        if not (0.0 <= new_confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {new_confidence}")
        self.confidence = new_confidence
    
    def escalate_severity(self) -> None:
        """
        Escalate the severity to the next level if possible.
        """
        escalation_map = {
            'low': 'medium',
            'medium': 'high',
            'high': 'critical'
        }
        if self.severity in escalation_map:
            self.severity = escalation_map[self.severity]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the threat assessment to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the threat assessment
        """
        return {
            'severity': self.severity,
            'category': self.category,
            'confidence': self.confidence,
            'indicators': self.indicators.copy(),
            'recommended_action': self.recommended_action
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatAssessment':
        """
        Create a ThreatAssessment from a dictionary.
        
        Args:
            data: Dictionary containing threat assessment data
            
        Returns:
            ThreatAssessment instance
        """
        return cls(
            severity=data['severity'],
            category=data['category'],
            confidence=data['confidence'],
            indicators=data.get('indicators', []),
            recommended_action=data.get('recommended_action', '')
        )
    
    def to_json(self) -> str:
        """
        Convert the threat assessment to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ThreatAssessment':
        """
        Create a ThreatAssessment from JSON string.
        
        Args:
            json_str: JSON string containing threat assessment data
            
        Returns:
            ThreatAssessment instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def create_low_threat(cls, category: str, indicators: Optional[List[str]] = None) -> 'ThreatAssessment':
        """
        Create a low-severity threat assessment.
        
        Args:
            category: Threat category
            indicators: Optional list of indicators
            
        Returns:
            ThreatAssessment with low severity
        """
        return cls(
            severity='low',
            category=category,
            confidence=0.5,
            indicators=indicators or [],
            recommended_action='Monitor activity'
        )
    
    @classmethod
    def create_critical_threat(cls, category: str, indicators: List[str], action: str) -> 'ThreatAssessment':
        """
        Create a critical-severity threat assessment.
        
        Args:
            category: Threat category
            indicators: List of threat indicators
            action: Recommended action
            
        Returns:
            ThreatAssessment with critical severity
        """
        return cls(
            severity='critical',
            category=category,
            confidence=0.9,
            indicators=indicators,
            recommended_action=action
        )