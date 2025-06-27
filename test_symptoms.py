#!/usr/bin/env python3
"""
Test script to verify symptom matching functionality
"""

import sys
import os

# Add the current directory to the path so we can import from main.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the function from main.py
from main import get_predicted_value

def test_symptom_matching():
    """Test various symptom inputs to ensure they match correctly"""
    
    test_cases = [
        ["coughing", "fever"],  # Should match "cough" and "high_fever"
        ["headache", "nausea"],  # Should match exactly
        ["vomiting", "fatigue"],  # Should match exactly
        ["invalid_symptom"],  # Should raise ValueError
        ["cough", "headache", "fever"],  # Should match all
    ]
    
    print("Testing symptom matching functionality...")
    print("=" * 50)
    
    for i, symptoms in enumerate(test_cases, 1):
        print(f"\nTest {i}: {symptoms}")
        try:
            result = get_predicted_value(symptoms)
            print(f"✅ Success: Predicted disease = {result}")
        except ValueError as e:
            print(f"❌ Expected error: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_symptom_matching() 