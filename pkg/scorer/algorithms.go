package scorer

import (
	"fmt"
	"math"
)

// RiskCalculator calculates the risk based on the criticality and likelihood of an event happening.
// The calculation takes into account the weights assigned to both criticality and likelihood.
// This function adheres to the guidelines outlined in the document "Weighting the Next Actionable Critical Dependency Proposal".
// For more details, refer to: https://docs.google.com/document/d/1Xb86MrKFQZQNq9rCQb08Dk1b5HU7nzLHkzfjBvbndeM/edit?usp=sharing
// It returns a pointer to the calculated risk value or an error if the sum of weights exceeds 1.
func RiskCalculator(criticality, likelihood, criticalityWeight, likelihoodWeight float64) (*float64, error) {
	if criticalityWeight+likelihoodWeight > 1 {
		return nil, fmt.Errorf("criticalityWeight and likelihoodWeight must be lesser than or equal to 1")
	}

	result := criticality*criticalityWeight + likelihood*likelihoodWeight

	return &result, nil
}

// Scorer calculates a weighted score based on a set of parameters and their respective weights.
// This function implements a scoring algorithm as per the specifications in the "Weighting the Next Actionable Critical Dependency Proposal".
// For more details, refer to: https://docs.google.com/document/d/1Xb86MrKFQZQNq9rCQb08Dk1b5HU7nzLHkzfjBvbndeM/edit?usp=sharing
// It aggregates the weighted scores of individual parameters to compute a final score.
func Scorer(params []ParameterValues) float64 {
	numeratorSum := float64(0)
	totalSum := float64(0)

	for i := 0; i < len(params); i++ {
		numeratorSum += params[i].Weight * calculateNumerator(params[i].Parameter, params[i].K, params[i].L)
		totalSum += params[i].Weight
	}

	return numeratorSum / totalSum
}

// calculateNumerator computes the numerator part of the scoring equation for a single parameter.
// This function is a helper for the scorer function, facilitating the calculation of weighted scores.
// It applies a sigmoid function to the parameter value, as described in the "Weighting the Next Actionable Critical Dependency Proposal".
// For more details, refer to: https://docs.google.com/document/d/1Xb86MrKFQZQNq9rCQb08Dk1b5HU7nzLHkzfjBvbndeM/edit?usp=sharing
func calculateNumerator(param float64, k float64, l float64) float64 {
	return 1 / (1 + math.Pow(math.E, -k*(param-l/2)))
}
