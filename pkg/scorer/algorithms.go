package scorer

import (
	"fmt"
	"math"
)

func riskCalculator(criticality, likelihood, criticalityWeight, likelihoodWeight float64) (*float64, error) {
	if criticalityWeight+likelihoodWeight > 1 {
		return nil, fmt.Errorf("criticalityWeight and likelihoodWeight must be lesser than or equal to 1")
	}

	result := criticality*criticalityWeight + likelihood*likelihoodWeight

	return &result, nil
}

func scorer(params []int, weights []int, ks []int, ls []int) float64 {
	numeratorSum := float64(0)
	totalSum := float64(0)

	for i := 0; i < len(params); i++ {
		numeratorSum += numerator(params[i], weights[i], ks[i], ls[i])
		totalSum += float64(weights[i])
	}

	return numeratorSum / totalSum
}

func numerator(param int, weight int, k int, l int) float64 {
	return float64(weight) / (1 + math.Pow(math.E, float64(-k*(param-l/2))))
}
