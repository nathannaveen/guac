package scorer

import (
	"encoding/json"
	"fmt"
	"os"
)

type InputData struct {
	Criticality Criticality `json:"criticality"`
	Likelihood  Likelihood  `json:"likelihood"`
}

type Criticality struct {
	NumberOfDependents ParameterValues `json:"number_of_dependents"`
	// add more parameters here for when there are more parameters for criticality
}

type Likelihood struct {
	Scorecard ParameterValues `json:"scorecard"`
	// add more parameters here for when there are more parameters for likelihood
}

type ParameterValues struct {
	K         float64 `json:"k_value"`
	Parameter float64 `json:"parameter"`
	L         float64 `json:"l_value"`
	Weight    float64 `json:"weight"`
}

func ReadNACDInputFile(filePath string) (*InputData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var inputData InputData
	err = json.NewDecoder(file).Decode(&inputData)
	if err != nil {
		return nil, err
	}

	return &inputData, nil
}

func main() {
	filePath := "pkg/scorer/defaultInput.json"
	data, err := ReadNACDInputFile(filePath)
	if err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

	fmt.Println("Successfully read input data:", data)

	// TODO: Add customization layer
}
