package network_schema

import (
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

var (
	data map[string]interface{}
	err  error
)

func ProcessNetworkSchema(network_config_file string) error {
	if data, err = yamlParse(network_config_file); err != nil {
		return fmt.Errorf("error unmarshelling the network-config file")
	}
	if err := validateFile(data, NetworkConfigSchema); err != nil {
		return fmt.Errorf("schema validation failed: %v", err)
	}
	return nil
}

func yamlParse(network_config_file string) (map[string]interface{}, error) {
	var yamlObj map[string]interface{}
	if err := yaml.Unmarshal([]byte(network_config_file), &yamlObj); err == nil {
		if json.Valid([]byte(network_config_file)) {
			return nil, fmt.Errorf("error unmarshelling the YAML file")
		}
		return yamlObj, nil
	}
	return nil, fmt.Errorf("error unmarshelling the YAML file")
}

func validateFile(data map[string]interface{}, SchemaContent string) error {
	sch, err := jsonschema.CompileString("schema.json", SchemaContent)
	if err != nil {
		return fmt.Errorf("error %v", err)
	}
	converted := convertToJSONCompatible(data)
	if err := sch.Validate(converted); err != nil {
		return fmt.Errorf("error %v", err)
	}
	return nil
}

func convertToJSONCompatible(v interface{}) interface{} {
	switch x := v.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range x {
			m[fmt.Sprintf("%v", k)] = convertToJSONCompatible(v)
		}
		return m
	case map[string]interface{}:
		for k, v := range x {
			x[k] = convertToJSONCompatible(v)
		}
		return x
	case []interface{}:
		for i, v := range x {
			x[i] = convertToJSONCompatible(v)
		}
		return x
	default:
		return v
	}
}
