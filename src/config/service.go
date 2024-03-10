package config

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
)

func ConfigFromEnv() (*Config, error) {
	config := &Config{}
	configReflection := reflect.ValueOf(config).Elem()

	for i := 0; i < configReflection.NumField(); i++ {
		varName := configReflection.Type().Field(i).Name
		varType := configReflection.Type().Field(i).Type
		field := configReflection.FieldByName(varName)
		envName := getEnvName(varName)
		envVal := os.Getenv(envName)

		if envVal == "" {
			return nil, fmt.Errorf("error env param %s required", envName)
		}

		if varType.String() == "[]string" {
			val := strings.Split(envVal, ",")
			field.Set(reflect.ValueOf(val))
		} else if varType.String() == "bool" {
			var val bool
			json.Unmarshal([]byte(envVal), &val)
			field.Set(reflect.ValueOf(val))
		} else {
			field.SetString(envVal)
		}
	}

	return config, nil
}

var envMatchConfig = regexp.MustCompile("([a-z0-9A-Z])([A-Z])")

func getEnvName(name string) string {
	envName := envMatchConfig.ReplaceAllString(name, "${1}_${2}")
	return strings.ToUpper(envName)
}
