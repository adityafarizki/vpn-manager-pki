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

		if varType.Name() == "string" {
			field.SetString(os.Getenv(envName))
		} else if varType.String() == "[]string" {
			var val []string
			json.Unmarshal([]byte(os.Getenv(envName)), &val)
			fmt.Println(os.Getenv(strings.ToUpper(varName)))
			field.Set(reflect.ValueOf(val))
		} else if varType.String() == "bool" {
			var val bool
			json.Unmarshal([]byte(os.Getenv(envName)), &val)
			fmt.Println(os.Getenv(strings.ToUpper(varName)))
			field.Set(reflect.ValueOf(val))
		} else {
			return nil, fmt.Errorf("error parsing config from env: %s not implemented", varType.String())
		}
	}

	return config, nil
}

var envMatchConfig = regexp.MustCompile("([a-z0-9A-Z])([A-Z])")

func getEnvName(name string) string {
	envName := envMatchConfig.ReplaceAllString(name, "${1}_${2}")
	return strings.ToUpper(envName)
}
