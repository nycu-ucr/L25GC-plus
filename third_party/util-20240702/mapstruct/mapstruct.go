package mapstruct

import (
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

// Decode takes an input structure and uses reflection to translate it to
// the output structure with time.Time type. output must be a pointer to a map or struct.
func Decode(input interface{}, output interface{}) error {
	stringToDateTimeHook := func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if t == reflect.TypeOf(time.Time{}) && f == reflect.TypeOf("") {
			return time.Parse(time.RFC3339, data.(string))
		}
		return data, nil
	}

	config := mapstructure.DecoderConfig{
		DecodeHook: stringToDateTimeHook,
		Result:     output,
	}

	decoder, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}
