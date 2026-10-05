package httpx

import (
	"errors"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// NewValidator returns a *validator.Validate configured so FieldError.Field()
// reports the JSON tag name (e.g. "username") instead of the Go struct field
// name (e.g. "Username"), so FormatValidationError describes the API contract
// rather than internal Go types. Register app-specific tags with
// RegisterValidation on the returned instance.
func NewValidator() *validator.Validate {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})
	return v
}

// FormatValidationError converts the error returned by validate.Struct(req)
// into a single, user-facing message — never the raw go-playground/validator
// text, which exposes Go struct/field/tag names. Only the first failing field
// is reported. custom maps an app-specific tag to the text that follows the
// field name, e.g. {"username_chars": "may only contain letters, numbers, and
// underscores"}; it is consulted before the built-in messages.
func FormatValidationError(err error, custom map[string]string) string {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) || len(verrs) == 0 {
		return "invalid request"
	}
	fe := verrs[0]
	field := strings.ReplaceAll(fe.Field(), "_", " ")
	if msg, ok := custom[fe.Tag()]; ok {
		return field + " " + msg
	}
	isSlice := fe.Kind() == reflect.Slice || fe.Kind() == reflect.Array

	switch fe.Tag() {
	case "required":
		return field + " is required"
	case "min":
		if isSlice {
			return field + " must have at least " + fe.Param() + " item(s)"
		}
		return field + " must be at least " + fe.Param() + " characters"
	case "max":
		if isSlice {
			return field + " must have at most " + fe.Param() + " item(s)"
		}
		return field + " must be at most " + fe.Param() + " characters"
	case "len":
		return field + " must be exactly " + fe.Param() + " characters"
	case "oneof":
		return field + " must be one of: " + strings.Join(strings.Fields(fe.Param()), ", ")
	case "hexcolor":
		return field + " must be a valid hex color"
	case "datetime":
		return field + " must be a valid date (YYYY-MM-DD)"
	case "alphanum":
		return field + " must contain only letters and numbers"
	case "email":
		return field + " must be a valid email address"
	case "url", "http_url":
		return field + " must be a valid URL"
	case "uuid", "uuid4":
		return field + " must be a valid UUID"
	case "gt", "gte", "lt", "lte":
		return field + " is out of range"
	default:
		return field + " is invalid"
	}
}
