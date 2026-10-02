package toml

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	gotoml "github.com/pelletier/go-toml/v2"
)

// Errors from decoding a config file are built here from the structured fields
// of go-toml's errors - position, key, and a message checked against a list of
// known value-free forms - and never from the text go-toml renders for a human.
//
// That rendered text (DecodeError.String, StrictMissingError.String) quotes the
// lines around the error, so a typo next to `secret = "..."` put the secret into
// the error. Loader errors end up in logs: the desktop CLI prints them, and on
// Android they become the "Client error" line and the error state the app shows
// and stores. A config file holds secrets and server addresses; none of its
// values belong in such a message, only where the problem is and what kind it is.

// decodeFileError turns an error from decoding the file at path into one that
// names the position, the key and the kind of problem, and no value from the
// file.
func decodeFileError(path string, err error) error {
	if serr, ok := errors.AsType[*gotoml.StrictMissingError](err); ok {
		parts := make([]string, 0, len(serr.Errors))
		for i := range serr.Errors {
			parts = append(parts, describeDecodeError(&serr.Errors[i]))
		}
		return fmt.Errorf("%s: %s", path, strings.Join(parts, "; "))
	}
	if derr, ok := errors.AsType[*gotoml.DecodeError](err); ok {
		return fmt.Errorf("%s: %s", path, describeDecodeError(derr))
	}
	// Reading the file failed (a directory, a permission problem): the error
	// names the path and the operation, nothing from the content.
	if _, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Errorf("%s: %w", path, err)
	}
	// Anything else go-toml returns is about the target type rather than the
	// document, but its text is not checked here, so none of it is passed on.
	return fmt.Errorf("%s: cannot decode the file", path)
}

// describeDecodeError renders one DecodeError as "line L, column C: kind" plus
// the key when go-toml knows it.
func describeDecodeError(e *gotoml.DecodeError) string {
	line, col := e.Position()
	msg := fmt.Sprintf("line %d, column %d: %s", line, col, decodeErrorKind(strings.TrimPrefix(e.Error(), "toml: ")))
	if key := safeKey(e.Key()); key != "" {
		msg += " (key " + key + ")"
	}
	return msg
}

// identifierKey is the shape of every key name in the schemas: snake_case,
// starting with a letter, no longer than the longest one with room to spare.
var identifierKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)

// safeKey joins the key parts with dots. A key is text from the document like
// any other, so a part is printed only when it has the shape of a schema field
// name, which covers the misspelt key an "unknown field" error is about.
// Anything else becomes "<unknown>": a value pasted before an "=", a quoted
// key, a 64-character hex secret. The position still says where.
func safeKey(k gotoml.Key) string {
	parts := make([]string, len(k))
	for i, p := range k {
		if identifierKey.MatchString(p) {
			parts[i] = p
		} else {
			parts[i] = "<unknown>"
		}
	}
	return strings.Join(parts, ".")
}

// tomlKinds are the value kinds go-toml names in a type mismatch.
const tomlKinds = `(string|integer|float|boolean|datetime|local datetime|local date|local time|array|inline table|table)`

// goType matches a Go type as reflect prints it: those come from the target
// struct, not from the document.
const goType = `([][*\w.]*(?: \{\})?)`

// decodeKinds maps the go-toml (v2.4.3) message forms that carry something
// from the document - a value, a character - or a key name to a fixed text.
// Groups that come from the target type are kept, nothing else is.
var decodeKinds = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`^cannot decode TOML ` + tomlKinds + ` into struct field ([\w.]+) of type ` + goType + `$`), "cannot decode TOML $1 into struct field $2 of type $3"},
	{regexp.MustCompile(`^(?:negative )?integer value -?\d+ cannot be stored in ` + goType + `$`), "integer value out of range for $1"},
	{regexp.MustCompile(`^float value \S+ cannot be stored in float32$`), "float value out of range for float32"},
	{regexp.MustCompile(`^unable to parse float`), "invalid float"},
	{regexp.MustCompile(`^expected newline but got U\+`), "expected a newline after the value"},
	{regexp.MustCompile(`^expected value but got U\+`), "expected a value"},
	{regexp.MustCompile(`^expected digit but got U\+`), "expected a digit"},
	{regexp.MustCompile(`^invalid escape character U\+`), "invalid escape character"},
	{regexp.MustCompile(`^invalid character at start of key: U\+`), "invalid character at start of key"},
	{regexp.MustCompile(`^unexpected character U\+[0-9A-F]+(?: .*)? at start of value$`), "unexpected character at start of value"},
	{regexp.MustCompile(`^expected (?:keyword )?"\w+"$`), "expected a keyword (true, false, inf or nan)"},
	{regexp.MustCompile(`^table \S+ already exists`), "table defined more than once"},
	{regexp.MustCompile(`^key \S+ (?:is already defined|already exists as a value)$`), "key defined more than once"},
	{regexp.MustCompile(`^key \S+ should be a table, not a \w+$`), "key defined as a value and as a table"},
	{regexp.MustCompile(`^key \S+ already exists as a \w+, but should be an array table$`), "key defined as a value and as an array of tables"},
	{regexp.MustCompile(`^cannot store (a table|an array table) in a ` + goType + `$`), "cannot store $1 in a $2"},
	{regexp.MustCompile(`^array of size \d+ is too small to store this array table$`), "array too small for this array table"},
	{regexp.MustCompile(`^arrays and inline tables are nested more than the maximum of \d+ levels deep$`), "arrays and inline tables are nested too deep"},
}

// staticDecodeMessages are go-toml messages with no formatting verb: fixed
// text, safe as it is. Two are reworded to drop a double quote and a
// backslash, which the Android error state would carry into its JSON.
var staticDecodeMessages = map[string]string{
	"unknown field":                                                                     "unknown field",
	"missing table":                                                                     "missing table",
	"expected '=' after key":                                                            "expected '=' after key",
	"expected ']' to close table name":                                                  "expected ']' to close table name",
	"expected ']]' to close array table name":                                           "expected ']]' to close array table name",
	"expected value, not end of input":                                                  "expected value, not end of input",
	"expected key but reached end of input":                                             "expected key but reached end of input",
	"expected ',' or ']' after array value":                                             "expected ',' or ']' after array value",
	"expected ',' or '}' after inline table key-value":                                  "expected ',' or '}' after inline table key-value",
	"unexpected comma in inline table":                                                  "unexpected comma in inline table",
	"array is incomplete":                                                               "array is incomplete",
	"inline table is incomplete":                                                        "inline table is incomplete",
	"strings must be quoted":                                                            "strings must be quoted",
	"expected number after sign":                                                        "expected number after sign",
	"number must have at least one digit between underscores":                           "number must have at least one digit between underscores",
	"radix prefix must be followed by at least one digit":                               "radix prefix must be followed by at least one digit",
	"sign is not allowed on numbers with a radix prefix":                                "sign is not allowed on numbers with a radix prefix",
	"integers cannot have leading zeroes":                                               "integers cannot have leading zeroes",
	"decimal point must be followed by a digit":                                         "decimal point must be followed by a digit",
	"exponent must contain at least one digit":                                          "exponent must contain at least one digit",
	"hexadecimal number is too large to fit in a 64-bit signed integer":                 "hexadecimal number is too large to fit in a 64-bit signed integer",
	"octal number is too large to fit in a 64-bit signed integer":                       "octal number is too large to fit in a 64-bit signed integer",
	"binary number is too large to fit in a 64-bit signed integer":                      "binary number is too large to fit in a 64-bit signed integer",
	"decimal number is too large to fit in a 64-bit signed integer":                     "decimal number is too large to fit in a 64-bit signed integer",
	"unterminated basic string":                                                         "unterminated basic string",
	"unterminated literal string":                                                       "unterminated literal string",
	`multiline basic string not terminated by """`:                                      "multiline basic string not terminated",
	"multiline literal string not terminated by '''":                                    "multiline literal string not terminated by '''",
	"basic strings cannot have new lines":                                               "basic strings cannot have new lines",
	"literal strings cannot have new lines":                                             "literal strings cannot have new lines",
	"basic strings cannot have control characters":                                      "basic strings cannot have control characters",
	"literal strings cannot have control characters":                                    "literal strings cannot have control characters",
	"multiline basic strings cannot have control characters":                            "multiline basic strings cannot have control characters",
	"multiline literal strings cannot have control characters":                          "multiline literal strings cannot have control characters",
	"too many quotes at the end of a multiline basic string":                            "too many quotes at the end of a multiline basic string",
	"too many quotes at the end of a multiline literal string":                          "too many quotes at the end of a multiline literal string",
	"carriage returns must be followed by a newline character":                          "carriage returns must be followed by a newline character",
	"invalid UTF-8 character in basic string":                                           "invalid UTF-8 character in basic string",
	"invalid UTF-8 character in literal string":                                         "invalid UTF-8 character in literal string",
	"invalid UTF-8 character in multiline basic string":                                 "invalid UTF-8 character in multiline basic string",
	"invalid UTF-8 character in multiline literal string":                               "invalid UTF-8 character in multiline literal string",
	`need a character after \`:                                                          "need a character after a backslash",
	"escape sequence is not a valid unicode code point":                                 "escape sequence is not a valid unicode code point",
	"unicode escape sequence is too short":                                              "unicode escape sequence is too short",
	"invalid hexadecimal digit in unicode escape sequence":                              "invalid hexadecimal digit in unicode escape sequence",
	"carriage returns are not allowed in comments":                                      "carriage returns are not allowed in comments",
	"control characters are not allowed in comments":                                    "control characters are not allowed in comments",
	"invalid UTF-8 character in comment":                                                "invalid UTF-8 character in comment",
	"dates are expected to have the format YYYY-MM-DD":                                  "dates are expected to have the format YYYY-MM-DD",
	"impossible date":                                                                   "impossible date",
	"expected digit (0-9)":                                                              "expected digit (0-9)",
	"times are expected to have the format HH:MM[:SS[.NNNNNN]]":                         "times are expected to have the format HH:MM[:SS[.NNNNNN]]",
	"hour cannot be greater 23":                                                         "hour cannot be greater 23",
	"expecting colon between hours and minutes":                                         "expecting colon between hours and minutes",
	"minutes cannot be greater 59":                                                      "minutes cannot be greater 59",
	"incomplete seconds":                                                                "incomplete seconds",
	"seconds cannot be greater than 59":                                                 "seconds cannot be greater than 59",
	"need at least one digit after fraction point":                                      "need at least one digit after fraction point",
	"local datetimes are expected to have the format YYYY-MM-DDTHH:MM[:SS[.NNNNNNNNN]]": "local datetimes are expected to have the format YYYY-MM-DDTHH:MM[:SS[.NNNNNNNNN]]",
	"datetime separator is expected to be T or a space":                                 "datetime separator is expected to be T or a space",
	"date-time is missing timezone":                                                     "date-time is missing timezone",
	"invalid date-time timezone":                                                        "invalid date-time timezone",
	"invalid timezone offset character":                                                 "invalid timezone offset character",
	"expected a : separator":                                                            "expected a : separator",
	"invalid timezone offset hours":                                                     "invalid timezone offset hours",
	"invalid timezone offset minutes":                                                   "invalid timezone offset minutes",
	"extra bytes at the end of the timezone":                                            "extra bytes at the end of the timezone",
	"extra characters at the end of a local time":                                       "extra characters at the end of a local time",
	"extra characters at the end of a local date time":                                  "extra characters at the end of a local date time",
}

// decodeErrorKind returns the kind of problem a DecodeError message describes,
// as a fixed text. A message that is neither static nor a known form becomes
// "invalid TOML": a go-toml upgrade that changes a message costs its wording,
// not a leak.
func decodeErrorKind(msg string) string {
	if kind, ok := staticDecodeMessages[msg]; ok {
		return kind
	}
	for _, k := range decodeKinds {
		if m := k.re.FindStringSubmatchIndex(msg); m != nil {
			return string(k.re.ExpandString(nil, k.kind, msg, m))
		}
	}
	return "invalid TOML"
}
