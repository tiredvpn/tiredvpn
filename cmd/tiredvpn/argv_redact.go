package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// This file has no build tag on purpose: everything the JNI entry point prints
// about its argv is built here, so the Linux CI tests it. jni_android.go only
// passes the result to logMessage.

// redactedValue replaces a sensitive argv value in logs. The app's Kotlin log
// (NativeArgs.kt) uses the same marker.
const redactedValue = "***"

// sensitiveArgNames are the argv flags whose value must never reach a log or
// an error. -secret authenticates the client. Keep this in step with
// SECRET_FLAGS in the app's NativeArgs.kt.
var sensitiveArgNames = []string{"secret"}

// sensitiveArg reports whether tok is a sensitive flag and, if so, whether its
// value is inline (-flag=value). One or two leading dashes are accepted, as
// the Go flag package does on desktop.
func sensitiveArg(tok string) (inline, ok bool) {
	rest, dashed := strings.CutPrefix(tok, "-")
	if !dashed {
		return false, false
	}
	rest = strings.TrimPrefix(rest, "-")
	name, _, inline := strings.Cut(rest, "=")
	return inline, slices.Contains(sensitiveArgNames, name)
}

// redactArgs returns a copy of args fit for a log: the value of a sensitive
// flag, whether the next token or the part after "=", becomes redactedValue.
// The flag names and every other token stay visible.
//
// Detection runs over the original args and never skips a token, so the
// value that follows a sensitive flag is checked as a flag itself: in
// "-secret -secret v" both values are hidden.
//
// The copy is for printing only. The parser keeps reading the original args.
func redactArgs(args []string) []string {
	out := slices.Clone(args)
	for i, tok := range args {
		inline, ok := sensitiveArg(tok)
		switch {
		case !ok:
		case inline:
			flag, _, _ := strings.Cut(tok, "=")
			out[i] = flag + "=" + redactedValue
		case i+1 < len(args):
			out[i+1] = redactedValue
		}
	}
	return out
}

// sensitiveArgValues returns the raw values redactArgs would hide.
func sensitiveArgValues(args []string) []string {
	var vals []string
	for i, tok := range args {
		inline, ok := sensitiveArg(tok)
		switch {
		case !ok:
		case inline:
			_, v, _ := strings.Cut(tok, "=")
			vals = append(vals, v)
		case i+1 < len(args):
			vals = append(vals, args[i+1])
		}
	}
	return vals
}

// jniStartLogLine is the line the JNI startClient logs before it starts the
// client. It goes to logcat, to the app's log file and to its log screen.
func jniStartLogLine(args []string) string {
	return fmt.Sprintf("Starting client with %d args: %s", len(args), strings.Join(redactArgs(args), " "))
}

// redactArgError hides the sensitive argv values inside err's text. It is the
// backstop for errors the parser does not format itself: a sensitive token
// consumed as another flag's value ("-shaper -secret=v", "-config -secret=v")
// comes back inside the shaper or config error. Both the raw and the %q-escaped
// spelling of a value are replaced. err is returned untouched when nothing
// matched, so wrapping survives in the common case.
func redactArgError(err error, args []string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, v := range sensitiveArgValues(args) {
		if v == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, v, redactedValue)
		if q := strconv.Quote(v); q[1:len(q)-1] != v {
			msg = strings.ReplaceAll(msg, q[1:len(q)-1], redactedValue)
		}
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

// strconvReason drops the input that a strconv error repeats ("parsing \"v\":
// invalid syntax" becomes "invalid syntax"). The parser prints the value
// itself, already redacted.
func strconvReason(err error) error {
	if ne, ok := errors.AsType[*strconv.NumError](err); ok {
		return ne.Err
	}
	return err
}
