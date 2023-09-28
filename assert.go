package main

import (
	"reflect"
	"testing"
)

func AssertEquals[A any](t *testing.T, value A, expected A) {
	if !reflect.DeepEqual(value, expected) {
		t.Errorf("Value %#v does not match %#v.", value, expected)
	}
}
