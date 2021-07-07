package qtls

import (
	"reflect"
	"unsafe"
)

func toConnectionState(c connectionState) ConnectionState {
	return *(*ConnectionState)(unsafe.Pointer(&c))
}

func toClientSessionState(s *clientSessionState) *ClientSessionState {
	return (*ClientSessionState)(unsafe.Pointer(s))
}

func fromClientSessionState(s *ClientSessionState) *clientSessionState {
	return (*clientSessionState)(unsafe.Pointer(s))
}

func structsEqual(a, b interface{}) bool {
	return compare(reflect.ValueOf(a), reflect.ValueOf(b))
}

func compare(a, b reflect.Value) bool {
	sa := a.Elem()
	sb := b.Elem()
	if sa.NumField() != sb.NumField() {
		return false
	}
	for i := 0; i < sa.NumField(); i++ {
		fa := sa.Type().Field(i)
		fb := sb.Type().Field(i)
		if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name || fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset || !reflect.DeepEqual(fa.Type, fb.Type) {
			if fa.Type.Kind() != fb.Type.Kind() {
				return false
			}
			if fa.Type.Kind() == reflect.Slice {
				if !compareStruct(fa.Type.Elem(), fb.Type.Elem()) {
					return false
				}
				continue
			}
			return false
		}
	}
	return true
}

func compareStruct(a, b reflect.Type) bool {
	if a.NumField() != b.NumField() {
		return false
	}
	for i := 0; i < a.NumField(); i++ {
		fa := a.Field(i)
		fb := b.Field(i)
		if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name || fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset || !reflect.DeepEqual(fa.Type, fb.Type) {
			return false
		}
	}
	return true
}
