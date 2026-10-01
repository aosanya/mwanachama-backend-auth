package mwanachamaauth

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/aosanya/mwanachama-backend-shared/spec"
)

const (
	RoleDevice            = roleDevice
	RoleChallenge         = roleChallenge
	RolePhoneAttempt      = rolePhoneAttempt
	RolePhoneBinding      = rolePhoneBinding
	RoleCredential        = roleCredential
	RoleCredentialAttempt = roleCredentialAttempt
	RoleVerification      = roleVerification
	RoleSalt              = roleSalt
)

func Check(s *spec.Spec, role string, v any) error {
	o, ok := s.ByRole(role)
	if !ok {
		return fmt.Errorf("check: this domain fills no object for the role %q", role)
	}
	return check(o, v)
}

func check(o spec.Object, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("check %s: want a struct, got %T", o.Name, v)
	}

	byColumn := map[string]reflect.Value{}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).PkgPath != "" {
			continue
		}
		byColumn[columnName(rt.Field(i).Name)] = rv.Field(i)
	}

	for _, f := range o.Fields {
		fv, ok := byColumn[f.Name]
		if !ok || fv.Kind() != reflect.String {
			continue
		}
		value := fv.String()

		if f.Required && strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s: %s is required", o.Name, f.Name)
		}
		if f.Type == spec.TypeEnum && value != "" && !declares(f.Values, value) {
			return fmt.Errorf("%s: %s is %q, which is not one of %s",
				o.Name, f.Name, value, strings.Join(f.Values, ", "))
		}
		if f.Matches != "" && value != "" {
			ok, known := patterns[f.Matches]
			if !known {
				return fmt.Errorf("%s: %s names the pattern %q, which this module does not supply",
					o.Name, f.Name, f.Matches)
			}
			if !ok(value) {
				return fmt.Errorf("%s: %s does not match %s", o.Name, f.Name, f.Matches)
			}
		}
	}
	return nil
}

func declares(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
