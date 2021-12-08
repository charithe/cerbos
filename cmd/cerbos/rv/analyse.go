// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rv

import (
	"context"
	"fmt"
	"strings"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/index"
)

type RoleInfo struct {
	Name            string                   `json:"name"`
	ResourceActions map[string]*ResourceInfo `json:"resourceActions"`
}

func (ri *RoleInfo) addResourceAction(resource, version string, action *ActionInfo) {
	resInfo, ok := ri.ResourceActions[resource]
	if !ok {
		resInfo = &ResourceInfo{Name: resource, VersionActions: make(map[string]map[string]*ActionInfo)}
		ri.ResourceActions[resource] = resInfo
	}

	resInfo.addVersionAction(version, action)
}

type ResourceInfo struct {
	Name           string                            `json:"name"`
	VersionActions map[string]map[string]*ActionInfo `json:"versionActions"`
}

func (ri *ResourceInfo) addVersionAction(version string, action *ActionInfo) {
	actionMap, ok := ri.VersionActions[version]
	if !ok {
		actionMap = make(map[string]*ActionInfo)
		ri.VersionActions[version] = actionMap
	}

	if _, ok := actionMap[action.Name]; ok {
		panic(fmt.Errorf("action %q already exists for version %q", action, version))
	}

	actionMap[action.Name] = action
}

type ActionInfo struct {
	Name            string `json:"name"`
	PolicyCond      string `json:"policyCond"`
	DerivedRole     string `json:"derivedRole"`
	DerivedRoleCond string `json:"derivedRoleCond"`
}

type derivedRoleMapping struct {
	role      string
	condition string
}

type analyser struct {
	idx   index.Index
	roles map[string]*RoleInfo
}

func analyse(ctx context.Context, idx index.Index) (map[string]*RoleInfo, error) {
	a := analyser{idx: idx, roles: make(map[string]*RoleInfo)}
	return a.analyse(ctx)
}

func (a *analyser) analyse(ctx context.Context) (map[string]*RoleInfo, error) {
	var errs compile.ErrorList

	for unit := range a.idx.GetAllCompilationUnits(ctx) {
		cp, err := compile.Compile(unit)
		if err != nil {
			errs.Add(err)
			continue
		}

		if rp := cp.GetResourcePolicy(); rp != nil {
			a.process(rp)
		}
	}

	return a.roles, errs.ErrOrNil()
}

func (a *analyser) process(rp *runtimev1.RunnableResourcePolicySet) {
	for _, p := range rp.Policies {
		drMapping := mkDerivedRolesMap(p)
		a.populateFromPolicyRules(rp.Meta, p, drMapping)
	}
}

func mkDerivedRolesMap(p *runtimev1.RunnableResourcePolicySet_Policy) map[string]*derivedRoleMapping {
	drMapping := make(map[string]*derivedRoleMapping)
	for _, dr := range p.DerivedRoles {
		cond := condToStr(dr.Condition)

		for r := range dr.ParentRoles {
			drMapping[dr.Name] = &derivedRoleMapping{role: r, condition: cond}
		}
	}

	return drMapping
}

func (a *analyser) populateFromPolicyRules(parent *runtimev1.RunnableResourcePolicySet_Metadata, p *runtimev1.RunnableResourcePolicySet_Policy, drMapping map[string]*derivedRoleMapping) {
	for _, rule := range p.Rules {
		cond := condToStr(rule.Condition)

		for r := range rule.Roles {
			a.initRoleInfo(r)
			roleInfo := a.roles[r]
			for action := range rule.Actions {
				roleInfo.addResourceAction(parent.Resource, parent.Version, &ActionInfo{
					Name:       action,
					PolicyCond: cond,
				})
			}
		}

		for dr := range rule.DerivedRoles {
			drm := drMapping[dr]
			a.initRoleInfo(drm.role)
			roleInfo := a.roles[drm.role]
			for action := range rule.Actions {
				roleInfo.addResourceAction(parent.Resource, parent.Version, &ActionInfo{
					Name:            action,
					PolicyCond:      cond,
					DerivedRole:     dr,
					DerivedRoleCond: drm.condition,
				})
			}
		}
	}
}

func (a *analyser) initRoleInfo(r string) {
	if _, ok := a.roles[r]; !ok {
		a.roles[r] = &RoleInfo{Name: r, ResourceActions: make(map[string]*ResourceInfo)}
	}
}

func condToStr(cond *runtimev1.Condition) string {
	sb := new(strings.Builder)
	doCondToStr(sb, cond)
	return sb.String()
}

func doCondToStr(sb *strings.Builder, cond *runtimev1.Condition) {
	if cond == nil {
		return
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		sb.WriteString(t.Expr.GetOriginal())
	case *runtimev1.Condition_All:
		condListToStr(sb, "allOf", t.All.Expr)
	case *runtimev1.Condition_Any:
		condListToStr(sb, "anyOf", t.Any.Expr)
	case *runtimev1.Condition_None:
		condListToStr(sb, "noneOf", t.None.Expr)
	default:
		panic(fmt.Errorf("unhandled condition type %T", t))
	}
}

func condListToStr(sb *strings.Builder, op string, exprs []*runtimev1.Condition) {
	sb.WriteString(" ")
	sb.WriteString(op)
	sb.WriteString("(")

	n := len(exprs) - 1
	for i, expr := range exprs {
		doCondToStr(sb, expr)
		if i < n {
			sb.WriteString(", ")
		}
	}
	sb.WriteString(") ")
}
