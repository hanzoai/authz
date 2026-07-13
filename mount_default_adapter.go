// Copyright 2026 Hanzo AI, Inc. Licensed under the Apache License, Version 2.0.

package authz

import (
	"strings"
	"sync"

	"github.com/hanzoai/authz/model"
)

// defaultAdapter is a minimal in-memory persist.Adapter that backs the
// `Mount()`-supplied default enforcer. It exists at root so mount.go does
// not import the `persist/string-adapter` subpackage (avoiding an import
// cycle through that subpackage's integration tests).
//
// Production deployments swap this for a persistent adapter (file, DB,
// etcd, etc.) by injecting it at enforcer construction. See
// `~/work/hanzo/authz/persist/` for shipped adapter implementations.
type defaultAdapter struct {
	mu    sync.Mutex
	lines []string
}

func newDefaultAdapter() *defaultAdapter { return &defaultAdapter{} }

// LoadPolicy reads the in-memory lines into the provided model.
func (a *defaultAdapter) LoadPolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, line := range a.lines {
		if line == "" {
			continue
		}
		loadPolicyLine(line, m)
	}
	return nil
}

// SavePolicy snapshots the model's policy + grouping rules into memory.
func (a *defaultAdapter) SavePolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = a.lines[:0]
	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			a.lines = append(a.lines, ptype+", "+strings.Join(rule, ", "))
		}
	}
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			a.lines = append(a.lines, ptype+", "+strings.Join(rule, ", "))
		}
	}
	return nil
}

// AddPolicy appends a rule to in-memory storage.
func (a *defaultAdapter) AddPolicy(sec, ptype string, rule []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, ptype+", "+strings.Join(rule, ", "))
	return nil
}

// RemovePolicy removes the matching rule.
func (a *defaultAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	target := ptype + ", " + strings.Join(rule, ", ")
	out := a.lines[:0]
	for _, line := range a.lines {
		if line != target {
			out = append(out, line)
		}
	}
	a.lines = out
	return nil
}

// RemoveFilteredPolicy is a no-op placeholder satisfying the persist.Adapter contract.
func (a *defaultAdapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

func loadPolicyLine(line string, m model.Model) {
	parts := strings.Split(line, ", ")
	if len(parts) < 2 {
		return
	}
	key := parts[0]
	sec := key[:1]
	if ast, ok := m[sec][key]; ok {
		ast.Policy = append(ast.Policy, parts[1:])
		ast.PolicyMap[strings.Join(parts[1:], ",")] = len(ast.Policy) - 1
	}
}
