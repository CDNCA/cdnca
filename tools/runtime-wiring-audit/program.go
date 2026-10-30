package main

import (
	"sort"
	"strings"
)

type functionNode struct {
	Key      string
	File     goFileFact
	Function functionFact
}

type programIndex struct {
	Nodes     map[string]functionNode
	Edges     map[string][]string
	Reverse   map[string][]string
	Reachable map[string]bool
	byPackage map[string]map[string][]string
}

func buildProgram(source sourceIndex) programIndex {
	program := programIndex{
		Nodes: map[string]functionNode{}, Edges: map[string][]string{}, Reverse: map[string][]string{},
		Reachable: map[string]bool{}, byPackage: map[string]map[string][]string{},
	}
	for _, file := range source.GoFiles {
		if file.Test {
			continue
		}
		for _, function := range file.Functions {
			key := functionKey(file.Path, function.Name)
			program.Nodes[key] = functionNode{Key: key, File: file, Function: function}
			if program.byPackage[file.PackageDir] == nil {
				program.byPackage[file.PackageDir] = map[string][]string{}
			}
			program.byPackage[file.PackageDir][function.Name] = append(program.byPackage[file.PackageDir][function.Name], key)
		}
	}
	for key, node := range program.Nodes {
		for _, call := range node.Function.Calls {
			program.Edges[key] = append(program.Edges[key], program.resolveCall(node, call)...)
		}
		for _, route := range node.File.Routes {
			if route.Symbol == node.Function.Name {
				program.Edges[key] = append(program.Edges[key], program.resolveName(node, route.Handler)...)
			}
		}
		program.Edges[key] = uniqueStrings(program.Edges[key])
		for _, target := range program.Edges[key] {
			program.Reverse[target] = append(program.Reverse[target], key)
		}
	}
	var roots []string
	for key, node := range program.Nodes {
		if !strings.HasPrefix(node.File.Path, "services/control-api/cmd/control-api/") {
			continue
		}
		if node.Function.Name == "main" || node.Function.Name == "init" {
			roots = append(roots, key)
		}
	}
	program.Reachable = program.reachableFrom(roots)
	return program
}

func functionKey(filePath, functionName string) string {
	return filePath + "#" + functionName
}

func (program programIndex) resolveCall(node functionNode, call callFact) []string {
	if call.PackageAlias != "" {
		packageDir := importedPackageDir(node.File, call.PackageAlias)
		return program.lookup(packageDir, callBase(call.Name))
	}
	if call.Receiver == "" {
		return program.lookup(node.File.PackageDir, call.Name)
	}
	return program.resolveName(node, call.Name)
}

func (program programIndex) resolveName(node functionNode, name string) []string {
	if name == "" || name == "receiver" || name == "handler" {
		return nil
	}
	if !strings.Contains(name, ".") {
		return program.lookup(node.File.PackageDir, name)
	}
	parts := strings.Split(name, ".")
	if _, ok := node.File.Imports[parts[0]]; ok {
		return program.lookup(importedPackageDir(node.File, parts[0]), parts[len(parts)-1])
	}
	packageDir, receiverType := program.receiverType(node, strings.Join(parts[:len(parts)-1], "."), map[string]bool{})
	if packageDir == "" || receiverType == "" {
		return nil
	}
	return program.lookup(packageDir, receiverType+"."+parts[len(parts)-1])
}

func (program programIndex) receiverType(node functionNode, receiver string, seen map[string]bool) (string, string) {
	parts := strings.Split(receiver, ".")
	if len(parts) == 0 {
		return "", ""
	}
	root := parts[0]
	packageDir, typeName := "", ""
	switch {
	case root == node.Function.ReceiverName:
		packageDir, typeName = typeLocation(node.File, node.Function.ReceiverType)
	case node.Function.Parameters[root] != "":
		packageDir, typeName = typeLocation(node.File, node.Function.Parameters[root])
	default:
		binding, ok := node.Function.Bindings[root]
		if !ok || seen[root] {
			return "", ""
		}
		seen[root] = true
		if binding.Identifier != "" && binding.Identifier != root {
			return program.receiverType(node, binding.Identifier+strings.TrimPrefix(receiver, root), seen)
		}
		if binding.Call {
			call := callFact{Name: binding.Name}
			if index := strings.Index(binding.Name, "."); index > 0 {
				prefix := binding.Name[:index]
				if _, ok := node.File.Imports[prefix]; ok {
					call.PackageAlias = prefix
				} else {
					return "", ""
				}
			}
			for _, target := range program.resolveCall(node, call) {
				targetNode := program.Nodes[target]
				if len(targetNode.Function.Results) > 0 {
					packageDir, typeName = typeLocation(targetNode.File, targetNode.Function.Results[0])
					break
				}
			}
		} else {
			packageDir, typeName = typeLocation(node.File, binding.Name)
		}
	}
	if packageDir == "" || typeName == "" {
		return "", ""
	}
	for _, field := range parts[1:] {
		fieldFile, fieldType := program.fieldType(packageDir, typeName, field)
		if fieldType == "" {
			return "", ""
		}
		packageDir, typeName = typeLocation(fieldFile, fieldType)
	}
	return packageDir, typeName
}

func (program programIndex) lookup(packageDir, name string) []string {
	if packageDir == "" || name == "" {
		return nil
	}
	return append([]string(nil), program.byPackage[packageDir][name]...)
}

func (program programIndex) fieldType(packageDir, typeName, field string) (goFileFact, string) {
	for _, node := range program.Nodes {
		if node.File.PackageDir != packageDir {
			continue
		}
		if fields := node.File.StructFields[typeName]; fields != nil && fields[field] != "" {
			return node.File, fields[field]
		}
	}
	return goFileFact{}, ""
}

func typeLocation(file goFileFact, raw string) (string, string) {
	value := strings.TrimSpace(raw)
	for strings.HasPrefix(value, "*") || strings.HasPrefix(value, "[]") {
		value = strings.TrimPrefix(value, "*")
		value = strings.TrimPrefix(value, "[]")
	}
	if value == "" || value == "interface" || value == "func" || strings.HasPrefix(value, "map[") {
		return "", ""
	}
	if index := strings.LastIndex(value, "."); index >= 0 {
		alias := value[:index]
		return importedPackageDir(file, alias), value[index+1:]
	}
	return file.PackageDir, value
}

func importedPackageDir(file goFileFact, alias string) string {
	importPath := file.Imports[alias]
	for _, marker := range []string{"/services/control-api/internal/", "/services/control-api/migrations"} {
		if index := strings.Index(importPath, marker); index >= 0 {
			return strings.TrimPrefix(importPath[index:], "/")
		}
	}
	return ""
}

func (program programIndex) reachableFrom(roots []string) map[string]bool {
	reachable := map[string]bool{}
	queue := append([]string(nil), roots...)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if reachable[current] || program.Nodes[current].Key == "" {
			continue
		}
		reachable[current] = true
		queue = append(queue, program.Edges[current]...)
	}
	return reachable
}

func (program programIndex) descendants(root string) map[string]bool {
	return program.reachableFrom([]string{root})
}

func (program programIndex) domainReachable(domain domainModel, routes []routeFact) map[string]bool {
	var roots []string
	for _, route := range routes {
		key := functionKey(route.File, route.Symbol)
		if program.Nodes[key].Key != "" {
			roots = append(roots, key)
			roots = append(roots, program.resolveName(program.Nodes[key], route.Handler)...)
		}
	}
	return program.reachableFrom(uniqueStrings(roots))
}

func (program programIndex) argumentRisk(node functionNode, expression expressionFact) (bool, bool) {
	return program.expressionRisk(node, expression, map[string]bool{})
}

func (program programIndex) expressionRisk(node functionNode, expression expressionFact, seen map[string]bool) (bool, bool) {
	if expression.Nil {
		return true, false
	}
	if expression.Placeholder || placeholderDependencyName(expression.Name) {
		return false, true
	}
	if expression.Identifier != "" {
		key := node.Key + ":binding:" + expression.Identifier
		if seen[key] {
			return false, false
		}
		seen[key] = true
		if binding, ok := node.Function.Bindings[expression.Identifier]; ok {
			return program.expressionRisk(node, binding, seen)
		}
	}
	if !expression.Call {
		return false, false
	}
	if !strings.Contains(expression.Name, ".") {
		if factory, ok := node.Function.Bindings[expression.Name]; ok && factory.Identifier != "" {
			return program.expressionRisk(node, expressionFact{Name: factory.Identifier, Call: true}, seen)
		}
	}
	call := callFact{Name: expression.Name}
	if index := strings.Index(expression.Name, "."); index > 0 {
		prefix := expression.Name[:index]
		if _, ok := node.File.Imports[prefix]; ok {
			call.PackageAlias = prefix
		} else {
			return false, false
		}
	}
	for _, target := range program.resolveCall(node, call) {
		if seen[target] {
			continue
		}
		seen[target] = true
		targetNode := program.Nodes[target]
		allNil := len(targetNode.Function.Returns) > 0
		placeholderRisk := false
		for _, returned := range targetNode.Function.Returns {
			nilRisk, returnedPlaceholder := program.expressionRisk(targetNode, returned, seen)
			allNil = allNil && nilRisk
			placeholderRisk = placeholderRisk || returnedPlaceholder
		}
		if allNil || placeholderRisk {
			return allNil, placeholderRisk
		}
	}
	return false, false
}

func (program programIndex) expressionOrigins(node functionNode, expression expressionFact, seen map[string]bool) []string {
	if expression.Identifier != "" {
		key := node.Key + ":origin:" + expression.Identifier
		if seen[key] {
			return nil
		}
		seen[key] = true
		if binding, ok := node.Function.Bindings[expression.Identifier]; ok {
			return program.expressionOrigins(node, binding, seen)
		}
	}
	if !expression.Call {
		return nil
	}
	if !strings.Contains(expression.Name, ".") {
		if factory, ok := node.Function.Bindings[expression.Name]; ok && factory.Identifier != "" {
			return program.expressionOrigins(node, expressionFact{Name: factory.Identifier, Call: true}, seen)
		}
	}
	call := callFact{Name: expression.Name}
	if index := strings.Index(expression.Name, "."); index > 0 {
		prefix := expression.Name[:index]
		if _, ok := node.File.Imports[prefix]; ok {
			call.PackageAlias = prefix
		} else {
			return nil
		}
	}
	var result []string
	if call.PackageAlias != "" {
		if packageDir := importedPackageDir(node.File, call.PackageAlias); packageDir != "" {
			result = append(result, packageDir)
		}
	}
	for _, target := range program.resolveCall(node, call) {
		result = append(result, program.functionOrigins(target, seen)...)
	}
	return uniqueStrings(result)
}

func (program programIndex) functionOrigins(key string, seen map[string]bool) []string {
	marker := key + ":function-origin"
	if seen[marker] {
		return nil
	}
	seen[marker] = true
	node := program.Nodes[key]
	var result []string
	for _, call := range node.Function.Calls {
		if call.PackageAlias != "" && runtimeConstructionCall(call.Name) {
			if packageDir := importedPackageDir(node.File, call.PackageAlias); packageDir != "" {
				result = append(result, packageDir)
			}
		}
	}
	for _, returned := range node.Function.Returns {
		result = append(result, program.expressionOrigins(node, returned, seen)...)
	}
	for _, target := range program.Edges[key] {
		result = append(result, program.functionOrigins(target, seen)...)
	}
	return uniqueStrings(result)
}

func (program programIndex) asyncCallOrigins(node functionNode, call callFact) []string {
	var result []string
	if call.Receiver != "" {
		root := strings.Split(call.Receiver, ".")[0]
		result = append(result, program.expressionOrigins(node, expressionFact{Identifier: root}, map[string]bool{})...)
	}
	for _, argument := range call.Arguments {
		result = append(result, program.expressionOrigins(node, argument, map[string]bool{})...)
	}
	return uniqueStrings(result)
}

func (program programIndex) callRunsWorker(node functionNode, call callFact) bool {
	base := strings.ToLower(callBase(call.Name))
	if base == "run" || base == "start" || base == "serve" || base == "consume" {
		return true
	}
	for _, target := range program.resolveCall(node, call) {
		for descendant := range program.descendants(target) {
			for _, nested := range program.Nodes[descendant].Function.Calls {
				nestedBase := strings.ToLower(callBase(nested.Name))
				if nestedBase == "run" || nestedBase == "start" || nestedBase == "serve" || nestedBase == "consume" {
					return true
				}
			}
		}
	}
	return false
}

func functionHasControlledLifecycle(function functionFact) bool {
	var add, done, wait, groupGo, stop, contextBound bool
	for _, call := range function.Calls {
		base := strings.ToLower(callBase(call.Name))
		add = add || base == "add"
		done = done || base == "done"
		wait = wait || base == "wait"
		groupGo = groupGo || base == "go"
		stop = stop || base == "cancel" || base == "close" || base == "shutdown" || base == "stop"
		for _, identifier := range call.Identifiers {
			contextBound = contextBound || identifier == "ctx" || strings.Contains(strings.ToLower(identifier), "context")
		}
	}
	return contextBound && ((add && done && wait) || (groupGo && wait)) && stop
}

func sortedFunctionKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
