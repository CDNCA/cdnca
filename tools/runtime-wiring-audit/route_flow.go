package main

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/token"
	"go/types"
	"sync"
)

const noFlowNode = -1

type routeFlowNode struct {
	Statement ast.Stmt
	Next      []int
}

type routeFlow struct {
	Nodes             []routeFlowNode
	Entry             int
	Info              *types.Info
	Imports           map[string]string
	Body              *ast.BlockStmt
	labels            map[string]int
	parent            *routeFlow
	call              token.Pos
	closures          localClosureBindings
	inputStates       map[types.Object]int
	schedule          closureSchedule
	completionSignals []completionSignal
	functionBodies    map[*types.Func]*ast.BlockStmt
}

var routeFunctionBodies sync.Map

type completionSignal struct {
	position token.Pos
	wait     token.Pos
	deferred bool
}

type closureSchedule uint8

const (
	closureImmediate closureSchedule = iota
	closureDeferred
	closureGoroutine
	closureGoroutineWaited
	closureUnproven
)

type routeFlowTargets struct {
	breakNode       int
	continueNode    int
	fallthroughNode int
}

func routeTypeInfo(fileSet *token.FileSet, file *ast.File, packagePath string) *types.Info {
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	config := types.Config{Importer: importer.Default(), Error: func(error) {}}
	_, _ = config.Check(packagePath, fileSet, []*ast.File{file}, info)
	bodies := map[*types.Func]*ast.BlockStmt{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		object, ok := info.Defs[function.Name].(*types.Func)
		if ok {
			bodies[object] = function.Body
		}
	}
	routeFunctionBodies.Store(info, bodies)
	return info
}

func newRouteFlow(body *ast.BlockStmt, info *types.Info, imports map[string]string) *routeFlow {
	return newNestedRouteFlow(body, info, imports, nil, token.NoPos)
}

func newNestedRouteFlow(body *ast.BlockStmt, info *types.Info, imports map[string]string, parent *routeFlow, call token.Pos) *routeFlow {
	flow := &routeFlow{Info: info, Imports: imports, Body: body, labels: map[string]int{}, parent: parent, call: call}
	if parent != nil {
		flow.functionBodies = parent.functionBodies
	} else if stored, ok := routeFunctionBodies.Load(info); ok {
		flow.functionBodies, _ = stored.(map[*types.Func]*ast.BlockStmt)
	}
	exit := flow.addNode(nil)
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		label, ok := node.(*ast.LabeledStmt)
		if ok {
			flow.labels[label.Label.Name] = flow.addNode(label)
		}
		return true
	})
	targets := routeFlowTargets{breakNode: noFlowNode, continueNode: noFlowNode, fallthroughNode: noFlowNode}
	first := flow.buildBlock(body.List, exit, targets)
	flow.Entry = flow.addNode(nil)
	flow.Nodes[flow.Entry].Next = []int{first}
	flow.closures = localClosures(body, info, flow)
	return flow
}

func (flow *routeFlow) addNode(statement ast.Stmt) int {
	flow.Nodes = append(flow.Nodes, routeFlowNode{Statement: statement})
	return len(flow.Nodes) - 1
}

func (flow *routeFlow) buildBlock(statements []ast.Stmt, follow int, targets routeFlowTargets) int {
	next := follow
	for index := len(statements) - 1; index >= 0; index-- {
		next = flow.buildStatement(statements[index], next, targets)
	}
	return next
}

func (flow *routeFlow) buildStatement(statement ast.Stmt, follow int, targets routeFlowTargets) int {
	switch typed := statement.(type) {
	case *ast.BlockStmt:
		return flow.buildBlock(typed.List, follow, targets)
	case *ast.LabeledStmt:
		labelNode := flow.labels[typed.Label.Name]
		flow.Nodes[labelNode].Next = []int{flow.buildStatement(typed.Stmt, follow, targets)}
		return labelNode
	case *ast.BranchStmt:
		node := flow.addNode(statement)
		target := noFlowNode
		switch typed.Tok {
		case token.GOTO:
			if typed.Label != nil {
				target = flow.labels[typed.Label.Name]
			}
		case token.BREAK:
			target = targets.breakNode
		case token.CONTINUE:
			target = targets.continueNode
		case token.FALLTHROUGH:
			target = targets.fallthroughNode
		}
		if target != noFlowNode {
			flow.Nodes[node].Next = []int{target}
		}
		return node
	case *ast.ReturnStmt:
		return flow.addNode(statement)
	case *ast.IfStmt:
		condition := flow.addNode(statement)
		thenEntry := flow.buildBlock(typed.Body.List, follow, targets)
		elseEntry := follow
		if typed.Else != nil {
			elseEntry = flow.buildStatement(typed.Else, follow, targets)
		}
		switch flow.constantBool(typed.Cond) {
		case 1:
			flow.Nodes[condition].Next = []int{thenEntry}
		case 0:
			flow.Nodes[condition].Next = []int{elseEntry}
		default:
			flow.Nodes[condition].Next = []int{thenEntry, elseEntry}
		}
		if typed.Init != nil {
			return flow.buildStatement(typed.Init, condition, targets)
		}
		return condition
	case *ast.ForStmt:
		condition := flow.addNode(statement)
		continueNode := condition
		if typed.Post != nil {
			continueNode = flow.buildStatement(typed.Post, condition, targets)
		}
		loopTargets := targets
		loopTargets.breakNode = follow
		loopTargets.continueNode = continueNode
		bodyEntry := flow.buildBlock(typed.Body.List, continueNode, loopTargets)
		switch flow.constantBool(typed.Cond) {
		case 1:
			flow.Nodes[condition].Next = []int{bodyEntry}
		case 0:
			flow.Nodes[condition].Next = []int{follow}
		default:
			flow.Nodes[condition].Next = []int{bodyEntry, follow}
		}
		if typed.Init != nil {
			return flow.buildStatement(typed.Init, condition, targets)
		}
		return condition
	case *ast.RangeStmt:
		loop := flow.addNode(statement)
		loopTargets := targets
		loopTargets.breakNode = follow
		loopTargets.continueNode = loop
		bodyEntry := flow.buildBlock(typed.Body.List, loop, loopTargets)
		flow.Nodes[loop].Next = []int{bodyEntry, follow}
		return loop
	case *ast.SwitchStmt:
		dispatch := flow.addNode(statement)
		entries := flow.buildClauses(typed.Body.List, follow, targets)
		flow.Nodes[dispatch].Next = entries
		if target, known := flow.constantSwitchTarget(typed, entries, follow); known {
			flow.Nodes[dispatch].Next = []int{target}
		}
		if typed.Init != nil {
			return flow.buildStatement(typed.Init, dispatch, targets)
		}
		return dispatch
	case *ast.TypeSwitchStmt:
		dispatch := flow.addNode(statement)
		flow.Nodes[dispatch].Next = flow.buildClauses(typed.Body.List, follow, targets)
		entry := dispatch
		if typed.Assign != nil {
			entry = flow.buildStatement(typed.Assign, entry, targets)
		}
		if typed.Init != nil {
			entry = flow.buildStatement(typed.Init, entry, targets)
		}
		return entry
	case *ast.SelectStmt:
		dispatch := flow.addNode(statement)
		if len(typed.Body.List) == 0 {
			return dispatch
		}
		flow.Nodes[dispatch].Next = flow.buildClauses(typed.Body.List, follow, targets)
		return dispatch
	case *ast.ExprStmt:
		node := flow.addNode(statement)
		if !flow.terminates(typed.X) {
			flow.Nodes[node].Next = []int{follow}
		}
		return node
	default:
		node := flow.addNode(statement)
		flow.Nodes[node].Next = []int{follow}
		return node
	}
}

func (flow *routeFlow) constantSwitchTarget(statement *ast.SwitchStmt, entries []int, follow int) (int, bool) {
	tag := constant.MakeBool(true)
	if statement.Tag != nil {
		value, ok := flow.Info.Types[statement.Tag]
		if !ok || value.Value == nil {
			return noFlowNode, false
		}
		tag = value.Value
	}
	defaultTarget := follow
	for index, rawClause := range statement.Body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok || index >= len(entries) {
			return noFlowNode, false
		}
		if len(clause.List) == 0 {
			defaultTarget = entries[index]
			continue
		}
		for _, expression := range clause.List {
			value, ok := flow.Info.Types[expression]
			if !ok || value.Value == nil {
				return noFlowNode, false
			}
			if constant.Compare(value.Value, token.EQL, tag) {
				return entries[index], true
			}
		}
	}
	return defaultTarget, true
}

func (flow *routeFlow) terminates(expression ast.Expr) bool {
	call, ok := unwrapParen(expression).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch function := unwrapParen(call.Fun).(type) {
	case *ast.Ident:
		builtin, ok := flow.Info.Uses[function].(*types.Builtin)
		return ok && builtin.Name() == "panic"
	case *ast.SelectorExpr:
		identifier, ok := unwrapParen(function.X).(*ast.Ident)
		return ok && ((function.Sel.Name == "Exit" && flow.Imports[identifier.Name] == "os") ||
			(function.Sel.Name == "Goexit" && flow.Imports[identifier.Name] == "runtime"))
	default:
		return false
	}
}

func (flow *routeFlow) buildClauses(statements []ast.Stmt, follow int, targets routeFlowTargets) []int {
	entries := make([]int, len(statements))
	nextClause := follow
	for index := len(statements) - 1; index >= 0; index-- {
		clauseTargets := targets
		clauseTargets.breakNode = follow
		clauseTargets.fallthroughNode = nextClause
		var body []ast.Stmt
		var communication ast.Stmt
		switch clause := statements[index].(type) {
		case *ast.CaseClause:
			body = clause.Body
		case *ast.CommClause:
			body = clause.Body
			communication = clause.Comm
		}
		entry := flow.buildBlock(body, follow, clauseTargets)
		if communication != nil {
			entry = flow.buildStatement(communication, entry, targets)
		}
		entries[index] = entry
		nextClause = entry
	}
	return append(entries, follow)
}

func (flow *routeFlow) constantBool(expression ast.Expr) int {
	if expression == nil {
		return 1
	}
	if value, ok := flow.Info.Types[expression]; ok && value.Value != nil && value.Value.Kind() == constant.Bool {
		if constant.BoolVal(value.Value) {
			return 1
		}
		return 0
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		if identifier.Name == "true" {
			return 1
		}
		if identifier.Name == "false" {
			return 0
		}
	}
	return -1
}

func (flow *routeFlow) provesServeMux(call *ast.CallExpr, fact callFact) bool {
	node := flow.nodeAt(call.Pos())
	if node == noFlowNode || !flow.nodeReachable(node) {
		return false
	}
	if fact.PackageAlias != "" {
		return fact.Receiver == fact.PackageAlias && flow.Imports[fact.PackageAlias] == "net/http"
	}
	selector, ok := unwrapParen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	root, fields, ok := receiverPath(selector.X)
	if !ok {
		return false
	}
	if flow.Imports[root] == "net/http" && len(fields) == 1 && fields[0] == "DefaultServeMux" {
		return true
	}
	object := expressionRootObject(selector.X, flow.Info)
	typedInput := flow.typedServeMuxInput(object, selector.X)
	states := flow.receiverStates(root, fields, object, typedInput)
	return states[node] == receiverValid
}

func (flow *routeFlow) allPathsReach(startPosition, targetPosition token.Pos) bool {
	start := flow.nodeAt(startPosition)
	target := flow.nodeAt(targetPosition)
	if start == noFlowNode || target == noFlowNode || !flow.nodeReachable(start) || !flow.nodeReachable(target) {
		return false
	}
	return flow.allPathsReachNodes(start, target)
}

func (flow *routeFlow) allEntryPathsReach(targetPosition token.Pos) bool {
	target := flow.nodeAt(targetPosition)
	if target == noFlowNode || !flow.nodeReachable(target) {
		return false
	}
	return flow.allPathsReachNodes(flow.Entry, target)
}

func (flow *routeFlow) allPathsReachNodes(start, target int) bool {
	visiting := map[int]bool{}
	memo := map[int]bool{}
	known := map[int]bool{}
	var reaches func(int) bool
	reaches = func(node int) bool {
		if node == target {
			return true
		}
		if known[node] {
			return memo[node]
		}
		if visiting[node] || len(flow.Nodes[node].Next) == 0 {
			return false
		}
		visiting[node] = true
		result := true
		for _, next := range flow.Nodes[node].Next {
			result = result && reaches(next)
		}
		delete(visiting, node)
		known[node] = true
		memo[node] = result
		return result
	}
	return reaches(start)
}

func (flow *routeFlow) deferredExecutionProven(position token.Pos) bool {
	start := flow.nodeAt(position)
	if start == noFlowNode || !flow.nodeReachable(start) {
		return false
	}
	visiting := map[int]bool{}
	memo := map[int]bool{}
	known := map[int]bool{}
	var terminates func(int) bool
	terminates = func(node int) bool {
		if known[node] {
			return memo[node]
		}
		if visiting[node] {
			return false
		}
		statement := flow.Nodes[node].Statement
		if statement == nil {
			return node == 0
		}
		nonBlockingCommunication := flow.nonBlockingSelectCommunication(statement)
		topLevelReceive := selectCommunicationReceive(statement)
		for _, receive := range statementReceives(statement) {
			if nonBlockingCommunication && receive == topLevelReceive {
				continue
			}
			if !flow.provenCompletionReceive(receive.Pos()) {
				return false
			}
		}
		if expression, ok := statement.(*ast.ExprStmt); ok && flow.terminates(expression.X) {
			return flow.terminationExecutesDefers(expression.X, map[*types.Func]bool{}, 0)
		}
		if flow.hasUnprovenReturningCall(statement, position) {
			return false
		}
		if send, ok := statement.(*ast.SendStmt); ok && send != nil && !nonBlockingCommunication {
			return false
		}
		if _, ok := statement.(*ast.ReturnStmt); ok {
			return true
		}
		if selection, ok := statement.(*ast.SelectStmt); ok && !selectHasDefault(selection) {
			return false
		}
		if len(flow.Nodes[node].Next) == 0 {
			return false
		}
		visiting[node] = true
		result := true
		for _, next := range flow.Nodes[node].Next {
			result = result && terminates(next)
		}
		delete(visiting, node)
		known[node] = true
		memo[node] = result
		return result
	}
	return terminates(start)
}

func statementReceives(statement ast.Stmt) []*ast.UnaryExpr {
	var receives []*ast.UnaryExpr
	ast.Inspect(statement, func(node ast.Node) bool {
		if nested, ok := node.(ast.Stmt); ok && nested != statement {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		receive, ok := node.(*ast.UnaryExpr)
		if ok && receive.Op == token.ARROW {
			receives = append(receives, receive)
		}
		return true
	})
	return receives
}

func selectCommunicationReceive(statement ast.Stmt) *ast.UnaryExpr {
	var expression ast.Expr
	switch typed := statement.(type) {
	case *ast.ExprStmt:
		expression = typed.X
	case *ast.AssignStmt:
		if len(typed.Rhs) == 1 {
			expression = typed.Rhs[0]
		}
	}
	receive, _ := unwrapParen(expression).(*ast.UnaryExpr)
	if receive != nil && receive.Op == token.ARROW {
		return receive
	}
	return nil
}

func (flow *routeFlow) provenCompletionReceive(position token.Pos) bool {
	proven := false
	ast.Inspect(flow.Body, func(node ast.Node) bool {
		if proven {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statement, ok := node.(*ast.GoStmt)
		if !ok || statement.Call == nil {
			return true
		}
		for _, signal := range goroutineCompletionSignals(statement.Call, flow) {
			if signal.wait == position {
				proven = true
				return false
			}
		}
		return true
	})
	return proven
}

func (flow *routeFlow) terminationExecutesDefers(expression ast.Expr, visiting map[*types.Func]bool, depth int) bool {
	call, ok := unwrapParen(expression).(*ast.CallExpr)
	if !ok {
		return false
	}
	if !flow.expressionsCompleteOrRunDefers(call.Args, visiting, depth) {
		return false
	}
	switch function := unwrapParen(call.Fun).(type) {
	case *ast.Ident:
		builtin, ok := flow.Info.Uses[function].(*types.Builtin)
		return ok && builtin.Name() == "panic"
	case *ast.SelectorExpr:
		identifier, ok := unwrapParen(function.X).(*ast.Ident)
		return ok && function.Sel.Name == "Goexit" && flow.Imports[identifier.Name] == "runtime"
	default:
		return false
	}
}

func (flow *routeFlow) hasUnprovenReturningCall(statement ast.Stmt, scheduled token.Pos) bool {
	if launched, ok := statement.(*ast.GoStmt); ok {
		return launched.Call == nil || !flow.goInvocationEvaluationProven(launched.Call, map[*types.Func]bool{}, 0)
	}
	unknown := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if unknown {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if ok && call.Pos() != scheduled && !flow.callReturnProven(call) {
			unknown = true
			return false
		}
		return true
	})
	return unknown
}

func (flow *routeFlow) callReturnProven(call *ast.CallExpr) bool {
	return flow.callCompletesOrRunsDefers(call, map[*types.Func]bool{}, 0)
}

const maxSimpleHelperDepth = 16

func (flow *routeFlow) callCompletesOrRunsDefers(call *ast.CallExpr, visiting map[*types.Func]bool, depth int) bool {
	if !flow.expressionEvaluationProven(call.Fun, visiting, depth) ||
		!flow.expressionsCompleteOrRunDefers(call.Args, visiting, depth) {
		return false
	}
	function := unwrapParen(call.Fun)
	switch typed := function.(type) {
	case *ast.FuncLit:
		return flow.simpleBodyProven(typed.Body, visiting, depth)
	case *ast.Ident:
		switch object := objectForIdentifier(typed, flow.Info).(type) {
		case *types.Builtin, *types.TypeName:
			return true
		case *types.Func:
			return flow.simpleFunctionProven(object, visiting, depth)
		}
		if literals := flow.possibleInvokedClosures(call); len(literals) > 0 {
			if depth >= maxSimpleHelperDepth {
				return false
			}
			for _, literal := range literals {
				if !flow.simpleBodyProven(literal.Body, visiting, depth+1) {
					return false
				}
			}
			return true
		}
		if function, receiver, ok := flow.boundMethodValue(typed, call.Pos()); ok {
			if knownServeMuxRegistration(function, receiver) {
				return true
			}
			return flow.simpleFunctionProven(function, visiting, depth)
		}
	case *ast.SelectorExpr:
		if identifier, ok := unwrapParen(typed.X).(*ast.Ident); ok && typed.Sel.Name == "NewServeMux" &&
			flow.Imports[identifier.Name] == "net/http" {
			return true
		}
		switch object := flow.Info.Uses[typed.Sel].(type) {
		case *types.TypeName:
			return true
		case *types.Func:
			if flow.simpleFunctionProven(object, visiting, depth) {
				return true
			}
		}
		selection := flow.Info.Selections[typed]
		if selection == nil {
			return false
		}
		if function, ok := selection.Obj().(*types.Func); ok && flow.simpleFunctionProven(function, visiting, depth) {
			return true
		}
		return (typed.Sel.Name == "Handle" || typed.Sel.Name == "HandleFunc") && serveMuxPointer(flow.Info.TypeOf(typed.X))
	}
	return false
}

func (flow *routeFlow) goInvocationEvaluationProven(call *ast.CallExpr, visiting map[*types.Func]bool, depth int) bool {
	return flow.expressionEvaluationProven(call.Fun, visiting, depth) &&
		flow.expressionsCompleteOrRunDefers(call.Args, visiting, depth)
}

func (flow *routeFlow) expressionsCompleteOrRunDefers(expressions []ast.Expr, visiting map[*types.Func]bool, depth int) bool {
	for _, expression := range expressions {
		if !flow.expressionEvaluationProven(expression, visiting, depth) {
			return false
		}
	}
	return true
}

func (flow *routeFlow) expressionEvaluationProven(expression ast.Expr, visiting map[*types.Func]bool, depth int) bool {
	if expression == nil {
		return expression == nil
	}
	proven := true
	ast.Inspect(expression, func(node ast.Node) bool {
		if !proven {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		proven = flow.callCompletesOrRunsDefers(call, visiting, depth)
		return false
	})
	return proven
}

func (flow *routeFlow) simpleFunctionProven(function *types.Func, visiting map[*types.Func]bool, depth int) bool {
	body := flow.functionBodies[function]
	if body == nil || depth >= maxSimpleHelperDepth || visiting[function] {
		return false
	}
	visiting[function] = true
	proven := flow.simpleBodyProven(body, visiting, depth+1)
	delete(visiting, function)
	return proven
}

func (flow *routeFlow) simpleBodyProven(body *ast.BlockStmt, visiting map[*types.Func]bool, depth int) bool {
	if body == nil || depth > maxSimpleHelperDepth {
		return false
	}
	for _, statement := range body.List {
		switch typed := statement.(type) {
		case *ast.EmptyStmt:
			continue
		case *ast.ReturnStmt:
			return flow.expressionsCompleteOrRunDefers(typed.Results, visiting, depth)
		case *ast.ExprStmt:
			if flow.terminates(typed.X) {
				return flow.terminationExecutesDefers(typed.X, visiting, depth)
			}
			call, ok := unwrapParen(typed.X).(*ast.CallExpr)
			if !ok || !flow.callCompletesOrRunsDefers(call, visiting, depth) {
				return false
			}
		case *ast.AssignStmt:
			if !flow.expressionsCompleteOrRunDefers(typed.Lhs, visiting, depth) ||
				!flow.expressionsCompleteOrRunDefers(typed.Rhs, visiting, depth) {
				return false
			}
		case *ast.DeclStmt:
			declaration, ok := typed.Decl.(*ast.GenDecl)
			if !ok {
				return false
			}
			for _, raw := range declaration.Specs {
				value, ok := raw.(*ast.ValueSpec)
				if !ok || !flow.expressionsCompleteOrRunDefers(value.Values, visiting, depth) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func selectHasDefault(statement *ast.SelectStmt) bool {
	for _, raw := range statement.Body.List {
		clause, ok := raw.(*ast.CommClause)
		if ok && clause.Comm == nil {
			return true
		}
	}
	return false
}

func (flow *routeFlow) nonBlockingSelectCommunication(statement ast.Stmt) bool {
	found := false
	ast.Inspect(flow.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		selection, ok := node.(*ast.SelectStmt)
		if !ok || !selectHasDefault(selection) {
			return true
		}
		for _, raw := range selection.Body.List {
			clause, ok := raw.(*ast.CommClause)
			if ok && clause.Comm == statement {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func (flow *routeFlow) provesServeMuxAt(receiver ast.Expr, position token.Pos) bool {
	if identifier, ok := receiver.(*ast.Ident); ok && flow.Imports[identifier.Name] == "net/http" {
		return true
	}
	root, fields, ok := receiverPath(receiver)
	if !ok {
		return false
	}
	if flow.Imports[root] == "net/http" && len(fields) == 1 && fields[0] == "DefaultServeMux" {
		return true
	}
	object := expressionRootObject(receiver, flow.Info)
	typedInput := flow.typedServeMuxInput(object, receiver)
	return flow.receiverStateAt(position, root, fields, object, typedInput) == receiverValid
}

func expressionRootObject(expression ast.Expr, info *types.Info) types.Object {
	switch typed := expression.(type) {
	case *ast.Ident:
		if object := info.Uses[typed]; object != nil {
			return object
		}
		return info.Defs[typed]
	case *ast.SelectorExpr:
		return expressionRootObject(typed.X, info)
	case *ast.ParenExpr:
		return expressionRootObject(typed.X, info)
	default:
		return nil
	}
}

func receiverPath(expression ast.Expr) (string, []string, bool) {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name, nil, true
	case *ast.SelectorExpr:
		root, fields, ok := receiverPath(typed.X)
		return root, append(fields, typed.Sel.Name), ok
	case *ast.ParenExpr:
		return receiverPath(typed.X)
	default:
		return "", nil, false
	}
}

const (
	receiverUnreachable = iota
	receiverInvalid
	receiverValid
	receiverEscaped
)

func (flow *routeFlow) receiverStates(root string, fields []string, object types.Object, typedInput bool) []int {
	states := make([]int, len(flow.Nodes))
	initial := receiverInvalid
	if input, ok := flow.inputStates[object]; ok {
		initial = input
	} else if flow.parent != nil {
		if object != nil && object.Pos() < flow.Body.Pos() {
			initial = flow.capturedReceiverState(root, fields, object, typedInput)
		}
	} else if typedInput {
		initial = receiverValid
	}
	states[flow.Entry] = initial
	changed := true
	for changed {
		changed = false
		for index, node := range flow.Nodes {
			if states[index] == receiverUnreachable {
				continue
			}
			out := flow.transferReceiver(node.Statement, states[index], root, fields, object)
			for _, next := range node.Next {
				joined := joinReceiverState(states[next], out)
				if joined != states[next] {
					states[next] = joined
					changed = true
				}
			}
		}
	}
	return states
}

func (flow *routeFlow) receiverStateAt(position token.Pos, root string, fields []string, object types.Object, typedInput bool) int {
	node := flow.nodeAt(position)
	if node == noFlowNode || !flow.nodeReachable(node) {
		return receiverInvalid
	}
	return flow.receiverStates(root, fields, object, typedInput)[node]
}

func (flow *routeFlow) typedServeMuxInput(object types.Object, receiver ast.Expr) bool {
	variable, ok := object.(*types.Var)
	if !ok || variable.Pkg() == nil || variable.Parent() == nil || variable.Parent() == variable.Pkg().Scope() ||
		flow.Body == nil || variable.Pos() >= flow.Body.Pos() {
		return false
	}
	return serveMuxPointer(flow.Info.TypeOf(receiver))
}

func joinReceiverState(current, incoming int) int {
	if current == receiverUnreachable {
		return incoming
	}
	if current == receiverEscaped || incoming == receiverEscaped {
		return receiverEscaped
	}
	if current == receiverValid && incoming == receiverValid {
		return receiverValid
	}
	return receiverInvalid
}

func (flow *routeFlow) transferReceiver(statement ast.Stmt, current int, root string, fields []string, object types.Object) int {
	if current == receiverEscaped {
		return receiverEscaped
	}
	if flow.receiverMayEscapeOrChange(statement, object) {
		return receiverEscaped
	}
	left, right, assigned := assignedExpression(statement, root, fields, object, flow.Info)
	if !assigned {
		return current
	}
	if left == 0 {
		if flow.definitionProvidesFields(right, fields) {
			return receiverValid
		}
		if aliasState, ok := flow.receiverAliasState(right, object, statement.Pos()); ok {
			return aliasState
		}
		return receiverInvalid
	}
	if left == len(fields) {
		if current == receiverValid && flow.nonNilServeMux(right) {
			return receiverValid
		}
		return receiverInvalid
	}
	return receiverInvalid
}

func (flow *routeFlow) receiverAliasState(expression ast.Expr, target types.Object, position token.Pos) (int, bool) {
	root, fields, ok := receiverPath(expression)
	if !ok {
		return receiverInvalid, false
	}
	object := expressionRootObject(expression, flow.Info)
	if object == nil || object == target || object.Pos() >= target.Pos() {
		return receiverInvalid, false
	}
	typedInput := flow.typedServeMuxInput(object, expression)
	if flow.parent != nil && object.Pos() < flow.Body.Pos() {
		return flow.capturedReceiverState(root, fields, object, typedInput), true
	}
	return flow.receiverStateAt(position, root, fields, object, typedInput), true
}

func (flow *routeFlow) capturedReceiverState(root string, fields []string, object types.Object, typedInput bool) int {
	if flow.parent == nil {
		return receiverInvalid
	}
	if flow.schedule == closureImmediate {
		return flow.parent.receiverStateAt(flow.call, root, fields, object, typedInput)
	}
	if (flow.schedule == closureDeferred || flow.schedule == closureGoroutineWaited) &&
		flow.parent.receiverStableAfter(flow.call, root, fields, object) {
		return flow.parent.receiverStateAt(flow.call, root, fields, object, typedInput)
	}
	return receiverInvalid
}

func (flow *routeFlow) receiverStableAfter(position token.Pos, root string, fields []string, object types.Object) bool {
	start := flow.nodeAt(position)
	if start == noFlowNode || !flow.nodeReachable(start) {
		return false
	}
	states := make([]map[types.Object]bool, len(flow.Nodes))
	queue := append([]int(nil), flow.Nodes[start].Next...)
	queued := make([]bool, len(flow.Nodes))
	for _, next := range queue {
		states[next] = map[types.Object]bool{object: true}
		queued[next] = true
	}
	for len(queue) > 0 {
		index := queue[0]
		queue = queue[1:]
		queued[index] = false
		node := flow.Nodes[index]
		aliases := states[index]
		if len(fields) > 0 && flow.receiverMethodMayChange(node.Statement, aliases, map[*ast.FuncLit]bool{}) {
			return false
		}
		if flow.receiverAliasesMayEscapeOrChange(node.Statement, aliases, object) {
			return false
		}
		if _, _, assigned := assignedExpression(node.Statement, root, fields, object, flow.Info); assigned {
			return false
		}
		out := flow.transferReceiverAliases(node.Statement, aliases)
		for _, next := range node.Next {
			if mergeReceiverAliases(&states[next], out) && !queued[next] {
				queue = append(queue, next)
				queued[next] = true
			}
		}
	}
	return true
}

func mergeReceiverAliases(target *map[types.Object]bool, incoming map[types.Object]bool) bool {
	if *target == nil {
		*target = map[types.Object]bool{}
	}
	changed := false
	for object := range incoming {
		if object != nil && !(*target)[object] {
			(*target)[object] = true
			changed = true
		}
	}
	return changed
}

func cloneReceiverAliases(aliases map[types.Object]bool) map[types.Object]bool {
	result := make(map[types.Object]bool, len(aliases))
	for object := range aliases {
		if object != nil {
			result[object] = true
		}
	}
	return result
}

func (flow *routeFlow) transferReceiverAliases(statement ast.Stmt, aliases map[types.Object]bool) map[types.Object]bool {
	result := cloneReceiverAliases(aliases)
	record := func(left, right ast.Expr) {
		identifier, ok := unwrapParen(left).(*ast.Ident)
		if !ok || !flow.localReceiverAliasTarget(identifier) {
			return
		}
		object := objectForIdentifier(identifier, flow.Info)
		if flow.receiverExpressionMayAlias(right, aliases, map[*types.Func]bool{}, map[*ast.FuncLit]bool{}) {
			result[object] = true
		} else {
			delete(result, object)
		}
	}
	switch typed := statement.(type) {
	case *ast.AssignStmt:
		if len(typed.Lhs) == len(typed.Rhs) {
			for index := range typed.Lhs {
				record(typed.Lhs[index], typed.Rhs[index])
			}
		}
	case *ast.DeclStmt:
		declaration, _ := typed.Decl.(*ast.GenDecl)
		if declaration == nil {
			break
		}
		for _, raw := range declaration.Specs {
			value, ok := raw.(*ast.ValueSpec)
			if !ok || len(value.Names) != len(value.Values) {
				continue
			}
			for index := range value.Names {
				record(value.Names[index], value.Values[index])
			}
		}
	}
	return result
}

func (flow *routeFlow) receiverAliasStates(initial map[types.Object]bool) ([]map[types.Object]bool, []bool) {
	states := make([]map[types.Object]bool, len(flow.Nodes))
	reached := make([]bool, len(flow.Nodes))
	queued := make([]bool, len(flow.Nodes))
	states[flow.Entry] = cloneReceiverAliases(initial)
	reached[flow.Entry] = true
	queued[flow.Entry] = true
	queue := []int{flow.Entry}
	for len(queue) > 0 {
		index := queue[0]
		queue = queue[1:]
		queued[index] = false
		out := flow.transferReceiverAliases(flow.Nodes[index].Statement, states[index])
		for _, next := range flow.Nodes[index].Next {
			changed := false
			if !reached[next] {
				states[next] = cloneReceiverAliases(out)
				reached[next] = true
				changed = true
			} else {
				changed = mergeReceiverAliases(&states[next], out)
			}
			if changed && !queued[next] {
				queue = append(queue, next)
				queued[next] = true
			}
		}
	}
	return states, reached
}

func (flow *routeFlow) receiverExpressionMayAlias(expression ast.Expr, aliases map[types.Object]bool, visiting map[*types.Func]bool, seen map[*ast.FuncLit]bool) bool {
	switch typed := unwrapParen(expression).(type) {
	case *ast.Ident:
		return aliases[objectForIdentifier(typed, flow.Info)]
	case *ast.CallExpr:
		if !flow.callResultCanAlias(typed, aliases) {
			return false
		}
		for _, literal := range flow.possibleInvokedClosures(typed) {
			if flow.functionLiteralReturnsAlias(literal, aliases, visiting, seen) {
				return true
			}
		}
		switch function := unwrapParen(typed.Fun).(type) {
		case *ast.FuncLit:
			return flow.functionLiteralReturnsAlias(function, aliases, visiting, seen)
		case *ast.SelectorExpr:
			if aliases[expressionRootObject(function.X, flow.Info)] {
				called := flow.calledFunction(typed)
				return called == nil || flow.functionReturnsReceiver(called, visiting)
			}
		case *ast.Ident:
			if called, receiver, ok := flow.boundMethodValue(function, typed.Pos()); ok && aliases[receiver] {
				return flow.functionReturnsReceiver(called, visiting)
			}
		}
		for _, argument := range typed.Args {
			if flow.receiverValueContainsAlias(argument, aliases) {
				return true
			}
		}
	}
	return false
}

func (flow *routeFlow) callResultCanAlias(call *ast.CallExpr, aliases map[types.Object]bool) bool {
	result := flow.Info.TypeOf(call)
	if result == nil {
		return true
	}
	for object := range aliases {
		if object != nil && object.Type() != nil && types.Identical(result, object.Type()) {
			return true
		}
	}
	return false
}

func (flow *routeFlow) functionLiteralReturnsAlias(literal *ast.FuncLit, aliases map[types.Object]bool, visiting map[*types.Func]bool, seen map[*ast.FuncLit]bool) bool {
	if literal == nil || seen[literal] {
		return true
	}
	seen[literal] = true
	defer delete(seen, literal)
	literalFlow := newNestedRouteFlow(literal.Body, flow.Info, flow.Imports, flow, literal.Pos())
	states, reached := literalFlow.receiverAliasStates(aliases)
	returned := false
	ast.Inspect(literal.Body, func(node ast.Node) bool {
		if returned {
			return false
		}
		if nested, ok := node.(*ast.FuncLit); ok && nested != literal {
			return false
		}
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		flowNode := literalFlow.nodeAt(statement.Pos())
		if flowNode == noFlowNode || !reached[flowNode] {
			return false
		}
		for _, result := range statement.Results {
			if literalFlow.receiverExpressionMayAlias(result, states[flowNode], visiting, seen) {
				returned = true
				return false
			}
		}
		return true
	})
	return returned
}

func (flow *routeFlow) functionReturnsReceiver(function *types.Func, visiting map[*types.Func]bool) bool {
	if function == nil || visiting[function] {
		return true
	}
	body := flow.functionBodies[function]
	receiver := receiverObject(function)
	if body == nil || receiver == nil {
		return true
	}
	visiting[function] = true
	defer delete(visiting, function)
	calleeFlow := newRouteFlow(body, flow.Info, flow.Imports)
	states, reached := calleeFlow.receiverAliasStates(map[types.Object]bool{receiver: true})
	signature, _ := function.Type().(*types.Signature)
	returned := false
	ast.Inspect(body, func(node ast.Node) bool {
		if returned {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		flowNode := calleeFlow.nodeAt(statement.Pos())
		if flowNode == noFlowNode || !reached[flowNode] {
			return false
		}
		aliases := states[flowNode]
		if len(statement.Results) == 0 && signature != nil {
			for index := 0; index < signature.Results().Len(); index++ {
				if aliases[signature.Results().At(index)] {
					returned = true
					return false
				}
			}
		}
		for _, result := range statement.Results {
			if calleeFlow.receiverExpressionMayAlias(result, aliases, visiting, map[*ast.FuncLit]bool{}) {
				returned = true
				return false
			}
		}
		return true
	})
	return returned
}

func (flow *routeFlow) directReceiverAlias(expression ast.Expr, aliases map[types.Object]bool) bool {
	identifier, ok := unwrapParen(expression).(*ast.Ident)
	return ok && aliases[objectForIdentifier(identifier, flow.Info)]
}

func (flow *routeFlow) localReceiverAliasTarget(identifier *ast.Ident) bool {
	object := objectForIdentifier(identifier, flow.Info)
	return object != nil && (object.Pkg() == nil || object.Parent() != object.Pkg().Scope())
}

func (flow *routeFlow) receiverExpressionUsesAlias(expression ast.Expr, aliases map[types.Object]bool) bool {
	uses := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if uses {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if ok && aliases[objectForIdentifier(identifier, flow.Info)] {
			uses = true
			return false
		}
		return true
	})
	return uses
}

func (flow *routeFlow) receiverValueContainsAlias(expression ast.Expr, aliases map[types.Object]bool) bool {
	contains := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if contains {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if selector, ok := node.(*ast.SelectorExpr); ok && aliases[expressionRootObject(selector.X, flow.Info)] {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if ok && aliases[objectForIdentifier(identifier, flow.Info)] {
			contains = true
			return false
		}
		return true
	})
	return contains
}

func (flow *routeFlow) receiverAssignmentUnsafe(assignment *ast.AssignStmt, aliases map[types.Object]bool, protected types.Object) bool {
	for _, left := range assignment.Lhs {
		identifier, direct := unwrapParen(left).(*ast.Ident)
		if direct && protected != nil && objectForIdentifier(identifier, flow.Info) == protected {
			return true
		}
		if !direct && flow.receiverExpressionUsesAlias(left, aliases) {
			return true
		}
	}
	for index, right := range assignment.Rhs {
		if !flow.receiverValueContainsAlias(right, aliases) {
			continue
		}
		if len(assignment.Lhs) == len(assignment.Rhs) && flow.directReceiverAlias(right, aliases) {
			identifier, direct := unwrapParen(assignment.Lhs[index]).(*ast.Ident)
			if direct && flow.localReceiverAliasTarget(identifier) {
				continue
			}
		}
		return true
	}
	return false
}

func (flow *routeFlow) receiverMethodMayChange(node ast.Node, aliases map[types.Object]bool, seen map[*ast.FuncLit]bool) bool {
	if node == nil || len(aliases) == 0 {
		return false
	}
	changed := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		if changed {
			return false
		}
		if _, nested := candidate.(*ast.FuncLit); nested {
			return false
		}
		call, ok := candidate.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, literal := range flow.possibleInvokedClosures(call) {
			if !seen[literal] {
				seen[literal] = true
				changed = flow.receiverMethodMayChange(literal.Body, aliases, seen)
				delete(seen, literal)
				if changed {
					return false
				}
			}
		}
		if identifier, ok := unwrapParen(call.Fun).(*ast.Ident); ok {
			function, receiver, bound := flow.boundMethodValue(identifier, call.Pos())
			if bound && aliases[receiver] && !knownServeMuxRegistration(function, receiver) && (flow.functionBodies[function] == nil ||
				flow.functionMayChangeObject(function, receiverObject(function), map[*types.Func]bool{})) {
				changed = true
				return false
			}
		}
		selector, ok := unwrapParen(call.Fun).(*ast.SelectorExpr)
		if !ok || !aliases[expressionRootObject(selector.X, flow.Info)] {
			return true
		}
		function := flow.calledFunction(call)
		if function == nil || flow.functionBodies[function] == nil ||
			flow.functionMayChangeObject(function, receiverObject(function), map[*types.Func]bool{}) {
			changed = true
			return false
		}
		return true
	})
	return changed
}

func (flow *routeFlow) receiverMayEscapeOrChange(statement ast.Stmt, object types.Object) bool {
	return flow.receiverAliasesMayEscapeOrChange(statement, map[types.Object]bool{object: object != nil}, nil)
}

func (flow *routeFlow) receiverAliasesMayEscapeOrChange(statement ast.Stmt, aliases map[types.Object]bool, protected types.Object) bool {
	if statement == nil || len(aliases) == 0 {
		return false
	}
	unsafe := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if unsafe {
			return false
		}
		switch typed := node.(type) {
		case *ast.UnaryExpr:
			if typed.Op == token.AND && flow.receiverExpressionUsesAlias(typed.X, aliases) {
				unsafe = true
				return false
			}
		case *ast.AssignStmt:
			if flow.receiverAssignmentUnsafe(typed, aliases, protected) {
				unsafe = true
				return false
			}
		case *ast.FuncLit:
			return false
		}
		return true
	})
	if unsafe {
		return true
	}
	for object := range aliases {
		if flow.escapingMutatorAssignment(statement, object) || flow.compositeMutatorEscape(statement, object) {
			return true
		}
	}
	ast.Inspect(statement, func(node ast.Node) bool {
		if unsafe {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for object := range aliases {
			for _, literal := range flow.possibleInvokedClosures(call) {
				if flow.functionLiteralMayChangeReceiver(literal, object) {
					unsafe = true
					return false
				}
			}
			if flow.callMayChangeReceiver(call, object, map[*types.Func]bool{}) {
				unsafe = true
				return false
			}
		}
		for _, argument := range call.Args {
			literal, proven := closureFromExpression(argument, flow.closures, flow, call.Pos())
			if proven {
				for object := range aliases {
					if flow.functionLiteralMayChangeReceiver(literal, object) {
						unsafe = true
						return false
					}
				}
			}
		}
		return true
	})
	if unsafe {
		return true
	}
	if returned, ok := statement.(*ast.ReturnStmt); ok {
		for _, result := range returned.Results {
			if flow.receiverValueContainsAlias(result, aliases) {
				return true
			}
			literal, proven := closureFromExpression(result, flow.closures, flow, returned.Pos())
			if proven {
				for object := range aliases {
					if flow.functionLiteralMayChangeReceiver(literal, object) {
						return true
					}
				}
			}
		}
	}
	return unsafe
}

func (flow *routeFlow) compositeMutatorEscape(statement ast.Stmt, object types.Object) bool {
	escaped := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if escaped {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		composite, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range composite.Elts {
			expression, ok := element.(ast.Expr)
			if keyed, keyedOK := element.(*ast.KeyValueExpr); keyedOK {
				expression, ok = keyed.Value, true
			}
			if !ok {
				continue
			}
			literal, proven := closureFromExpression(expression, flow.closures, flow, expression.Pos())
			if proven && flow.functionLiteralMayChangeReceiver(literal, object) {
				escaped = true
				return false
			}
		}
		return true
	})
	return escaped
}

func (flow *routeFlow) escapingMutatorAssignment(statement ast.Stmt, object types.Object) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok {
		return false
	}
	for index, right := range assignment.Rhs {
		literal, proven := closureFromExpression(right, flow.closures, flow, assignment.Pos())
		if !proven || !flow.functionLiteralMayChangeReceiver(literal, object) {
			continue
		}
		if index >= len(assignment.Lhs) || !flow.localClosureTarget(assignment.Lhs[index]) {
			return true
		}
	}
	return false
}

func (flow *routeFlow) localClosureTarget(expression ast.Expr) bool {
	identifier, ok := unwrapParen(expression).(*ast.Ident)
	if !ok || identifier.Name == "" {
		return false
	}
	if identifier.Name == "_" {
		return true
	}
	object := objectForIdentifier(identifier, flow.Info)
	return object != nil && (object.Pkg() == nil || object.Parent() != object.Pkg().Scope())
}

func (flow *routeFlow) functionLiteralMayChangeReceiver(literal *ast.FuncLit, object types.Object) bool {
	return flow.functionLiteralMayChangeReceiverSeen(literal, object, map[*ast.FuncLit]bool{})
}

func (flow *routeFlow) functionLiteralMayChangeReceiverSeen(literal *ast.FuncLit, object types.Object, seen map[*ast.FuncLit]bool) bool {
	if literal == nil || seen[literal] {
		return false
	}
	seen[literal] = true
	literalFlow := newNestedRouteFlow(literal.Body, flow.Info, flow.Imports, flow, literal.Pos())
	states, reached := literalFlow.receiverAliasStates(map[types.Object]bool{object: true})
	changed := false
	ast.Inspect(literal.Body, func(node ast.Node) bool {
		if changed {
			return false
		}
		switch typed := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			flowNode := literalFlow.nodeAt(typed.Pos())
			if flowNode != noFlowNode && reached[flowNode] && literalFlow.receiverAssignmentUnsafe(typed, states[flowNode], object) {
				changed = true
				return false
			}
		case *ast.UnaryExpr:
			flowNode := literalFlow.nodeAt(typed.Pos())
			if typed.Op == token.AND && flowNode != noFlowNode && reached[flowNode] &&
				literalFlow.receiverExpressionUsesAlias(typed.X, states[flowNode]) {
				changed = true
				return false
			}
		case *ast.CallExpr:
			flowNode := literalFlow.nodeAt(typed.Pos())
			if flowNode == noFlowNode || !reached[flowNode] {
				return false
			}
			for alias := range states[flowNode] {
				if literalFlow.callMayChangeReceiverSeen(typed, alias, map[*types.Func]bool{}, seen) {
					changed = true
					return false
				}
			}
			factory, ok := unwrapParen(typed.Fun).(*ast.CallExpr)
			if ok {
				returned, returnedOK := literalFlow.returnedFunctionLiteral(factory)
				if !returnedOK || literalFlow.functionLiteralMayChangeReceiverSeen(returned, object, seen) {
					changed = true
					return false
				}
			}
		}
		return true
	})
	return changed
}

func (flow *routeFlow) possibleInvokedClosures(call *ast.CallExpr) []*ast.FuncLit {
	if call == nil {
		return nil
	}
	result := flow.possibleClosureLiterals(call.Fun, call.Pos(), map[types.Object]bool{})
	unique := make([]*ast.FuncLit, 0, len(result))
	seen := map[*ast.FuncLit]bool{}
	for _, literal := range result {
		if literal != nil && !seen[literal] {
			seen[literal] = true
			unique = append(unique, literal)
		}
	}
	return unique
}

func (flow *routeFlow) possibleClosureLiterals(expression ast.Expr, use token.Pos, seen map[types.Object]bool) []*ast.FuncLit {
	switch typed := unwrapParen(expression).(type) {
	case *ast.FuncLit:
		return []*ast.FuncLit{typed}
	case *ast.CallExpr:
		if literal, proven := flow.returnedFunctionLiteral(typed); proven {
			return []*ast.FuncLit{literal}
		}
		return nil
	case *ast.Ident:
		object := objectForIdentifier(typed, flow.Info)
		if object == nil || seen[object] {
			return nil
		}
		seen[object] = true
		defer delete(seen, object)
		var result []*ast.FuncLit
		for _, binding := range flow.closures[object] {
			definition := flow.nodeAt(binding.definition)
			target := flow.nodeAt(use)
			if definition == noFlowNode || target == noFlowNode || !flow.nodeReachable(definition) ||
				(definition != target && !flow.nodeReachableFrom(definition, target)) || !binding.valid {
				continue
			}
			if binding.literal != nil {
				result = append(result, binding.literal)
			} else if binding.source != nil {
				for source, bindings := range flow.closures {
					if source != binding.source {
						continue
					}
					for _, sourceBinding := range bindings {
						if sourceBinding.definition < binding.definition && sourceBinding.literal != nil {
							result = append(result, sourceBinding.literal)
						}
					}
				}
			}
		}
		if len(result) == 0 && len(flow.closures[object]) == 0 && flow.parent != nil && object.Pos() < flow.Body.Pos() {
			delete(seen, object)
			return flow.parent.possibleClosureLiterals(expression, flow.call, seen)
		}
		return result
	default:
		return nil
	}
}

func (flow *routeFlow) callMayChangeReceiver(call *ast.CallExpr, object types.Object, visiting map[*types.Func]bool) bool {
	return flow.callMayChangeReceiverSeen(call, object, visiting, map[*ast.FuncLit]bool{})
}

func (flow *routeFlow) callMayChangeReceiverSeen(call *ast.CallExpr, object types.Object, visiting map[*types.Func]bool, seen map[*ast.FuncLit]bool) bool {
	if call == nil || object == nil {
		return false
	}
	if literals := flow.possibleInvokedClosures(call); len(literals) > 0 {
		for _, literal := range literals {
			if flow.functionLiteralMayChangeReceiverSeen(literal, object, seen) {
				return true
			}
		}
		return false
	}
	if identifier, ok := unwrapParen(call.Fun).(*ast.Ident); ok {
		function, receiver, bound := flow.boundMethodValue(identifier, call.Pos())
		if bound && receiver == object {
			if knownServeMuxRegistration(function, receiver) {
				return false
			}
			return flow.functionBodies[function] == nil || flow.functionMayChangeObject(function, receiverObject(function), visiting)
		}
	}
	if selector, ok := unwrapParen(call.Fun).(*ast.SelectorExpr); ok && expressionRootObject(selector.X, flow.Info) == object {
		if function := flow.calledFunction(call); function != nil && flow.functionMayChangeObject(function, receiverObject(function), visiting) {
			return true
		}
	}
	for _, argument := range call.Args {
		if expressionContainsObject(argument, object, flow.Info) {
			return true
		}
	}
	function := flow.calledFunction(call)
	if function == nil {
		if factory, ok := unwrapParen(call.Fun).(*ast.CallExpr); ok {
			returned, proven := flow.returnedFunctionLiteral(factory)
			return !proven || flow.functionLiteralMayChangeReceiver(returned, object)
		}
		if identifier, ok := unwrapParen(call.Fun).(*ast.Ident); ok {
			switch objectForIdentifier(identifier, flow.Info).(type) {
			case *types.Builtin, *types.TypeName:
				return false
			}
		}
		return object.Pkg() != nil && object.Parent() == object.Pkg().Scope()
	}
	if object.Pkg() == nil || object.Parent() != object.Pkg().Scope() || function.Pkg() != object.Pkg() {
		return false
	}
	if flow.functionBodies[function] == nil {
		return true
	}
	return flow.functionMayChangeObject(function, object, visiting)
}

func knownServeMuxRegistration(function *types.Func, receiver types.Object) bool {
	return function != nil && receiver != nil && (function.Name() == "Handle" || function.Name() == "HandleFunc") &&
		serveMuxPointer(receiver.Type())
}

func (flow *routeFlow) boundMethodValue(identifier *ast.Ident, use token.Pos) (*types.Func, types.Object, bool) {
	target := objectForIdentifier(identifier, flow.Info)
	if target == nil || flow.Body == nil {
		return nil, nil, false
	}
	type binding struct {
		definition token.Pos
		function   *types.Func
		receiver   types.Object
	}
	var bindings []binding
	record := func(left, right ast.Expr, definition token.Pos) {
		name, ok := unwrapParen(left).(*ast.Ident)
		if !ok || objectForIdentifier(name, flow.Info) != target {
			return
		}
		current := binding{definition: definition}
		selector, ok := unwrapParen(right).(*ast.SelectorExpr)
		if ok {
			if selection := flow.Info.Selections[selector]; selection != nil {
				current.function, _ = selection.Obj().(*types.Func)
			} else {
				current.function, _ = flow.Info.Uses[selector.Sel].(*types.Func)
			}
			current.receiver = expressionRootObject(selector.X, flow.Info)
		}
		bindings = append(bindings, current)
	}
	ast.Inspect(flow.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch typed := node.(type) {
		case *ast.AssignStmt:
			if len(typed.Lhs) == len(typed.Rhs) {
				for index := range typed.Lhs {
					record(typed.Lhs[index], typed.Rhs[index], typed.Pos())
				}
			}
		case *ast.ValueSpec:
			if len(typed.Names) == len(typed.Values) {
				for index := range typed.Names {
					record(typed.Names[index], typed.Values[index], typed.Pos())
				}
			}
		}
		return true
	})
	definitions := make([]token.Pos, len(bindings))
	for index := range bindings {
		definitions[index] = bindings[index].definition
	}
	var selected *binding
	for index := range bindings {
		if !flow.bindingReachesUse(bindings[index].definition, use, definitions) {
			continue
		}
		if selected != nil {
			return nil, nil, false
		}
		selected = &bindings[index]
	}
	if selected == nil || selected.function == nil || selected.receiver == nil {
		return nil, nil, false
	}
	return selected.function, selected.receiver, true
}

func (flow *routeFlow) calledFunction(call *ast.CallExpr) *types.Func {
	switch function := unwrapParen(call.Fun).(type) {
	case *ast.Ident:
		result, _ := objectForIdentifier(function, flow.Info).(*types.Func)
		return result
	case *ast.SelectorExpr:
		if selection := flow.Info.Selections[function]; selection != nil {
			result, _ := selection.Obj().(*types.Func)
			return result
		}
		result, _ := flow.Info.Uses[function.Sel].(*types.Func)
		return result
	default:
		return nil
	}
}

func receiverObject(function *types.Func) types.Object {
	if function == nil {
		return nil
	}
	signature, _ := function.Type().(*types.Signature)
	if signature == nil {
		return nil
	}
	return signature.Recv()
}

func (flow *routeFlow) functionMayChangeObject(function *types.Func, object types.Object, visiting map[*types.Func]bool) bool {
	if function == nil || object == nil || visiting[function] {
		return true
	}
	body := flow.functionBodies[function]
	if body == nil {
		return false
	}
	visiting[function] = true
	defer delete(visiting, function)
	calleeFlow := newRouteFlow(body, flow.Info, flow.Imports)
	states, reached := calleeFlow.receiverAliasStates(map[types.Object]bool{object: true})
	var protected types.Object
	if object.Pkg() != nil && object.Parent() == object.Pkg().Scope() {
		protected = object
	}
	changed := false
	ast.Inspect(body, func(node ast.Node) bool {
		if changed {
			return false
		}
		switch typed := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			flowNode := calleeFlow.nodeAt(typed.Pos())
			if flowNode != noFlowNode && reached[flowNode] && calleeFlow.receiverAssignmentUnsafe(typed, states[flowNode], protected) {
				changed = true
				return false
			}
		case *ast.UnaryExpr:
			flowNode := calleeFlow.nodeAt(typed.Pos())
			if typed.Op == token.AND && flowNode != noFlowNode && reached[flowNode] &&
				calleeFlow.receiverExpressionUsesAlias(typed.X, states[flowNode]) {
				changed = true
				return false
			}
		case *ast.CallExpr:
			flowNode := calleeFlow.nodeAt(typed.Pos())
			if flowNode == noFlowNode || !reached[flowNode] {
				return false
			}
			for alias := range states[flowNode] {
				if calleeFlow.callMayChangeReceiver(typed, alias, visiting) {
					changed = true
					return false
				}
			}
		}
		return true
	})
	return changed
}

func (flow *routeFlow) returnedFunctionLiteral(call *ast.CallExpr) (*ast.FuncLit, bool) {
	function := flow.calledFunction(call)
	body := flow.functionBodies[function]
	if body == nil || len(body.List) != 1 {
		return nil, false
	}
	returned, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return nil, false
	}
	literal, ok := unwrapParen(returned.Results[0]).(*ast.FuncLit)
	return literal, ok
}

func expressionContainsObject(expression ast.Expr, object types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if ok && objectForIdentifier(identifier, info) == object {
			found = true
		}
		return !found
	})
	return found
}

func assignedExpression(statement ast.Stmt, root string, fields []string, object types.Object, info *types.Info) (int, ast.Expr, bool) {
	var leftExpressions []ast.Expr
	var rightExpressions []ast.Expr
	switch typed := statement.(type) {
	case *ast.AssignStmt:
		leftExpressions, rightExpressions = typed.Lhs, typed.Rhs
	case *ast.DeclStmt:
		declaration, ok := typed.Decl.(*ast.GenDecl)
		if !ok {
			return 0, nil, false
		}
		for _, spec := range declaration.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range values.Names {
				leftExpressions = append(leftExpressions, name)
			}
			rightExpressions = append(rightExpressions, values.Values...)
		}
	case *ast.RangeStmt:
		for _, expression := range []ast.Expr{typed.Key, typed.Value} {
			if expression != nil {
				leftExpressions = append(leftExpressions, expression)
			}
		}
	default:
		return 0, nil, false
	}
	for index, expression := range leftExpressions {
		candidateRoot, candidateFields, ok := receiverPath(expression)
		if !ok || candidateRoot != root || expressionRootObject(expression, info) != object || len(candidateFields) > len(fields) {
			continue
		}
		matches := true
		for fieldIndex := range candidateFields {
			matches = matches && candidateFields[fieldIndex] == fields[fieldIndex]
		}
		if !matches {
			continue
		}
		var right ast.Expr
		if len(leftExpressions) == len(rightExpressions) && index < len(rightExpressions) {
			right = rightExpressions[index]
		}
		return len(candidateFields), right, true
	}
	return 0, nil, false
}

func (flow *routeFlow) definitionProvidesFields(expression ast.Expr, fields []string) bool {
	expression = unwrapParen(expression)
	if len(fields) == 0 {
		return flow.nonNilServeMux(expression)
	}
	if pointer, ok := expression.(*ast.UnaryExpr); ok && pointer.Op == token.AND {
		expression = pointer.X
	}
	composite, ok := expression.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, element := range composite.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok || expressionName(field.Key) != fields[0] {
			continue
		}
		return flow.definitionProvidesFields(field.Value, fields[1:])
	}
	return false
}

func (flow *routeFlow) nonNilServeMux(expression ast.Expr) bool {
	expression = unwrapParen(expression)
	if expression == nil || !serveMuxPointer(flow.Info.TypeOf(expression)) {
		return false
	}
	switch typed := expression.(type) {
	case *ast.CallExpr:
		name := expressionName(typed.Fun)
		return importedCall(name, "net/http", "NewServeMux", flow.Imports) || name == "new"
	case *ast.UnaryExpr:
		return typed.Op == token.AND
	default:
		return false
	}
}

func serveMuxPointer(value types.Type) bool {
	pointer, ok := value.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "ServeMux"
}

func (flow *routeFlow) nodeAt(position token.Pos) int {
	result := noFlowNode
	span := token.Pos(0)
	for index, node := range flow.Nodes {
		if node.Statement == nil || position < node.Statement.Pos() || position > node.Statement.End() {
			continue
		}
		candidateSpan := node.Statement.End() - node.Statement.Pos()
		if result == noFlowNode || candidateSpan < span {
			result, span = index, candidateSpan
		}
	}
	return result
}

func (flow *routeFlow) nodeReachable(target int) bool {
	return flow.nodeReachableWithout(target, noFlowNode)
}

func (flow *routeFlow) nodeReachableFrom(start, target int) bool {
	if start == noFlowNode || target == noFlowNode {
		return false
	}
	reachable := map[int]bool{}
	queue := append([]int(nil), flow.Nodes[start].Next...)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if reachable[current] {
			continue
		}
		reachable[current] = true
		queue = append(queue, flow.Nodes[current].Next...)
	}
	return reachable[target]
}

func (flow *routeFlow) nodeReachableWithout(target, excluded int) bool {
	reachable := map[int]bool{}
	queue := []int{flow.Entry}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == excluded || reachable[current] {
			continue
		}
		reachable[current] = true
		queue = append(queue, flow.Nodes[current].Next...)
	}
	return reachable[target]
}

func (flow *routeFlow) positionReachable(position token.Pos) bool {
	node := flow.nodeAt(position)
	return node != noFlowNode && flow.nodeReachable(node) && flow.scheduledWorkBeforeCompletion(position)
}

func (flow *routeFlow) scheduledWorkBeforeCompletion(position token.Pos) bool {
	if flow.schedule != closureGoroutineWaited {
		return true
	}
	if len(flow.completionSignals) == 0 {
		return false
	}
	for _, signal := range flow.completionSignals {
		if signal.deferred {
			if !flow.positionDominates(position, signal.position) && !flow.allPathsReach(signal.position, position) {
				return false
			}
			continue
		}
		if !flow.positionDominates(position, signal.position) {
			return false
		}
	}
	return true
}

func (flow *routeFlow) positionDominates(definition, use token.Pos) bool {
	definitionNode := flow.nodeAt(definition)
	useNode := flow.nodeAt(use)
	if definitionNode == noFlowNode || useNode == noFlowNode || definitionNode == useNode ||
		!flow.nodeReachable(definitionNode) || !flow.nodeReachable(useNode) {
		return false
	}
	return !flow.nodeReachableWithout(useNode, definitionNode)
}

func (flow *routeFlow) bindingReachesUse(definition, use token.Pos, definitions []token.Pos) bool {
	if !flow.positionDominates(definition, use) {
		return false
	}
	definitionNode := flow.nodeAt(definition)
	useNode := flow.nodeAt(use)
	for _, other := range definitions {
		if other == definition {
			continue
		}
		otherNode := flow.nodeAt(other)
		if flow.nodeReachableFrom(definitionNode, otherNode) && flow.nodeReachableFrom(otherNode, useNode) {
			return false
		}
	}
	return true
}
