package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type callFact struct {
	Name          string
	PackageAlias  string
	Receiver      string
	NilArgument   bool
	ConfigArg     bool
	StringArgs    []string
	Identifiers   []string
	Arguments     []expressionFact
	Async         bool
	InTransaction bool
}

type functionFact struct {
	Name                 string
	ReceiverName         string
	ReceiverType         string
	Parameters           map[string]string
	ParameterOrder       []string
	NilDefaultParameters []string
	Results              []string
	Bindings             map[string]expressionFact
	FieldBindings        map[string]expressionFact
	Returns              []expressionFact
	Calls                []callFact
	Strings              []string
	Tables               []string
	Selectors            []string
}

type expressionFact struct {
	Name        string
	Identifier  string
	Nil         bool
	Call        bool
	Placeholder bool
}

type embedFact struct {
	Variable string
	Type     string
	Patterns []string
}

type routeFact struct {
	Method  string
	Path    string
	Handler string
	Symbol  string
	File    string
}

type goFileFact struct {
	Path         string
	Package      string
	PackageDir   string
	Test         bool
	Imports      map[string]string
	Symbols      []string
	Functions    []functionFact
	Routes       []routeFact
	Tables       []string
	Strings      []string
	Placeholders []string
	StructFields map[string]map[string]string
	Embeds       []embedFact
	ParseError   string
}

type textFact struct {
	Path   string
	Routes []string
	Words  []string
	Active bool
}

type sourceIndex struct {
	GoFiles      []goFileFact
	Frontend     []textFact
	Smoke        []textFact
	SourceSHA256 string
	Manifest     fileManifest
	Contents     map[string][]byte
	OpenAPI      []openAPIDoc
}

var routePattern = regexp.MustCompile(`/v[0-9]+/[A-Za-z0-9_./{}$:-]+`)
var wordPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]{2,}`)
var activeClientPattern = regexp.MustCompile(`(?i)\b(fetch|request|get|post|put|patch|delete|curl|playwright|go\s+test|node)\b`)

func buildSourceIndex(root string) (sourceIndex, error) {
	result := sourceIndex{Contents: map[string][]byte{}}
	openAPI, err := loadOpenAPI(root)
	if err != nil {
		return result, err
	}
	result.OpenAPI = openAPI
	scopes := []string{
		"services/control-api/internal",
		"services/control-api/cmd/control-api",
		"services/control-api/migrations",
		"apps/web/src",
		"scripts",
		"tests",
	}
	var paths []string
	openAPIContent := map[string][]byte{}
	for _, document := range openAPI {
		openAPIContent[document.Path] = document.Content
	}
	for _, scope := range scopes {
		base := filepath.Join(root, filepath.FromSlash(scope))
		if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("audited source symlink rejected: %s", relative)
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasPrefix(relative, "tests/runtime-wiring-audit/") ||
				strings.HasPrefix(relative, "tools/runtime-wiring-audit/") {
				return nil
			}
			if relevantSourcePath(relative) {
				paths = append(paths, relative)
			}
			return nil
		}); err != nil {
			return result, fmt.Errorf("walk %s: %w", scope, err)
		}
	}
	for _, document := range openAPI {
		paths = append(paths, document.Path)
	}
	sort.Strings(paths)
	paths = uniqueStrings(paths)
	for _, relative := range paths {
		content, ok := openAPIContent[relative]
		if !ok {
			content, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil {
				return result, fmt.Errorf("read %s: %w", relative, err)
			}
		}
		if strings.HasPrefix(relative, "apps/web/src/") {
			frontendFact := parseTextFact(relative, content)
			if frontendFact.Active && len(frontendFact.Routes) > 0 {
				result.Frontend = append(result.Frontend, frontendFact)
			}
		}
		result.Contents[relative] = append([]byte(nil), content...)
		switch {
		case strings.HasSuffix(relative, ".go") &&
			(strings.HasPrefix(relative, "services/control-api/internal/") || strings.HasPrefix(relative, "services/control-api/cmd/control-api/") ||
				strings.HasPrefix(relative, "services/control-api/migrations/")):
			fact := parseGoFact(relative, content)
			if fact.ParseError != "" {
				return result, fmt.Errorf("parse %s: %s", relative, fact.ParseError)
			}
			result.GoFiles = append(result.GoFiles, fact)
		case strings.HasPrefix(relative, "apps/web/src/"):
			// All frontend source participates in the snapshot; only active consumers become facts.
		case isSmokePath(relative):
			result.Smoke = append(result.Smoke, parseTextFact(relative, content))
		}
	}
	result.Manifest = newFileManifest(sourceManifestKind, paths, result.Contents)
	result.SourceSHA256 = result.Manifest.TotalSHA256
	return result, nil
}

func relevantSourcePath(path string) bool {
	if strings.Contains(path, "/node_modules/") || strings.Contains(path, "/vendor/") {
		return false
	}
	switch {
	case strings.HasPrefix(path, "services/control-api/internal/"), strings.HasPrefix(path, "services/control-api/cmd/control-api/"):
		return strings.HasSuffix(path, ".go")
	case strings.HasPrefix(path, "services/control-api/migrations/"):
		return strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".sql")
	case strings.HasPrefix(path, "api/"):
		return false
	case strings.HasPrefix(path, "apps/web/src/"):
		return (strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx")) && !isFrontendTest(path)
	case strings.HasPrefix(path, "scripts/"), strings.HasPrefix(path, "tests/"):
		return isSmokePath(path)
	default:
		return false
	}
}

func isFrontendTest(path string) bool {
	return strings.Contains(path, "/test/") || strings.Contains(path, "/tests/") ||
		strings.Contains(path, ".test.") || strings.Contains(path, ".spec.")
}

func isSmokePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasPrefix(lower, "scripts/") && strings.Contains(lower, "smoke") ||
		strings.HasPrefix(lower, "tests/") && (strings.Contains(lower, "smoke") || strings.Contains(lower, "e2e"))
}

func parseGoFact(path string, content []byte) goFileFact {
	fact := goFileFact{
		Path:         path,
		PackageDir:   filepath.ToSlash(filepath.Dir(path)),
		Test:         strings.HasSuffix(path, "_test.go"),
		Imports:      map[string]string{},
		StructFields: map[string]map[string]string{},
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments)
	if err != nil {
		fact.ParseError = err.Error()
		return fact
	}
	fact.Package = file.Name.Name
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		alias := filepath.Base(importPath)
		if imported.Name != nil {
			alias = imported.Name.Name
		}
		fact.Imports[alias] = importPath
	}
	routeTypes := routeTypeInfo(fset, file, fact.PackageDir)
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch named := spec.(type) {
				case *ast.TypeSpec:
					fact.Symbols = append(fact.Symbols, named.Name.Name)
					if structure, ok := named.Type.(*ast.StructType); ok {
						fields := map[string]string{}
						for _, field := range structure.Fields.List {
							fieldType := expressionName(field.Type)
							for _, fieldName := range field.Names {
								fields[fieldName.Name] = fieldType
							}
						}
						fact.StructFields[named.Name.Name] = fields
					}
				case *ast.ValueSpec:
					for _, name := range named.Names {
						fact.Symbols = append(fact.Symbols, name.Name)
					}
					for _, expression := range named.Values {
						ast.Inspect(expression, func(node ast.Node) bool {
							literal, ok := node.(*ast.BasicLit)
							if !ok || literal.Kind != token.STRING {
								return true
							}
							if decoded, decodeErr := strconv.Unquote(literal.Value); decodeErr == nil {
								fact.Strings = append(fact.Strings, decoded)
							}
							return true
						})
					}
					patterns := embedDirectives(typed.Doc, named.Doc)
					if len(patterns) > 0 && named.Type != nil && expressionName(named.Type) == "embed.FS" {
						if imported, ok := fact.Imports["embed"]; ok && imported == "embed" {
							for _, name := range named.Names {
								fact.Embeds = append(fact.Embeds, embedFact{Variable: name.Name, Type: "embed.FS", Patterns: patterns})
							}
						}
					}
				}
			}
		case *ast.FuncDecl:
			name := functionName(typed)
			fact.Symbols = append(fact.Symbols, name)
			function := functionFact{
				Name: name, Parameters: map[string]string{}, Bindings: map[string]expressionFact{},
				FieldBindings: map[string]expressionFact{},
			}
			if typed.Recv != nil && len(typed.Recv.List) > 0 {
				function.ReceiverType = expressionName(typed.Recv.List[0].Type)
				if len(typed.Recv.List[0].Names) > 0 {
					function.ReceiverName = typed.Recv.List[0].Names[0].Name
				}
			}
			collectFieldTypes(typed.Type.Params, function.Parameters)
			function.ParameterOrder = parameterOrder(typed.Type.Params)
			function.NilDefaultParameters = nilDefaultParameters(typed, routeTypes)
			function.Results = resultTypes(typed.Type.Results)
			if typed.Body != nil {
				routeControl := newRouteFlow(typed.Body, routeTypes, fact.Imports)
				collectBindingsAndReturns(typed.Body, &function, routeControl)
				collectExecutedFacts(typed.Body, &function, fact.Imports, routeControl, false, false)
				fact.Routes = append(fact.Routes, routesFromExecutedBody(path, name, typed.Body, fact, routeControl)...)
			}
			function.Strings = uniqueStrings(function.Strings)
			function.Tables = tablesFromStrings(function.Strings)
			function.Selectors = uniqueStrings(function.Selectors)
			fact.Functions = append(fact.Functions, function)
			fact.Strings = append(fact.Strings, function.Strings...)
			fact.Tables = append(fact.Tables, function.Tables...)
		}
	}
	fact.Symbols = uniqueStrings(fact.Symbols)
	fact.Strings = uniqueStrings(fact.Strings)
	fact.Tables = uniqueStrings(fact.Tables)
	for _, symbol := range fact.Symbols {
		if placeholderName(symbol) {
			fact.Placeholders = append(fact.Placeholders, symbol)
		}
	}
	return fact
}

func callBase(name string) string {
	if index := strings.LastIndex(name, "."); index >= 0 {
		return name[index+1:]
	}
	return name
}

func transactionCallName(name string) bool {
	base := strings.ToLower(callBase(name))
	return base == "beginfunc" || base == "begin" || base == "begintx" || base == "withtx" || base == "transaction"
}

func collectFieldTypes(fields *ast.FieldList, destination map[string]string) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		fieldType := expressionName(field.Type)
		for _, name := range field.Names {
			destination[name.Name] = fieldType
		}
	}
}

func parameterOrder(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var result []string
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			result = append(result, "")
			continue
		}
		for _, name := range field.Names {
			result = append(result, name.Name)
		}
	}
	return result
}

func nilDefaultParameters(function *ast.FuncDecl, info *types.Info) []string {
	if function.Body == nil {
		return nil
	}
	parameters := map[types.Object]string{}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if object := info.Defs[name]; object != nil {
					parameters[object] = name.Name
				}
			}
		}
	}
	var result []string
	for statementIndex, statement := range function.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		parameterObject := nilComparedObject(conditional.Cond, info)
		parameter := parameters[parameterObject]
		if parameter == "" {
			continue
		}
		defaulted := false
		reassignedInConditional := false
		defaultIndex := -1
		for bodyIndex, bodyStatement := range conditional.Body.List {
			assignment, ok := bodyStatement.(*ast.AssignStmt)
			if !ok {
				continue
			}
			for index, left := range assignment.Lhs {
				identifier, ok := left.(*ast.Ident)
				if ok && objectForIdentifier(identifier, info) == parameterObject && index < len(assignment.Rhs) && definitelyNonNilDefault(assignment.Rhs[index]) {
					defaulted = true
					defaultIndex = bodyIndex
					for _, following := range conditional.Body.List[bodyIndex+1:] {
						reassignedInConditional = reassignedInConditional || statementAssignsObject(following, parameterObject, info)
					}
				}
			}
		}
		for _, preceding := range function.Body.List[:statementIndex] {
			if nodeReferencesObject(preceding, parameterObject, info) {
				defaulted = false
			}
		}
		if defaultIndex >= 0 {
			for _, preceding := range conditional.Body.List[:defaultIndex] {
				if nodeReferencesObject(preceding, parameterObject, info) {
					defaulted = false
				}
			}
		}
		if conditional.Else != nil {
			reassignedInConditional = reassignedInConditional || statementAssignsObject(conditional.Else, parameterObject, info)
			defaulted = defaulted && !nodeReferencesObject(conditional.Else, parameterObject, info)
		}
		if !defaulted || reassignedInConditional {
			continue
		}
		usedInReturn := false
		reassigned := false
		escaped := false
		if defaultIndex >= 0 {
			escaped = nilDefaultEscapes(conditional.Body.List[defaultIndex+1:], parameterObject, info)
		}
		for _, following := range function.Body.List[statementIndex+1:] {
			reassigned = reassigned || statementAssignsObject(following, parameterObject, info)
			usedInReturn = usedInReturn || returnConstructionUsesObject(following, parameterObject, info)
			escaped = escaped || nilDefaultEscapes([]ast.Stmt{following}, parameterObject, info)
		}
		if !reassigned && !escaped && usedInReturn {
			result = append(result, parameter)
		}
	}
	return uniqueStrings(result)
}

func nilDefaultEscapes(statements []ast.Stmt, object types.Object, info *types.Info) bool {
	escaped := false
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			if escaped {
				return false
			}
			switch typed := node.(type) {
			case *ast.FuncLit:
				if nodeReferencesObject(typed.Body, object, info) {
					escaped = true
				}
				return false
			case *ast.UnaryExpr:
				candidate, ok := typed.X.(*ast.Ident)
				if typed.Op == token.AND && ok && objectForIdentifier(candidate, info) == object {
					escaped = true
					return false
				}
			}
			return true
		})
		if escaped {
			return true
		}
	}
	return false
}

func nodeReferencesObject(node ast.Node, object types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(node, func(child ast.Node) bool {
		candidate, ok := child.(*ast.Ident)
		if ok && objectForIdentifier(candidate, info) == object {
			found = true
		}
		return !found
	})
	return found
}

func statementAssignsObject(statement ast.Stmt, object types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, left := range assignment.Lhs {
			if target, ok := left.(*ast.Ident); ok && objectForIdentifier(target, info) == object {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}

func returnConstructionUsesObject(statement ast.Stmt, object types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		returned, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, expression := range returned.Results {
			construction := expression
			if pointer, ok := construction.(*ast.UnaryExpr); ok && pointer.Op == token.AND {
				construction = pointer.X
			}
			switch construction.(type) {
			case *ast.CompositeLit, *ast.CallExpr:
				ast.Inspect(construction, func(child ast.Node) bool {
					if candidate, ok := child.(*ast.Ident); ok && objectForIdentifier(candidate, info) == object {
						found = true
					}
					return !found
				})
			}
		}
		return !found
	})
	return found
}

func nilComparedObject(expression ast.Expr, info *types.Info) types.Object {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL {
		return nil
	}
	left, leftOK := binary.X.(*ast.Ident)
	right, rightOK := binary.Y.(*ast.Ident)
	if leftOK && rightOK && right.Name == "nil" {
		return objectForIdentifier(left, info)
	}
	if leftOK && rightOK && left.Name == "nil" {
		return objectForIdentifier(right, info)
	}
	return nil
}

func objectForIdentifier(identifier *ast.Ident, info *types.Info) types.Object {
	if object := info.Uses[identifier]; object != nil {
		return object
	}
	return info.Defs[identifier]
}

func definitelyNonNilDefault(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.UnaryExpr:
		return typed.Op == token.AND
	case *ast.CallExpr:
		return expressionName(typed.Fun) == "new"
	default:
		return false
	}
}

func resultTypes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var result []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			result = append(result, expressionName(field.Type))
		}
	}
	return result
}

func collectBindingsAndReturns(body *ast.BlockStmt, function *functionFact, flow *routeFlow) {
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			if !flow.positionReachable(value.Pos()) {
				return false
			}
			for index, left := range value.Lhs {
				if index >= len(value.Rhs) {
					continue
				}
				expression := expressionFromAST(value.Rhs[index])
				switch target := left.(type) {
				case *ast.Ident:
					function.Bindings[target.Name] = expression
				case *ast.SelectorExpr:
					function.FieldBindings[target.Sel.Name] = expression
				}
			}
		case *ast.DeclStmt:
			if !flow.positionReachable(value.Pos()) {
				return false
			}
			declaration, ok := value.Decl.(*ast.GenDecl)
			if !ok {
				break
			}
			for _, spec := range declaration.Specs {
				named, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range named.Names {
					if index < len(named.Values) {
						function.Bindings[name.Name] = expressionFromAST(named.Values[index])
					}
				}
			}
		case *ast.ReturnStmt:
			if flow.positionReachable(value.Pos()) && len(value.Results) > 0 {
				function.Returns = append(function.Returns, expressionFromAST(value.Results[0]))
			}
		}
		return true
	})
}

func collectExecutedFacts(body *ast.BlockStmt, function *functionFact, imports map[string]string, flow *routeFlow, async, inTransaction bool) {
	asyncCalls := map[token.Pos]bool{}
	schedules := scheduledClosureCalls(body, flow)
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.GoStmt:
			if statement.Call != nil && flow.positionReachable(statement.Pos()) {
				asyncCalls[statement.Call.Pos()] = true
			}
		}
		return true
	})
	closures := localClosures(body, flow.Info, flow)
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch value := node.(type) {
		case *ast.CallExpr:
			if !flow.positionReachable(value.Pos()) {
				return false
			}
			call := callFromAST(value, imports)
			call.Async = async || asyncCalls[value.Pos()]
			call.InTransaction = inTransaction
			function.Calls = append(function.Calls, call)
			base := callBase(call.Name)
			for _, argument := range value.Args {
				if base != "Go" && !transactionCallName(call.Name) {
					continue
				}
				literal, proven := closureFromExpression(argument, closures, flow, value.Pos())
				if !proven {
					continue
				}
				schedule := closureImmediate
				if base == "Go" {
					schedule = closureGoroutine
				}
				child := nestedRouteFlow(literal, flow, value, imports, schedule)
				collectExecutedFacts(literal.Body, function, imports, child,
					async || base == "Go", inTransaction || transactionCallName(call.Name))
			}
			if literal, proven := invokedClosure(value, closures, flow); proven {
				schedule := schedules[value.Pos()]
				if schedule != closureUnproven {
					child := nestedRouteFlow(literal, flow, value, imports, schedule)
					collectExecutedFacts(literal.Body, function, imports, child, call.Async, inTransaction)
				}
			}
		case *ast.BasicLit:
			if flow.positionReachable(value.Pos()) && value.Kind == token.STRING {
				if decoded, err := strconv.Unquote(value.Value); err == nil {
					function.Strings = append(function.Strings, decoded)
				}
			}
		case *ast.SelectorExpr:
			if flow.positionReachable(value.Pos()) {
				function.Selectors = append(function.Selectors, expressionName(value))
			}
		}
		return true
	})
}

func expressionFromAST(expression ast.Expr) expressionFact {
	expression = unwrapParen(expression)
	result := expressionFact{Name: expressionName(expression)}
	switch value := expression.(type) {
	case *ast.Ident:
		result.Identifier = value.Name
		result.Nil = value.Name == "nil"
	case *ast.CallExpr:
		result.Name = expressionName(value.Fun)
		result.Call = true
	case *ast.UnaryExpr:
		return expressionFromAST(value.X)
	case *ast.CompositeLit:
		result.Name = expressionName(value.Type)
	}
	result.Placeholder = placeholderDependencyName(result.Name)
	return result
}

func embedDirectives(groups ...*ast.CommentGroup) []string {
	var patterns []string
	for _, group := range groups {
		if group == nil {
			continue
		}
		for _, comment := range group.List {
			if !strings.HasPrefix(comment.Text, "//go:embed ") {
				continue
			}
			patterns = append(patterns, strings.Fields(strings.TrimPrefix(comment.Text, "//go:embed "))...)
		}
	}
	return uniqueStrings(patterns)
}

func functionName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}
	return expressionName(function.Recv.List[0].Type) + "." + function.Name.Name
}

func expressionName(expression ast.Expr) string {
	expression = unwrapParen(expression)
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return expressionName(typed.X)
	case *ast.SelectorExpr:
		return expressionName(typed.X) + "." + typed.Sel.Name
	case *ast.IndexExpr:
		return expressionName(typed.X)
	case *ast.ArrayType:
		return "[]" + expressionName(typed.Elt)
	case *ast.InterfaceType:
		return "interface"
	case *ast.FuncType:
		return "func"
	case *ast.MapType:
		return "map[" + expressionName(typed.Key) + "]" + expressionName(typed.Value)
	case *ast.CallExpr:
		return expressionName(typed.Fun)
	default:
		return "receiver"
	}
}

func unwrapParen(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func callFromAST(call *ast.CallExpr, imports map[string]string) callFact {
	result := callFact{Name: expressionName(call.Fun)}
	if selector, ok := unwrapParen(call.Fun).(*ast.SelectorExpr); ok {
		result.Receiver = expressionName(selector.X)
		if identifier, ok := selector.X.(*ast.Ident); ok {
			if _, exists := imports[identifier.Name]; exists {
				result.PackageAlias = identifier.Name
			}
		}
	}
	for _, argument := range call.Args {
		result.Arguments = append(result.Arguments, expressionFromAST(argument))
		if identifier, ok := argument.(*ast.Ident); ok && identifier.Name == "nil" {
			result.NilArgument = true
		}
		ast.Inspect(argument, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					if decoded, err := strconv.Unquote(value.Value); err == nil {
						result.StringArgs = append(result.StringArgs, decoded)
					}
				}
			case *ast.Ident:
				result.Identifiers = append(result.Identifiers, value.Name)
				if value.Name == "cfg" || strings.Contains(strings.ToLower(value.Name), "config") {
					result.ConfigArg = true
				}
			case *ast.SelectorExpr:
				if root := expressionName(value.X); root == "cfg" || strings.Contains(strings.ToLower(root), "config") {
					result.ConfigArg = true
				}
			case *ast.CompositeLit:
				if strings.Contains(strings.ToLower(expressionName(value.Type)), "config") {
					result.ConfigArg = true
				}
			}
			return true
		})
	}
	result.StringArgs = uniqueStrings(result.StringArgs)
	result.Identifiers = uniqueStrings(result.Identifiers)
	return result
}

func routeFromCall(path, symbol string, expression *ast.CallExpr, call callFact, flow *routeFlow) (routeFact, bool) {
	base := callBase(call.Name)
	if base != "Handle" && base != "HandleFunc" || len(expression.Args) < 2 || !serveMuxReceiver(call, expression, flow) {
		return routeFact{}, false
	}
	pattern, ok := constantString(expression.Args[0])
	if !ok {
		return routeFact{}, false
	}
	return routeFromPattern(path, symbol, pattern, routeHandlerName(expression))
}

func routesFromRanges(filePath, symbol string, body *ast.BlockStmt, file goFileFact, flow *routeFlow) []routeFact {
	var result []routeFact
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statement, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		value, ok := statement.Value.(*ast.Ident)
		if !ok || value.Name == "_" {
			return true
		}
		patterns := stringLiterals(statement.X)
		if len(patterns) == 0 {
			return true
		}
		ast.Inspect(statement.Body, func(child ast.Node) bool {
			if _, nested := child.(*ast.FuncLit); nested {
				return false
			}
			expression, ok := child.(*ast.CallExpr)
			if !ok || len(expression.Args) < 2 {
				return true
			}
			identifier, ok := expression.Args[0].(*ast.Ident)
			if !ok || identifier.Name != value.Name {
				return true
			}
			call := callFromAST(expression, file.Imports)
			base := callBase(call.Name)
			if base != "Handle" && base != "HandleFunc" || !serveMuxReceiver(call, expression, flow) {
				return true
			}
			for _, pattern := range patterns {
				if route, ok := routeFromPattern(filePath, symbol, pattern, routeHandlerName(expression)); ok {
					result = append(result, route)
				}
			}
			return true
		})
		return true
	})
	return result
}

type localClosure struct {
	literal    *ast.FuncLit
	source     types.Object
	definition token.Pos
	valid      bool
}

type localClosureBindings map[types.Object][]localClosure

func routesFromExecutedBody(filePath, symbol string, body *ast.BlockStmt, file goFileFact, flow *routeFlow) []routeFact {
	var result []routeFact
	closures := localClosures(body, flow.Info, flow)
	methods := localRouteMethods(body, flow.Info, flow)
	scheduled := scheduledClosureCalls(body, flow)
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !flow.positionReachable(call.Pos()) {
			return true
		}
		fact := callFromAST(call, file.Imports)
		if route, ok := routeFromCall(filePath, symbol, call, fact, flow); ok {
			result = append(result, route)
		} else if route, ok := routeFromMethodValue(filePath, symbol, call, flow, methods); ok {
			result = append(result, route)
		}
		literal, proven := invokedClosure(call, closures, flow)
		if !proven {
			return true
		}
		schedule := scheduled[call.Pos()]
		if schedule == closureUnproven {
			return true
		}
		child := nestedRouteFlow(literal, flow, call, file.Imports, schedule)
		result = append(result, routesFromExecutedBody(filePath, symbol, literal.Body, file, child)...)
		return true
	})
	return append(result, routesFromRanges(filePath, symbol, body, file, flow)...)
}

func scheduledClosureCalls(body *ast.BlockStmt, flow *routeFlow) map[token.Pos]closureSchedule {
	result := map[token.Pos]closureSchedule{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch statement := node.(type) {
		case *ast.GoStmt:
			if statement.Call != nil && flow.positionReachable(statement.Pos()) {
				result[statement.Call.Pos()] = closureGoroutine
				if goroutineCompletionProven(statement.Call, flow) {
					result[statement.Call.Pos()] = closureGoroutineWaited
				}
			}
		case *ast.DeferStmt:
			if statement.Call != nil && flow.positionReachable(statement.Pos()) {
				result[statement.Call.Pos()] = closureUnproven
				if flow.deferredExecutionProven(statement.Call.Pos()) {
					result[statement.Call.Pos()] = closureDeferred
				}
			}
		}
		return true
	})
	return result
}

func goroutineCompletionProven(call *ast.CallExpr, flow *routeFlow) bool {
	return len(goroutineCompletionSignals(call, flow)) > 0
}

func goroutineCompletionSignals(call *ast.CallExpr, flow *routeFlow) []completionSignal {
	literal, proven := invokedClosure(call, flow.closures, flow)
	if !proven {
		return nil
	}
	child := newNestedRouteFlow(literal.Body, flow.Info, flow.Imports, flow, call.Pos())
	signals := map[types.Object][]completionSignal{}
	guaranteedSends := map[types.Object]int{}
	guaranteedClose := map[types.Object]bool{}
	ast.Inspect(literal.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch candidate := node.(type) {
		case *ast.CallExpr:
			if !child.positionReachable(candidate.Pos()) || len(candidate.Args) != 1 {
				return true
			}
			identifier, ok := unwrapParen(candidate.Fun).(*ast.Ident)
			builtin, builtinOK := flow.Info.Uses[identifier].(*types.Builtin)
			argument, argumentOK := unwrapParen(candidate.Args[0]).(*ast.Ident)
			if !ok || !builtinOK || builtin.Name() != "close" || !argumentOK {
				return true
			}
			flowNode := child.nodeAt(candidate.Pos())
			_, deferred := child.Nodes[flowNode].Statement.(*ast.DeferStmt)
			object := objectForIdentifier(argument, flow.Info)
			if object != nil {
				signals[object] = append(signals[object], completionSignal{
					position: candidate.Pos(),
					deferred: deferred,
				})
				guaranteedClose[object] = guaranteedClose[object] || child.allEntryPathsReach(candidate.Pos()) &&
					(!deferred || child.deferredExecutionProven(candidate.Pos()))
			}
		case *ast.SendStmt:
			identifier, ok := unwrapParen(candidate.Chan).(*ast.Ident)
			if !ok || !child.positionReachable(candidate.Pos()) {
				return true
			}
			object := objectForIdentifier(identifier, flow.Info)
			if object != nil {
				signals[object] = append(signals[object], completionSignal{position: candidate.Pos()})
				if child.allEntryPathsReach(candidate.Pos()) {
					guaranteedSends[object]++
				}
			}
		}
		return true
	})
	if len(signals) == 0 {
		return nil
	}
	var completed []completionSignal
	consumed := map[types.Object]int{}
	ast.Inspect(flow.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		receive, ok := node.(*ast.UnaryExpr)
		if !ok || receive.Op != token.ARROW {
			return true
		}
		identifier, ok := unwrapParen(receive.X).(*ast.Ident)
		if !ok {
			return true
		}
		object := objectForIdentifier(identifier, flow.Info)
		available := signals[object]
		if len(available) == 0 || !guaranteedClose[object] && consumed[object] >= guaranteedSends[object] ||
			!flow.positionReachable(receive.Pos()) ||
			!flow.positionDominates(call.Pos(), receive.Pos()) || !flow.allPathsReach(call.Pos(), receive.Pos()) {
			return true
		}
		for _, signal := range available {
			signal.wait = receive.Pos()
			completed = append(completed, signal)
		}
		if !guaranteedClose[object] {
			consumed[object]++
		}
		return true
	})
	return completed
}

func nestedRouteFlow(literal *ast.FuncLit, parent *routeFlow, call *ast.CallExpr, imports map[string]string, schedule closureSchedule) *routeFlow {
	child := newNestedRouteFlow(literal.Body, parent.Info, imports, parent, call.Pos())
	child.schedule = schedule
	if schedule == closureGoroutineWaited {
		child.completionSignals = goroutineCompletionSignals(call, parent)
	}
	child.inputStates = map[types.Object]int{}
	if schedule == closureGoroutine || schedule == closureUnproven {
		return child
	}
	invoked, direct := invokedClosure(call, parent.closures, parent)
	if !direct || invoked != literal || literal.Type.Params == nil {
		return child
	}
	argument := 0
	for _, field := range literal.Type.Params.List {
		for _, name := range field.Names {
			state := receiverInvalid
			if argument < len(call.Args) && parent.provesServeMuxAt(call.Args[argument], call.Pos()) {
				state = receiverValid
			}
			if object := parent.Info.Defs[name]; object != nil {
				child.inputStates[object] = state
			}
			argument++
		}
	}
	return child
}

func localClosures(body *ast.BlockStmt, info *types.Info, flow *routeFlow) localClosureBindings {
	result := localClosureBindings{}
	record := func(object types.Object, right ast.Expr, definition token.Pos) {
		if object == nil || flow != nil && !flow.positionReachable(definition) {
			return
		}
		right = unwrapParen(right)
		binding := localClosure{definition: definition, valid: right != nil}
		switch value := right.(type) {
		case *ast.FuncLit:
			binding.literal = value
		case *ast.Ident:
			binding.source = objectForIdentifier(value, info)
			binding.valid = binding.source != nil
		default:
			binding.valid = false
		}
		result[object] = append(result[object], binding)
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || identifier.Name == "_" {
					continue
				}
				var right ast.Expr
				if index < len(value.Rhs) {
					right = value.Rhs[index]
				}
				record(objectForIdentifier(identifier, info), right, value.Pos())
			}
		case *ast.ValueSpec:
			for index, name := range value.Names {
				var right ast.Expr
				if index < len(value.Values) {
					right = value.Values[index]
				}
				record(info.Defs[name], right, value.Pos())
			}
		}
		return true
	})
	return result
}

func invokedClosure(call *ast.CallExpr, closures localClosureBindings, flow *routeFlow) (*ast.FuncLit, bool) {
	return closureFromExpression(call.Fun, closures, flow, call.Pos())
}

func closureFromExpression(expression ast.Expr, closures localClosureBindings, flow *routeFlow, use token.Pos) (*ast.FuncLit, bool) {
	expression = unwrapParen(expression)
	switch typed := expression.(type) {
	case *ast.FuncLit:
		return typed, true
	case *ast.CallExpr:
		if flow == nil {
			return nil, false
		}
		return flow.returnedFunctionLiteral(typed)
	}
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return nil, false
	}
	return resolveClosure(objectForIdentifier(identifier, flow.Info), closures, flow, use, map[types.Object]bool{})
}

func resolveClosure(object types.Object, closures localClosureBindings, flow *routeFlow, use token.Pos, seen map[types.Object]bool) (*ast.FuncLit, bool) {
	if object == nil || seen[object] {
		return nil, false
	}
	bindings := closures[object]
	definitions := make([]token.Pos, 0, len(bindings))
	for _, binding := range bindings {
		definitions = append(definitions, binding.definition)
	}
	var closure *localClosure
	for index := range bindings {
		if !flow.bindingReachesUse(bindings[index].definition, use, definitions) {
			continue
		}
		if closure != nil {
			return nil, false
		}
		closure = &bindings[index]
	}
	if closure == nil || !closure.valid {
		return nil, false
	}
	seen[object] = true
	if closure.literal != nil {
		return closure.literal, true
	}
	if closure.source == nil {
		return nil, false
	}
	return resolveClosure(closure.source, closures, flow, closure.definition, seen)
}

type localRouteMethod struct {
	receiver   ast.Expr
	method     string
	source     types.Object
	definition token.Pos
	valid      bool
}

type localRouteMethodBindings map[types.Object][]localRouteMethod

func localRouteMethods(body *ast.BlockStmt, info *types.Info, flow *routeFlow) localRouteMethodBindings {
	result := localRouteMethodBindings{}
	record := func(object types.Object, right ast.Expr, definition token.Pos) {
		if object == nil || flow != nil && !flow.positionReachable(definition) {
			return
		}
		right = unwrapParen(right)
		binding := localRouteMethod{definition: definition, valid: right != nil}
		switch value := right.(type) {
		case *ast.SelectorExpr:
			if value.Sel.Name != "Handle" && value.Sel.Name != "HandleFunc" {
				binding.valid = false
				break
			}
			binding.receiver = value.X
			binding.method = value.Sel.Name
		case *ast.Ident:
			binding.source = objectForIdentifier(value, info)
			binding.valid = binding.source != nil
		default:
			binding.valid = false
		}
		result[object] = append(result[object], binding)
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok || identifier.Name == "_" {
					continue
				}
				var right ast.Expr
				if index < len(value.Rhs) {
					right = value.Rhs[index]
				}
				record(objectForIdentifier(identifier, info), right, value.Pos())
			}
		case *ast.ValueSpec:
			for index, name := range value.Names {
				var right ast.Expr
				if index < len(value.Values) {
					right = value.Values[index]
				}
				record(info.Defs[name], right, value.Pos())
			}
		}
		return true
	})
	return result
}

func routeFromMethodValue(filePath, symbol string, call *ast.CallExpr, flow *routeFlow, methods localRouteMethodBindings) (routeFact, bool) {
	identifier, ok := unwrapParen(call.Fun).(*ast.Ident)
	if !ok || len(call.Args) < 2 {
		return routeFact{}, false
	}
	binding, ok := resolveRouteMethod(objectForIdentifier(identifier, flow.Info), methods, flow, call.Pos(), map[types.Object]bool{})
	if !ok || !flow.provesServeMuxAt(binding.receiver, binding.definition) {
		return routeFact{}, false
	}
	pattern, ok := constantString(call.Args[0])
	if !ok {
		return routeFact{}, false
	}
	return routeFromPattern(filePath, symbol, pattern, routeHandlerName(call))
}

func resolveRouteMethod(object types.Object, methods localRouteMethodBindings, flow *routeFlow, use token.Pos, seen map[types.Object]bool) (localRouteMethod, bool) {
	if object == nil || seen[object] {
		return localRouteMethod{}, false
	}
	bindings := methods[object]
	definitions := make([]token.Pos, 0, len(bindings))
	for _, binding := range bindings {
		definitions = append(definitions, binding.definition)
	}
	var selected *localRouteMethod
	for index := range bindings {
		if !flow.bindingReachesUse(bindings[index].definition, use, definitions) {
			continue
		}
		if selected != nil {
			return localRouteMethod{}, false
		}
		selected = &bindings[index]
	}
	if selected == nil || !selected.valid {
		return localRouteMethod{}, false
	}
	seen[object] = true
	if selected.receiver != nil {
		return *selected, true
	}
	if selected.source == nil {
		return localRouteMethod{}, false
	}
	return resolveRouteMethod(selected.source, methods, flow, selected.definition, seen)
}

func serveMuxReceiver(call callFact, expression *ast.CallExpr, flow *routeFlow) bool {
	return flow.provesServeMux(expression, call)
}

func importedCall(name, importPath, functionName string, imports map[string]string) bool {
	parts := strings.Split(name, ".")
	return len(parts) == 2 && parts[1] == functionName && imports[parts[0]] == importPath
}

func constantString(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func stringLiterals(expression ast.Expr) []string {
	var result []string
	ast.Inspect(expression, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		if decoded, err := strconv.Unquote(literal.Value); err == nil {
			result = append(result, decoded)
		}
		return true
	})
	return uniqueStrings(result)
}

func routeFromPattern(filePath, symbol, pattern, handler string) (routeFact, bool) {
	pattern = strings.TrimSpace(pattern)
	method := "*"
	routePath := pattern
	if fields := strings.Fields(pattern); len(fields) == 2 && strings.HasPrefix(fields[1], "/") {
		method, routePath = strings.ToUpper(fields[0]), fields[1]
	}
	if !strings.HasPrefix(routePath, "/") {
		return routeFact{}, false
	}
	return routeFact{Method: method, Path: routePath, Handler: handler, Symbol: symbol, File: filePath}, true
}

func routeHandlerName(expression *ast.CallExpr) string {
	if len(expression.Args) < 2 {
		return "handler"
	}
	handler := expression.Args[1]
	if wrapper, ok := handler.(*ast.CallExpr); ok && len(wrapper.Args) > 0 {
		return expressionName(wrapper.Args[0])
	}
	return expressionName(handler)
}

func tablesFromStrings(values []string) []string {
	var tables []string
	for _, value := range values {
		tables = append(tables, referencedSQLObjects(scanSQL([]byte(value)).tokens)...)
	}
	return uniqueStrings(tables)
}

func writtenTablesFromStrings(values []string) []string {
	var tables []string
	for _, value := range values {
		tables = append(tables, writtenSQLObjects(scanSQL([]byte(value)).tokens)...)
	}
	return uniqueStrings(tables)
}

func placeholderName(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "noop") || strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "inmemory") || strings.HasPrefix(lower, "mock")
}

func placeholderDependencyName(value string) bool {
	lower := strings.ToLower(value)
	return placeholderName(value) || strings.Contains(lower, "mock") || strings.Contains(lower, "fake") ||
		strings.Contains(lower, "stub") || strings.Contains(lower, "generated") || strings.Contains(lower, "memory")
}

func parseTextFact(path string, content []byte) textFact {
	clean := stripTextComments(content)
	result := textFact{Path: path, Active: activeClientPattern.Match(clean)}
	for _, route := range routePattern.FindAll(clean, -1) {
		result.Routes = append(result.Routes, string(route))
	}
	for _, word := range wordPattern.FindAll(clean, -1) {
		result.Words = append(result.Words, strings.ToLower(string(word)))
	}
	result.Routes = uniqueStrings(result.Routes)
	result.Words = uniqueStrings(result.Words)
	return result
}

func stripTextComments(content []byte) []byte {
	var output bytes.Buffer
	var quote byte
	escaped := false
	for index := 0; index < len(content); {
		current := content[index]
		if quote != 0 {
			output.WriteByte(current)
			index++
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
			} else if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' || current == '`' {
			quote = current
			output.WriteByte(current)
			index++
			continue
		}
		if current == '/' && index+1 < len(content) && content[index+1] == '/' {
			for index < len(content) && content[index] != '\n' {
				index++
			}
			continue
		}
		if current == '/' && index+1 < len(content) && content[index+1] == '*' {
			index += 2
			for index+1 < len(content) && (content[index] != '*' || content[index+1] != '/') {
				if content[index] == '\n' {
					output.WriteByte('\n')
				}
				index++
			}
			if index+1 < len(content) {
				index += 2
			}
			continue
		}
		if current == '#' {
			lineStart := index == 0 || content[index-1] == '\n'
			if lineStart {
				for index < len(content) && content[index] != '\n' {
					index++
				}
				continue
			}
		}
		output.WriteByte(current)
		index++
	}
	return output.Bytes()
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
