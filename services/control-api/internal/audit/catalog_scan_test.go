package audit

// Source scanner behind TestEventCatalogCoversProductionActions: it finds
// every audit.Event the control-api production code builds and resolves the
// Action expression to the set of strings it can take, using only go/parser
// (string literals, package constants, "+" concatenation, local assignments,
// function parameters traced to their call sites, and functions whose every
// return is resolvable). Expressions it cannot resolve (struct fields, values
// computed at run time) must be listed in dynamicActionSites.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const auditImportSuffix = "/services/control-api/internal/audit"

type scanFile struct {
	pkg       *scanPackage
	path      string // relative to control-api root
	file      *ast.File
	imports   map[string]string // local name -> import path
	auditName string            // local name of the audit package ("" if not imported)
}

type scanPackage struct {
	importPath string
	files      []*scanFile
	consts     map[string]constRef
	funcs      map[string][]funcRef
}

type constRef struct {
	file *scanFile
	expr ast.Expr
}

type funcRef struct {
	file *scanFile
	decl *ast.FuncDecl
}

// actionSite is one place production code sets audit.Event.Action.
type actionSite struct {
	Key      string // "<relative path>:<function>"
	Position string
	Values   []string
	Resolved bool
}

type actionScanner struct {
	fset     *token.FileSet
	packages map[string]*scanPackage
	visiting map[string]bool
}

func loadActionScanner(t *testing.T, root string) *actionScanner {
	t.Helper()
	modulePath := readModulePath(t, filepath.Join(root, "go.mod"))
	scanner := &actionScanner{fset: token.NewFileSet(), packages: map[string]*scanPackage{}, visiting: map[string]bool{}}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(scanner.fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if buildIgnored(parsed) {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		importPath := modulePath
		if dir := filepath.ToSlash(filepath.Dir(relative)); dir != "." {
			importPath += "/" + dir
		}
		pkg := scanner.packages[importPath]
		if pkg == nil {
			pkg = &scanPackage{importPath: importPath, consts: map[string]constRef{}, funcs: map[string][]funcRef{}}
			scanner.packages[importPath] = pkg
		}
		file := &scanFile{pkg: pkg, path: relative, file: parsed, imports: map[string]string{}}
		for _, spec := range parsed.Imports {
			value, _ := strconv.Unquote(spec.Path.Value)
			name := value[strings.LastIndex(value, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			file.imports[name] = value
			if strings.HasSuffix(value, auditImportSuffix) {
				file.auditName = name
			}
		}
		pkg.files = append(pkg.files, file)
		for _, decl := range parsed.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				if typed.Tok != token.CONST && typed.Tok != token.VAR {
					continue
				}
				for _, spec := range typed.Specs {
					value := spec.(*ast.ValueSpec)
					for index, name := range value.Names {
						if index < len(value.Values) {
							pkg.consts[name.Name] = constRef{file: file, expr: value.Values[index]}
						}
					}
				}
			case *ast.FuncDecl:
				pkg.funcs[typed.Name.Name] = append(pkg.funcs[typed.Name.Name], funcRef{file: file, decl: typed})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan control-api sources: %v", err)
	}
	return scanner
}

func buildIgnored(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:build") && strings.Contains(comment.Text, "ignore") {
				return true
			}
		}
	}
	return false
}

func readModulePath(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}

// sites returns every audit.Event Action site in production code.
func (scanner *actionScanner) sites() []actionSite {
	var sites []actionSite
	for _, pkg := range scanner.packages {
		for _, file := range pkg.files {
			for _, decl := range file.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				eventVars := map[string]bool{}
				addLiteral := func(literal *ast.CompositeLit) {
					for _, element := range literal.Elts {
						pair, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if key, isIdent := pair.Key.(*ast.Ident); isIdent && key.Name == "Action" {
							sites = append(sites, scanner.site(file, fn, pair.Value))
						}
					}
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					switch typed := node.(type) {
					case *ast.CompositeLit:
						if scanner.isEventType(file, typed.Type) {
							addLiteral(typed)
							return true
						}
						// []audit.Event{{...}} / map[K]audit.Event{k: {...}} elide the element type.
						var element ast.Expr
						switch container := typed.Type.(type) {
						case *ast.ArrayType:
							element = container.Elt
						case *ast.MapType:
							element = container.Value
						}
						if element == nil || !scanner.isEventType(file, element) {
							return true
						}
						for _, item := range typed.Elts {
							if pair, ok := item.(*ast.KeyValueExpr); ok {
								item = pair.Value
							}
							if inner, ok := item.(*ast.CompositeLit); ok && inner.Type == nil {
								addLiteral(inner)
							}
						}
					case *ast.ValueSpec:
						if scanner.isEventType(file, typed.Type) {
							for _, name := range typed.Names {
								eventVars[name.Name] = true
							}
						}
					case *ast.AssignStmt:
						for index, left := range typed.Lhs {
							selector, ok := left.(*ast.SelectorExpr)
							if !ok || selector.Sel.Name != "Action" || index >= len(typed.Rhs) {
								continue
							}
							if base, isIdent := selector.X.(*ast.Ident); isIdent && eventVars[base.Name] {
								sites = append(sites, scanner.site(file, fn, typed.Rhs[index]))
							}
						}
					}
					return true
				})
			}
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Position < sites[j].Position })
	return sites
}

func (scanner *actionScanner) isEventType(file *scanFile, expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if strings.HasSuffix(file.pkg.importPath, auditImportSuffix) {
		if ident, ok := expr.(*ast.Ident); ok && ident.Name == "Event" {
			return true
		}
	}
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || file.auditName == "" || selector.Sel.Name != "Event" {
		return false
	}
	base, ok := selector.X.(*ast.Ident)
	return ok && base.Name == file.auditName
}

func (scanner *actionScanner) site(file *scanFile, fn *ast.FuncDecl, expr ast.Expr) actionSite {
	position := scanner.fset.Position(expr.Pos())
	raw, ok := scanner.eval(file, fn, expr, 0)
	// `x := ""` placeholders reassigned later yield "" or "prefix."; they are
	// never written, so drop them.
	values := raw[:0]
	for _, value := range raw {
		if value != "" && !strings.HasSuffix(value, ".") {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return actionSite{
		Key:      file.path + ":" + fn.Name.Name,
		Position: file.path + ":" + strconv.Itoa(position.Line),
		Values:   uniqueStrings(values),
		Resolved: ok,
	}
}

const maxEvalDepth = 10

// eval resolves expr (inside fn of file) to every string it can hold.
func (scanner *actionScanner) eval(file *scanFile, fn *ast.FuncDecl, expr ast.Expr, depth int) ([]string, bool) {
	if depth > maxEvalDepth || expr == nil {
		return nil, false
	}
	switch typed := expr.(type) {
	case *ast.BasicLit:
		if typed.Kind != token.STRING {
			return nil, false
		}
		value, err := strconv.Unquote(typed.Value)
		return []string{value}, err == nil
	case *ast.ParenExpr:
		return scanner.eval(file, fn, typed.X, depth+1)
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return nil, false
		}
		left, ok := scanner.eval(file, fn, typed.X, depth+1)
		if !ok {
			return nil, false
		}
		right, ok := scanner.eval(file, fn, typed.Y, depth+1)
		if !ok {
			return nil, false
		}
		var joined []string
		for _, l := range left {
			for _, r := range right {
				joined = append(joined, l+r)
			}
		}
		return joined, true
	case *ast.CallExpr:
		return scanner.evalCall(file, fn, typed, depth)
	case *ast.Ident:
		return scanner.evalIdent(file, fn, typed.Name, depth)
	case *ast.SelectorExpr:
		base, ok := typed.X.(*ast.Ident)
		if !ok {
			return nil, false
		}
		importPath, ok := file.imports[base.Name]
		if !ok {
			return nil, false
		}
		pkg := scanner.packages[importPath]
		if pkg == nil {
			return nil, false
		}
		ref, ok := pkg.consts[typed.Sel.Name]
		if !ok {
			return nil, false
		}
		return scanner.eval(ref.file, nil, ref.expr, depth+1)
	}
	return nil, false
}

func (scanner *actionScanner) evalCall(file *scanFile, fn *ast.FuncDecl, call *ast.CallExpr, depth int) ([]string, bool) {
	// Conversions such as string(x) or Action(x).
	if len(call.Args) == 1 {
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "string" {
			return scanner.eval(file, fn, call.Args[0], depth+1)
		}
	}
	var name string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	default:
		return nil, false
	}
	refs := file.pkg.funcs[name]
	if len(refs) != 1 {
		return nil, false
	}
	callee := refs[0]
	key := "call:" + file.pkg.importPath + "." + name
	if scanner.visiting[key] {
		return nil, false
	}
	scanner.visiting[key] = true
	defer delete(scanner.visiting, key)
	var values []string
	found := false
	resolved := true
	ast.Inspect(callee.decl.Body, func(node ast.Node) bool {
		if _, isLiteral := node.(*ast.FuncLit); isLiteral {
			return false
		}
		ret, ok := node.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		found = true
		got, ok := scanner.eval(callee.file, callee.decl, ret.Results[0], depth+1)
		if !ok {
			resolved = false
		}
		values = append(values, got...)
		return true
	})
	return values, found && resolved
}

func (scanner *actionScanner) evalIdent(file *scanFile, fn *ast.FuncDecl, name string, depth int) ([]string, bool) {
	if fn != nil {
		var values []string
		assigned, resolved := false, true
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				if len(typed.Lhs) != len(typed.Rhs) {
					return true
				}
				for index, left := range typed.Lhs {
					if ident, ok := left.(*ast.Ident); ok && ident.Name == name {
						assigned = true
						got, ok := scanner.eval(file, fn, typed.Rhs[index], depth+1)
						resolved = resolved && ok
						values = append(values, got...)
					}
				}
			case *ast.ValueSpec:
				for index, ident := range typed.Names {
					if ident.Name == name && index < len(typed.Values) {
						assigned = true
						got, ok := scanner.eval(file, fn, typed.Values[index], depth+1)
						resolved = resolved && ok
						values = append(values, got...)
					}
				}
			}
			return true
		})
		if index, ok := paramIndex(fn, name); ok {
			got, ok := scanner.evalParam(file, fn, index, depth)
			return append(values, got...), ok && resolved
		}
		if assigned {
			return values, resolved
		}
	}
	if ref, ok := file.pkg.consts[name]; ok {
		return scanner.eval(ref.file, nil, ref.expr, depth+1)
	}
	return nil, false
}

func paramIndex(fn *ast.FuncDecl, name string) (int, bool) {
	index := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, ident := range field.Names {
			if ident.Name == name {
				return index, true
			}
			index++
		}
	}
	return 0, false
}

// evalParam resolves parameter index of fn from every call site: the same
// package for unexported functions, every package for exported ones.
func (scanner *actionScanner) evalParam(file *scanFile, fn *ast.FuncDecl, index, depth int) ([]string, bool) {
	key := "param:" + file.pkg.importPath + "." + fn.Name.Name + "#" + strconv.Itoa(index)
	if scanner.visiting[key] {
		return nil, true // recursive call passes the same parameter through
	}
	scanner.visiting[key] = true
	defer delete(scanner.visiting, key)
	packages := []*scanPackage{file.pkg}
	if ast.IsExported(fn.Name.Name) {
		packages = packages[:0]
		for _, pkg := range scanner.packages {
			packages = append(packages, pkg)
		}
	}
	var values []string
	calls, resolved := 0, true
	for _, pkg := range packages {
		for _, caller := range pkg.files {
			for _, decl := range caller.file.Decls {
				callerFn, ok := decl.(*ast.FuncDecl)
				if !ok || callerFn.Body == nil {
					continue
				}
				ast.Inspect(callerFn.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok || !callsFunction(caller, file.pkg, call, fn.Name.Name) {
						return true
					}
					if index >= len(call.Args) {
						return true
					}
					calls++
					got, ok := scanner.eval(caller, callerFn, call.Args[index], depth+1)
					resolved = resolved && ok
					values = append(values, got...)
					return true
				})
			}
		}
	}
	return values, calls > 0 && resolved
}

func callsFunction(caller *scanFile, target *scanPackage, call *ast.CallExpr, name string) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return caller.pkg == target && fun.Name == name
	case *ast.SelectorExpr:
		if fun.Sel.Name != name {
			return false
		}
		if base, ok := fun.X.(*ast.Ident); ok {
			if importPath, isImport := caller.imports[base.Name]; isImport {
				return importPath == target.importPath
			}
		}
		// Method call: only trust it inside the target package or for
		// exported methods (the receiver type is not checked).
		return caller.pkg == target || ast.IsExported(name)
	}
	return false
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func TestActionScannerInventory(t *testing.T) {
	if os.Getenv("AUDIT_ACTION_INVENTORY") == "" {
		t.Skip("set AUDIT_ACTION_INVENTORY=1 to print the action inventory")
	}
	scanner := loadActionScanner(t, filepath.Join("..", ".."))
	for _, site := range scanner.sites() {
		t.Logf("%s\t%s\t%v\t%s", site.Position, site.Key, site.Resolved, strings.Join(site.Values, ","))
	}
}
