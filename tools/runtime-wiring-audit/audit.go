package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type domainModel struct {
	Name     string
	Packages []string
	Prod     []goFileFact
	Tests    []goFileFact
}

type runtimeReference struct {
	File        string
	Symbol      string
	Call        callFact
	PackageName string
}

type migrationFact struct {
	Path               string
	Version            string
	Direction          string
	Owned              []string
	Uncertain          []string
	GlobalUnknown      bool
	LexicallyUncertain bool
	Embedded           bool
}

type migrationIndex struct {
	Files        []migrationFact
	RuntimeLoads bool
	RuntimeProof []string
}

type openAPIOperation struct {
	Path       string
	Method     string
	ID         string
	HasError   bool
	EvidenceID string
	Fragment   string
}

type openAPIDoc struct {
	Path       string
	Operations []openAPIOperation
	Refs       []string
	Document   map[string]any
	Content    []byte
	ParseError string
}

type repositoryFacts struct {
	Source           sourceIndex
	RuntimeProd      []goFileFact
	RuntimeTests     []goFileFact
	CentralRoutes    []routeFact
	CentralFunctions map[string]string
	CentralLive      bool
	Migrations       migrationIndex
	OpenAPI          []openAPIDoc
	Program          programIndex
}

var migrationNamePattern = regexp.MustCompile(`^([0-9]+)_(.+)\.(up|down)\.sql$`)

const canonicalOpenAPIRoot = "api/openapi/v1/control.yaml"

func auditRepository(root string) (report, error) {
	source, err := buildSourceIndex(root)
	if err != nil {
		return report{}, err
	}
	program := buildProgram(source)
	domains := discoverDomains(source.GoFiles)
	migrations, err := loadMigrations(source, program)
	if err != nil {
		return report{}, err
	}
	facts := repositoryFacts{
		Source:           source,
		Migrations:       migrations,
		OpenAPI:          source.OpenAPI,
		Program:          program,
		CentralFunctions: map[string]string{},
	}
	for _, file := range source.GoFiles {
		if isRuntimeRoot(file.Path) {
			if file.Test {
				facts.RuntimeTests = append(facts.RuntimeTests, file)
			} else {
				facts.RuntimeProd = append(facts.RuntimeProd, file)
			}
		}
		if !file.Test && strings.HasPrefix(file.Path, "services/control-api/internal/httpapi/") {
			facts.CentralRoutes = append(facts.CentralRoutes, file.Routes...)
			for _, function := range file.Functions {
				name := function.Name
				if index := strings.LastIndex(name, "."); index >= 0 {
					name = name[index+1:]
				}
				facts.CentralFunctions[strings.ToLower(name)] = file.Path
			}
		}
	}
	facts.CentralLive = centralRouterLive(facts.RuntimeProd, program)

	result := report{
		SchemaVersion:     schemaVersion,
		SnapshotSemantics: "snapshot-at-time",
		Scope: []string{
			"services/control-api/internal/*",
			"services/control-api/cmd/control-api",
			"services/control-api/migrations",
			canonicalOpenAPIRoot + " and reachable local OpenAPI refs",
			"apps/web/src",
			"scripts/*smoke* and tests/*e2e*",
		},
		SourceSHA256:     source.SourceSHA256,
		SourceManifest:   source.Manifest,
		RepositoryRoot:   root,
		ToolRoot:         root,
		StatusVocabulary: []status{statusPass, statusFail, statusUnknown, statusNotApplied},
		CheckOrder:       append([]string(nil), checkOrder...),
		Summary:          map[status]int{},
		ConflictFilters:  currentConflictFilters(),
	}
	for _, domain := range domains {
		domainResult := evaluateDomain(domain, facts)
		result.Domains = append(result.Domains, domainResult)
		for _, name := range checkOrder {
			result.Summary[domainResult.Checks[name].Status]++
		}
	}
	result.NextTasks = suggestTasks(result.Domains, result.ConflictFilters)
	return result, nil
}

func discoverDomains(files []goFileFact) []domainModel {
	directoryFiles := map[string][]goFileFact{}
	directories := map[string]bool{}
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "services/control-api/internal/") {
			continue
		}
		name := strings.TrimPrefix(file.PackageDir, "services/control-api/internal/")
		if name == "" {
			continue
		}
		directories[name] = true
		directoryFiles[name] = append(directoryFiles[name], file)
	}
	groups := map[string]*domainModel{}
	for directory := range directories {
		top := strings.Split(directory, "/")[0]
		name := domainRoot(top, directories)
		if groups[name] == nil {
			groups[name] = &domainModel{Name: name}
		}
		groups[name].Packages = append(groups[name].Packages, directory)
		for _, file := range directoryFiles[directory] {
			if file.Test {
				groups[name].Tests = append(groups[name].Tests, file)
			} else {
				groups[name].Prod = append(groups[name].Prod, file)
			}
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]domainModel, 0, len(names))
	for _, name := range names {
		group := groups[name]
		group.Packages = uniqueStrings(group.Packages)
		sort.Slice(group.Prod, func(i, j int) bool { return group.Prod[i].Path < group.Prod[j].Path })
		sort.Slice(group.Tests, func(i, j int) bool { return group.Tests[i].Path < group.Tests[j].Path })
		result = append(result, *group)
	}
	return result
}

func domainRoot(directory string, directories map[string]bool) string {
	for _, suffix := range []string{"context", "runtime", "worker", "source", "http"} {
		base := strings.TrimSuffix(directory, suffix)
		if base != directory && directories[base] {
			return base
		}
	}
	return directory
}

func evaluateDomain(domain domainModel, facts repositoryFacts) domainResult {
	result := domainResult{Name: domain.Name, Packages: domain.Packages, Checks: map[string]checkResult{}}
	fallback := domainEvidence(domain)
	prodReferences := referencesForDomain(domain, facts.RuntimeProd, facts.Program, true)
	testReferences := referencesForDomain(domain, facts.RuntimeTests, facts.Program, false)
	domainRoutes := routesForDomain(domain, facts)
	expectsHTTP := domainExpectsHTTP(domain, domainRoutes)
	workerEvidence := domainWorkerEvidence(domain)
	placeholderRuntime := placeholderRuntimeReferences(prodReferences, facts.Program)
	nilRuntime, unknownNilRuntime := nilRuntimeReferences(prodReferences, facts.Program)

	result.Checks["core_package"] = corePackageCheck(domain, fallback)
	result.Checks["postgres_repository"] = postgresCheck(domain, fallback)
	result.Checks["http_handler"] = handlerCheck(domain, domainRoutes, expectsHTTP, fallback)
	result.Checks["router_mount"] = routerMountCheck(domain, facts, domainRoutes, expectsHTTP, prodReferences, testReferences, fallback)
	result.Checks["runtime_dependency_wiring"] = runtimeWiringCheck(domain, prodReferences, testReferences, nilRuntime, unknownNilRuntime, placeholderRuntime, facts.Program, fallback)
	result.Checks["runtime_configuration"] = runtimeConfigurationCheck(domain, realRuntimeReferences(prodReferences, facts.Program), fallback)

	migrationUp, migrationDown, migrationHead := migrationChecks(domain, facts.Migrations, result.Checks["postgres_repository"], fallback)
	result.Checks["migration_up"] = migrationUp
	result.Checks["migration_down"] = migrationDown
	result.Checks["migration_runtime_head"] = migrationHead

	documents := documentsForDomain(domain, domainRoutes, facts.OpenAPI)
	openPath, openOperation, openError, openAggregation := openAPIChecks(documents, facts.OpenAPI, expectsHTTP, fallback)
	result.Checks["openapi_path"] = openPath
	result.Checks["openapi_operation"] = openOperation
	result.Checks["openapi_error"] = openError
	result.Checks["openapi_aggregation"] = openAggregation

	rbacPermission, rbacRecheck, rbacStringOnly := rbacChecks(domain, domainRoutes, facts.Program, fallback)
	result.Checks["rbac_permission"] = rbacPermission
	result.Checks["rbac_transactional_recheck"] = rbacRecheck
	result.Checks["idempotency"] = idempotencyCheck(domain, domainRoutes, facts.Program, fallback)
	result.Checks["audit"] = auditCheck(domain, domainRoutes, facts.Program, fallback)
	result.Checks["background_worker"] = backgroundWorkerCheck(domain, workerEvidence, prodReferences, facts.Program, fallback)
	result.Checks["outbox"] = outboxCheck(domain, result.Checks["background_worker"], fallback)
	result.Checks["frontend_api_consumer"] = frontendCheck(documents, domainRoutes, facts.Source.Frontend, expectsHTTP, fallback)
	result.Checks["smoke_e2e"] = smokeCheck(domain, documents, domainRoutes, facts.Source.Smoke, expectsHTTP, workerEvidence != "", fallback)

	for _, reference := range nilRuntime {
		result.Findings = append(result.Findings, finding{
			Code: "NIL_RUNTIME_DEPENDENCY", Evidence: referenceEvidence(reference),
			Detail: "生产运行时构造器传入 nil，不能视为依赖已接线。",
		})
	}
	for _, reference := range placeholderRuntime {
		result.Findings = append(result.Findings, finding{
			Code: "PLACEHOLDER_RUNTIME_DEFAULT", Evidence: referenceEvidence(reference),
			Detail: "生产运行时选择 Noop、placeholder、mock 或 in-memory 实现。",
		})
	}
	if expectsHTTP && len(prodReferences) == 0 && len(testReferences) > 0 {
		result.Findings = append(result.Findings, finding{
			Code: "TEST_ONLY_MOUNT", Evidence: referenceEvidence(testReferences[0]),
			Detail: "handler 仅在测试构造或挂载。",
		})
	}
	if rbacStringOnly != "" {
		result.Findings = append(result.Findings, finding{
			Code: "RBAC_STRING_ONLY", Evidence: rbacStringOnly,
			Detail: "权限字符串存在，但未找到生产授权调用。",
		})
	}
	if workerEvidence != "" && result.Checks["background_worker"].Status == statusFail {
		result.Findings = append(result.Findings, finding{
			Code: "WORKER_NOT_STARTED", Evidence: workerEvidence,
			Detail: "worker 已实现，但未证明由生产启动链启动并随 context/Close 关闭。",
		})
	}
	if len(documents) > 0 && result.Checks["http_handler"].Status != statusPass {
		result.Findings = append(result.Findings, finding{
			Code: "OPENAPI_ONLY", Evidence: documents[0].Path + "#document",
			Detail: "OpenAPI 文档存在，但没有生产 HTTP handler 证据。",
		})
	}
	for _, document := range documents {
		if result.Checks["openapi_aggregation"].Status == statusFail {
			result.Findings = append(result.Findings, finding{
				Code: "OPENAPI_NOT_AGGREGATED", Evidence: document.Path + "#document",
				Detail: "OpenAPI 片段未被聚合入口引用。",
			})
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Code == result.Findings[j].Code {
			return result.Findings[i].Evidence < result.Findings[j].Evidence
		}
		return result.Findings[i].Code < result.Findings[j].Code
	})
	result.Findings = uniqueFindings(result.Findings)
	for _, name := range checkOrder {
		check := result.Checks[name]
		check.Evidence = limitedEvidence(check.Evidence, fallback)
		result.Checks[name] = check
	}
	return result
}

func corePackageCheck(domain domainModel, fallback string) checkResult {
	var real []string
	for _, file := range domain.Prod {
		for _, symbol := range file.Symbols {
			if !placeholderName(symbol) {
				real = append(real, file.Path+"#"+symbol)
			}
		}
	}
	if len(real) > 0 {
		return checked(statusPass, real, "存在非测试、非占位的 Go 声明。")
	}
	if len(domain.Prod) == 0 && len(domain.Tests) > 0 {
		return checked(statusFail, []string{domain.Tests[0].Path + "#test-only-package"}, "仅测试文件存在。")
	}
	return checked(statusFail, []string{fallback}, "未找到可执行核心声明。")
}

func postgresCheck(domain domainModel, fallback string) checkResult {
	var evidence []string
	storeIntent := false
	for _, file := range domain.Prod {
		importsPGX := false
		for _, imported := range file.Imports {
			importsPGX = importsPGX || strings.Contains(imported, "jackc/pgx")
		}
		for _, symbol := range file.Symbols {
			lower := strings.ToLower(symbol)
			storeIntent = storeIntent || strings.Contains(lower, "repository") || strings.Contains(lower, "postgres")
		}
		if importsPGX && (len(file.Tables) > 0 || fileHasCall(file, "query", "exec", "begin")) {
			evidence = append(evidence, file.Path+"#postgres-calls")
		}
	}
	if len(evidence) > 0 {
		return checked(statusPass, evidence, "生产代码通过 pgx 执行数据库操作。")
	}
	if storeIntent {
		return checked(statusFail, []string{fallback}, "存在 store/repository 意图，但未找到生产 pgx 操作。")
	}
	return checked(statusNotApplied, []string{fallback}, "未发现该领域需要 PostgreSQL repository 的结构证据。")
}

func handlerCheck(domain domainModel, routes []routeFact, expects bool, fallback string) checkResult {
	var evidence []string
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			lower := strings.ToLower(function.Name)
			if strings.HasSuffix(lower, ".servehttp") || strings.HasSuffix(lower, ".handler") || lower == "newhandler" {
				evidence = append(evidence, file.Path+"#"+function.Name)
			}
		}
	}
	for _, route := range routes {
		evidence = append(evidence, routeEvidence(route))
	}
	if len(evidence) > 0 && len(routes) > 0 {
		return checked(statusPass, evidence, "生产 handler 与实际路由声明同时存在。")
	}
	if expects {
		return checked(statusFail, []string{fallback}, "存在 HTTP 意图，但没有可调用 handler 与路由声明的组合。")
	}
	return checked(statusNotApplied, []string{fallback}, "未发现 HTTP handler 意图。")
}

func routerMountCheck(domain domainModel, facts repositoryFacts, routes []routeFact, expects bool, prod, tests []runtimeReference, fallback string) checkResult {
	if !expects {
		return checked(statusNotApplied, []string{fallback}, "未发现 HTTP handler 意图。")
	}
	central := false
	var evidence []string
	for _, route := range routes {
		if strings.HasPrefix(route.File, "services/control-api/internal/httpapi/") {
			central = true
			evidence = append(evidence, routeEvidence(route))
		}
	}
	if central && facts.CentralLive {
		evidence = append(evidence, "services/control-api/cmd/control-api/main.go#httpapi.New.Handler")
		return checked(statusPass, evidence, "中心 router 路由已进入 cmd/control-api 生产 Handler。")
	}
	realProd := realRuntimeReferences(prod, facts.Program)
	realTests := realRuntimeReferences(tests, facts.Program)
	if len(realProd) > 0 {
		for _, reference := range realProd {
			for _, runtimeFile := range facts.RuntimeProd {
				if runtimeFile.Path != reference.File || !referenceMountsRoute(reference, runtimeFile) {
					continue
				}
				evidence = append(evidence, referenceEvidence(reference))
				for _, route := range runtimeFile.Routes {
					evidence = append(evidence, routeEvidence(route))
				}
			}
		}
		if len(evidence) > 0 {
			return checked(statusPass, evidence, "独立 handler 在同一生产运行根文件中构造并注册路由。")
		}
		return checked(statusFail, []string{referenceEvidence(realProd[0])}, "handler 在生产代码中构造，但没有同文件路由注册证据。")
	}
	if len(realTests) > 0 {
		return checked(statusFail, []string{referenceEvidence(realTests[0])}, "handler 仅在测试运行根出现。")
	}
	return checked(statusFail, []string{fallback}, "handler 未挂载到 cmd/control-api 或已挂载中心 router。")
}

func runtimeWiringCheck(domain domainModel, prod, tests, nilRefs, unknownNilRefs, placeholderRefs []runtimeReference, program programIndex, fallback string) checkResult {
	if len(nilRefs) > 0 {
		return checked(statusFail, []string{referenceEvidence(nilRefs[0])}, "生产构造器含 nil 依赖。")
	}
	if len(placeholderRefs) > 0 {
		return checked(statusFail, []string{referenceEvidence(placeholderRefs[0])}, "生产默认依赖为 Noop/placeholder/mock/in-memory。")
	}
	if len(unknownNilRefs) > 0 {
		return checked(statusUnknown, []string{referenceEvidence(unknownNilRefs[0])}, "nil 参数的 callee 默认语义无法静态证明。")
	}
	realProd := realRuntimeReferences(prod, program)
	realTests := realRuntimeReferences(tests, program)
	if len(realProd) > 0 {
		var evidence []string
		for _, reference := range realProd {
			evidence = append(evidence, referenceEvidence(reference))
		}
		return checked(statusPass, evidence, "领域 constructor/handler/worker 由可达生产入口构造或启动。")
	}
	if len(realTests) > 0 {
		return checked(statusFail, []string{referenceEvidence(realTests[0])}, "依赖仅在测试构造。")
	}
	if domainHasRuntimeIntent(domain) {
		return checked(statusFail, []string{fallback}, "核心构造器/handler/worker 存在，但生产运行根没有引用。")
	}
	if len(prod) > 0 {
		return checked(statusFail, []string{referenceEvidence(prod[0])}, "生产入口只引用领域符号，未构造 constructor/handler/worker。")
	}
	return checked(statusUnknown, []string{fallback}, "未能证明该库包需要独立运行时接线。")
}

func realRuntimeReferences(references []runtimeReference, program programIndex) []runtimeReference {
	var result []runtimeReference
	for _, reference := range references {
		if runtimeReferenceIsConstruction(reference, program) {
			result = append(result, reference)
		}
	}
	return result
}

func runtimeReferenceIsConstruction(reference runtimeReference, program programIndex) bool {
	if runtimeConstructionCall(reference.Call.Name) {
		return true
	}
	caller := program.Nodes[functionKey(reference.File, reference.Symbol)]
	for _, target := range program.resolveCall(caller, reference.Call) {
		targetNode := program.Nodes[target]
		if len(targetNode.Function.Results) == 0 {
			continue
		}
		packageDir, resultType := typeLocation(targetNode.File, targetNode.Function.Results[0])
		if packageDir == "services/control-api/internal/"+reference.PackageName && !primitiveType(resultType) {
			return true
		}
	}
	return false
}

func primitiveType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "bool", "byte", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64",
		"rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "interface", "func":
		return true
	default:
		return strings.HasPrefix(value, "[]") || strings.HasPrefix(value, "map[")
	}
}

func runtimeConstructionCall(name string) bool {
	base := callBase(name)
	return strings.HasPrefix(base, "New") || strings.HasPrefix(base, "Open") || strings.HasPrefix(base, "Build") ||
		base == "Handler" || base == "Run" || base == "Start" || base == "Serve"
}

func runtimeConfigurationCheck(domain domainModel, references []runtimeReference, fallback string) checkResult {
	hasConfig := false
	for _, file := range domain.Prod {
		for _, symbol := range file.Symbols {
			hasConfig = hasConfig || symbol == "Config" || strings.HasSuffix(symbol, "Config")
		}
	}
	if !hasConfig {
		return checked(statusNotApplied, []string{fallback}, "领域未声明运行配置类型。")
	}
	for _, reference := range references {
		if reference.Call.ConfigArg {
			return checked(statusPass, []string{referenceEvidence(reference)}, "生产构造器接收 cfg/config 参数或配置值。")
		}
	}
	if len(references) > 0 {
		return checked(statusFail, []string{referenceEvidence(references[0])}, "运行时引用存在，但未证明领域配置被传入。")
	}
	return checked(statusFail, []string{fallback}, "配置类型未接入生产运行根。")
}

func migrationChecks(domain domainModel, migrations migrationIndex, postgres checkResult, fallback string) (checkResult, checkResult, checkResult) {
	ownedTables := domainWrittenTables(domain)
	ownedVersions := map[string]bool{}
	covered := map[string]bool{}
	uncertainObjects := map[string][]string{}
	var lexicalUncertain, globalUncertain []string
	for _, migration := range migrations.Files {
		if migration.Direction != "up" {
			continue
		}
		evidence := migration.Path + "#migration:" + migration.Version + ":up:ownership-unknown"
		hasOwned := false
		for _, table := range ownedTables {
			if containsString(migration.Owned, table) {
				covered[table] = true
				hasOwned = true
			}
			if containsString(migration.Uncertain, table) {
				uncertainObjects[table] = append(uncertainObjects[table], evidence)
				if migration.LexicallyUncertain {
					lexicalUncertain = append(lexicalUncertain, evidence)
				}
			}
		}
		if hasOwned {
			ownedVersions[migration.Version] = true
		}
		if migration.GlobalUnknown && (hasOwned || intersects(ownedTables, migration.Uncertain)) {
			globalUncertain = append(globalUncertain, evidence)
		}
	}
	var uncovered []string
	for _, table := range ownedTables {
		if !covered[table] {
			uncovered = append(uncovered, table)
		}
	}
	uncertain := append([]string(nil), lexicalUncertain...)
	for _, table := range uncovered {
		uncertain = append(uncertain, uncertainObjects[table]...)
	}
	if len(uncovered) > 0 {
		uncertain = append(uncertain, globalUncertain...)
	}
	if len(uncertain) > 0 {
		unknown := checked(statusUnknown, uncertain, "DO/dynamic SQL 无法静态证明领域对象 ownership。")
		return unknown, unknown, unknown
	}
	var candidates []migrationFact
	for _, migration := range migrations.Files {
		if ownedVersions[migration.Version] {
			candidates = append(candidates, migration)
		}
	}
	if len(candidates) == 0 {
		if postgres.Status == statusPass {
			failed := checked(statusFail, []string{fallback}, "repository 使用表，但未匹配到领域迁移。")
			return failed, failed, failed
		}
		na := checked(statusNotApplied, []string{fallback}, "未发现 PostgreSQL repository 或领域迁移。")
		return na, na, na
	}
	var up, down, head []string
	versionsUp := map[string]bool{}
	versionsDown := map[string]bool{}
	headOK := migrations.RuntimeLoads
	for _, candidate := range candidates {
		evidence := candidate.Path + "#migration:" + candidate.Version + ":" + candidate.Direction
		if candidate.Direction == "up" {
			up = append(up, evidence)
			versionsUp[candidate.Version] = true
			headOK = headOK && candidate.Embedded
			if candidate.Embedded {
				head = append(head, evidence)
			}
		} else {
			down = append(down, evidence)
			versionsDown[candidate.Version] = true
		}
	}
	upResult := checked(statusPass, up, "匹配到领域 up 迁移。")
	if len(up) == 0 {
		upResult = checked(statusFail, append(down, fallback), "只找到 down 迁移或未找到 up 迁移。")
	}
	downOK := len(versionsUp) > 0
	for version := range versionsUp {
		downOK = downOK && versionsDown[version]
	}
	downResult := checked(statusPass, down, "每个匹配 up 迁移都有同版本 down。")
	if !downOK {
		downResult = checked(statusFail, append(up, down...), "up/down 迁移版本不成对。")
	}
	head = append(head, migrations.RuntimeProof...)
	headResult := checked(statusPass, head, "匹配 up 迁移已被 embed，且生产迁移器加载 migrations.FS。")
	if !headOK || len(up) == 0 {
		headResult = checked(statusFail, append(up, head...), "迁移未同时进入 embed glob 与生产 current-head 加载链。")
	}
	return upResult, downResult, headResult
}

func openAPIChecks(documents, all []openAPIDoc, expectsHTTP bool, fallback string) (checkResult, checkResult, checkResult, checkResult) {
	if len(documents) == 0 {
		if expectsHTTP {
			failed := checked(statusFail, []string{fallback}, "HTTP handler 存在，但没有匹配 OpenAPI 文档。")
			return failed, failed, failed, failed
		}
		na := checked(statusNotApplied, []string{fallback}, "未发现 HTTP/OpenAPI 意图。")
		return na, na, na, na
	}
	var paths, operations, errorsEvidence, aggregation []string
	operationOK := true
	errorOK := true
	aggregationOK := true
	for _, document := range documents {
		if document.ParseError != "" || len(document.Operations) == 0 {
			operationOK = false
			errorOK = false
		}
		seenPath := map[string]bool{}
		for _, operation := range document.Operations {
			seenPath[operation.Path] = true
			if operation.ID == "" {
				operationOK = false
			} else {
				operations = append(operations, document.Path+"#operation:"+operation.ID)
			}
			if !operation.HasError {
				errorOK = false
			} else {
				errorsEvidence = append(errorsEvidence, document.Path+"#error:"+operation.EvidenceID)
			}
			if referencedByAggregator(document.Path, operation.Fragment, all) {
				aggregation = append(aggregation, document.Path+"#operation:"+operation.ID)
			} else {
				aggregationOK = false
			}
		}
		for routePath := range seenPath {
			paths = append(paths, document.Path+"#path:"+routePath)
		}
	}
	pathResult := checked(statusPass, paths, "OpenAPI 包含至少一个 path。")
	if len(paths) == 0 {
		pathResult = checked(statusFail, []string{documents[0].Path + "#paths"}, "OpenAPI 未声明 path。")
	}
	operationResult := checked(statusPass, operations, "所有已解析操作都有 operationId。")
	if !operationOK {
		operationResult = checked(statusFail, append(operations, documents[0].Path+"#operations"), "至少一个操作缺少 operationId 或文档不可解析。")
	}
	errorResult := checked(statusPass, errorsEvidence, "所有已解析操作都有结构化非 2xx 响应。")
	if !errorOK {
		errorResult = checked(statusFail, append(errorsEvidence, documents[0].Path+"#responses"), "至少一个操作缺少结构化错误响应。")
	}
	aggregationResult := checked(statusPass, aggregation, "领域 OpenAPI operation 可从权威根的 fragment 引用图到达。")
	if !aggregationOK {
		aggregationResult = checked(statusFail, append(aggregation, documents[0].Path+"#operations"), "至少一个 OpenAPI operation 不可从权威根的 fragment 引用图到达。")
	}
	return pathResult, operationResult, errorResult, aggregationResult
}

func rbacChecks(domain domainModel, routes []routeFact, program programIndex, fallback string) (checkResult, checkResult, string) {
	var permissionStrings []string
	var authorization []string
	var transactional []string
	rbacIntent := false
	reachable := program.domainReachable(domain, routes)
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			for _, value := range function.Strings {
				if permissionLiteral(value) {
					permissionStrings = append(permissionStrings, file.Path+"#"+function.Name)
				}
			}
			key := functionKey(file.Path, function.Name)
			if !reachable[key] {
				continue
			}
			node := program.Nodes[key]
			for _, call := range function.Calls {
				if !authorizationCall(call.Name) {
					continue
				}
				evidence := file.Path + "#" + function.Name + "->" + call.Name
				authorization = append(authorization, evidence)
				if callUsesIdentifier(call, "tx") && (call.InTransaction || functionHasTxParameter(function)) &&
					authorizationIsDatabaseBacked(domain, node, call, program) {
					transactional = append(transactional, evidence)
				}
			}
		}
		for _, symbol := range file.Symbols {
			base := symbol
			if index := strings.LastIndex(base, "."); index >= 0 {
				base = base[index+1:]
			}
			lower := strings.ToLower(base)
			rbacIntent = rbacIntent || strings.Contains(lower, "permission")
			if (strings.HasPrefix(lower, "permission") || strings.HasSuffix(lower, "permission")) &&
				!strings.Contains(lower, "denied") && !strings.HasPrefix(lower, "err") {
				permissionStrings = append(permissionStrings, file.Path+"#"+symbol)
			}
		}
	}
	permissionStrings = uniqueStrings(permissionStrings)
	if len(authorization) == 0 {
		if len(permissionStrings) > 0 {
			failed := checked(statusFail, permissionStrings, "只找到权限字符串/声明，没有生产授权调用。")
			return failed, checked(statusFail, permissionStrings, "没有授权调用，无法证明事务内重检。"), permissionStrings[0]
		}
		if rbacIntent {
			failed := checked(statusFail, []string{fallback}, "存在权限拒绝/RBAC 意图，但没有生产授权调用。")
			return failed, checked(statusFail, []string{fallback}, "存在 RBAC 意图，但没有事务内授权复验。"), ""
		}
		na := checked(statusNotApplied, []string{fallback}, "未发现该领域声明 RBAC 权限。")
		return na, na, ""
	}
	permission := checked(statusPass, authorization, "HTTP 路由可达的生产代码执行权限授权调用。")
	if len(transactional) == 0 {
		return permission, checked(statusFail, authorization, "授权存在，但未证明写事务内再次校验。"), ""
	}
	return permission, checked(statusPass, transactional, "写路径在数据库事务中调用携带 tx 的授权复验，且授权实现查询数据库。"), ""
}

func idempotencyCheck(domain domainModel, routes []routeFact, program programIndex, fallback string) checkResult {
	if !hasMutationRoute(routes) {
		return checked(statusNotApplied, []string{fallback}, "未发现 HTTP 写操作。")
	}
	var transport, persistence []string
	reachable := program.domainReachable(domain, routes)
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			key := functionKey(file.Path, function.Name)
			if !reachable[key] {
				continue
			}
			for _, call := range function.Calls {
				if strings.EqualFold(callBase(call.Name), "Get") && containsFold(call.StringArgs, "Idempotency-Key") &&
					strings.Contains(strings.ToLower(call.Receiver), "header") {
					transport = append(transport, file.Path+"#"+function.Name+"->"+call.Name)
				}
			}
			if functionHasPersistentIdempotency(function) {
				persistence = append(persistence, file.Path+"#"+function.Name+"->transactional-idempotency")
			}
		}
	}
	if len(transport) > 0 && len(persistence) > 0 {
		return checked(statusPass, append(transport, persistence...), "同一 HTTP 写入口可达 header 读取与事务持久化幂等事实。")
	}
	return checked(statusFail, append(append(transport, persistence...), fallback), "HTTP 写操作缺少传输层 key 或持久化幂等证据。")
}

func auditCheck(domain domainModel, routes []routeFact, program programIndex, fallback string) checkResult {
	if !hasMutationRoute(routes) {
		return checked(statusNotApplied, []string{fallback}, "未发现 HTTP 写操作。")
	}
	var transport, persistence []string
	reachable := program.domainReachable(domain, routes)
	for _, file := range domain.Prod {
		auditAlias := ""
		for alias, imported := range file.Imports {
			if strings.HasSuffix(imported, "/internal/audit") {
				auditAlias = alias
			}
		}
		for _, function := range file.Functions {
			if !reachable[functionKey(file.Path, function.Name)] {
				continue
			}
			for _, call := range function.Calls {
				if strings.EqualFold(callBase(call.Name), "Get") && strings.Contains(strings.ToLower(call.Receiver), "header") &&
					(containsFold(call.StringArgs, "Idempotency-Key") || containsFold(call.StringArgs, "X-Request-ID") ||
						containsFold(call.StringArgs, "X-Trace-ID") || containsFold(call.StringArgs, "Traceparent")) {
					transport = append(transport, file.Path+"#"+function.Name+"->"+call.Name)
				}
				base := strings.ToLower(callBase(call.Name))
				receiver := strings.ToLower(call.Receiver)
				isAudit := auditAlias != "" && call.PackageAlias == auditAlias && base == "append" ||
					(strings.Contains(receiver, "audit") && (base == "append" || base == "record" || base == "write"))
				if isAudit && callUsesIdentifier(call, "tx") && (call.InTransaction || functionHasTxParameter(function)) {
					persistence = append(persistence, file.Path+"#"+function.Name+"->"+call.Name)
				}
			}
		}
	}
	if len(transport) > 0 && len(persistence) > 0 {
		return checked(statusPass, append(transport, persistence...), "同一 HTTP 写入口可达请求元数据 header 与事务内 audit 持久化调用。")
	}
	return checked(statusFail, append(append(transport, persistence...), fallback), "HTTP 写操作未形成请求元数据 header 到事务 audit 的可达链。")
}

func backgroundWorkerCheck(domain domainModel, worker string, references []runtimeReference, program programIndex, fallback string) checkResult {
	if worker == "" {
		return checked(statusNotApplied, []string{fallback}, "未发现 Worker/Run/Start 实现。")
	}
	packageSet := map[string]bool{}
	for _, packageName := range domain.Packages {
		packageSet["services/control-api/internal/"+packageName] = true
	}
	for _, key := range sortedFunctionKeys(program.Reachable) {
		node := program.Nodes[key]
		if !isRuntimeRoot(node.File.Path) || !functionHasControlledLifecycle(node.Function) {
			continue
		}
		for _, call := range node.Function.Calls {
			if !call.Async || !program.callRunsWorker(node, call) {
				continue
			}
			for _, origin := range program.asyncCallOrigins(node, call) {
				if packageSet[origin] {
					return checked(statusPass, []string{worker, node.File.Path + "#" + node.Function.Name + "->go:" + call.Name},
						"worker 由生产 goroutine 启动，并受 context 与 WaitGroup/errgroup 关闭等待控制。")
				}
			}
		}
	}
	return checked(statusFail, []string{worker}, "worker 未在生产运行根启动。")
}

func outboxCheck(domain domainModel, worker checkResult, fallback string) checkResult {
	var evidence []string
	for _, file := range domain.Prod {
		for _, table := range file.Tables {
			if strings.Contains(table, "outbox") {
				evidence = append(evidence, file.Path+"#table:"+table)
			}
		}
		for _, symbol := range file.Symbols {
			if strings.Contains(strings.ToLower(symbol), "outbox") {
				evidence = append(evidence, file.Path+"#"+symbol)
			}
		}
	}
	if len(evidence) == 0 {
		return checked(statusNotApplied, []string{fallback}, "未发现 outbox 实现。")
	}
	if worker.Status != statusPass {
		return checked(statusFail, evidence, "outbox 存在，但没有已启动 worker 的证据。")
	}
	return checked(statusPass, evidence, "outbox 与已启动 worker 同时存在。")
}

func frontendCheck(documents []openAPIDoc, routes []routeFact, frontend []textFact, expects bool, fallback string) checkResult {
	targets := routeTargets(documents, routes)
	if len(targets) == 0 {
		if expects {
			return checked(statusFail, []string{fallback}, "HTTP 意图存在，但没有可匹配 API path。")
		}
		return checked(statusNotApplied, []string{fallback}, "未发现 API path。")
	}
	var evidence []string
	for _, file := range frontend {
		if !file.Active {
			continue
		}
		for _, candidate := range file.Routes {
			if routeMatchesAny(candidate, targets) {
				evidence = append(evidence, file.Path+"#api-call:"+routePrefix(candidate))
			}
		}
	}
	if len(evidence) > 0 {
		return checked(statusPass, evidence, "非测试前端代码调用匹配 API path。")
	}
	return checked(statusFail, []string{fallback}, "API path 没有非测试前端 consumer。")
}

func smokeCheck(domain domainModel, documents []openAPIDoc, routes []routeFact, smoke []textFact, expectsHTTP, expectsWorker bool, fallback string) checkResult {
	if !expectsHTTP && !expectsWorker {
		return checked(statusNotApplied, []string{fallback}, "未发现需要 smoke/e2e 的 HTTP 或 worker 入口。")
	}
	targets := routeTargets(documents, routes)
	tokens := []string{strings.ToLower(domain.Name)}
	for _, packageName := range domain.Packages {
		tokens = append(tokens, strings.ToLower(packageName))
	}
	var evidence []string
	for _, file := range smoke {
		if !file.Active {
			continue
		}
		matched := false
		for _, route := range file.Routes {
			matched = matched || routeMatchesAny(route, targets)
		}
		for _, token := range tokens {
			matched = matched || containsString(file.Words, token)
		}
		if matched {
			evidence = append(evidence, file.Path+"#runtime-command")
		}
	}
	if len(evidence) > 0 {
		return checked(statusPass, evidence, "独立 smoke/e2e 执行入口覆盖该领域。")
	}
	return checked(statusFail, []string{fallback}, "包内测试不计入；未找到独立 smoke/e2e 执行入口。")
}

func checked(value status, evidence []string, reason string) checkResult {
	return checkResult{Status: value, Evidence: uniqueStrings(evidence), Reason: reason}
}

func limitedEvidence(evidence []string, fallback string) []string {
	evidence = uniqueStrings(evidence)
	if len(evidence) == 0 {
		evidence = []string{fallback}
	}
	if len(evidence) > 8 {
		evidence = evidence[:8]
	}
	return evidence
}

func domainEvidence(domain domainModel) string {
	if len(domain.Prod) > 0 {
		return domain.Prod[0].Path + "#package:" + domain.Prod[0].Package
	}
	if len(domain.Tests) > 0 {
		return domain.Tests[0].Path + "#package:" + domain.Tests[0].Package
	}
	return "services/control-api/internal/" + domain.Name + "#package:" + domain.Name
}

func isRuntimeRoot(path string) bool {
	return strings.HasPrefix(path, "services/control-api/cmd/control-api/") ||
		strings.HasPrefix(path, "services/control-api/internal/httpapi/")
}

func centralRouterLive(files []goFileFact, program programIndex) bool {
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "services/control-api/cmd/control-api/") {
			continue
		}
		alias := aliasForImport(file, "/internal/httpapi")
		for _, function := range file.Functions {
			if !program.Reachable[functionKey(file.Path, function.Name)] {
				continue
			}
			hasNew := false
			hasHandler := false
			for _, call := range function.Calls {
				hasNew = hasNew || alias != "" && call.PackageAlias == alias && strings.HasSuffix(call.Name, ".New")
				hasHandler = hasHandler || strings.HasSuffix(call.Name, ".Handler")
			}
			if hasNew && hasHandler {
				return true
			}
		}
	}
	return false
}

func referenceMountsRoute(reference runtimeReference, file goFileFact) bool {
	var variables []string
	for _, function := range file.Functions {
		if function.Name != reference.Symbol {
			continue
		}
		for variable, binding := range function.Bindings {
			if binding.Call && binding.Name == reference.Call.Name {
				variables = append(variables, variable)
			}
		}
	}
	for _, route := range file.Routes {
		if route.Symbol != reference.Symbol {
			continue
		}
		if strings.Contains(route.Handler, reference.Call.Name) {
			return true
		}
		for _, variable := range variables {
			if route.Handler == variable || strings.HasPrefix(route.Handler, variable+".") {
				return true
			}
		}
	}
	return false
}

func referencesForDomain(domain domainModel, files []goFileFact, program programIndex, requireReachable bool) []runtimeReference {
	packageSet := map[string]bool{}
	for _, name := range domain.Packages {
		packageSet[name] = true
	}
	var result []runtimeReference
	for _, file := range files {
		aliases := map[string]string{}
		for alias, imported := range file.Imports {
			marker := "/services/control-api/internal/"
			if index := strings.Index(imported, marker); index >= 0 {
				packageName := strings.TrimPrefix(imported[index:], marker)
				if packageSet[packageName] {
					aliases[alias] = packageName
				}
			}
		}
		for _, function := range file.Functions {
			if requireReachable && !program.Reachable[functionKey(file.Path, function.Name)] {
				continue
			}
			for _, call := range function.Calls {
				if packageName, ok := aliases[call.PackageAlias]; ok {
					result = append(result, runtimeReference{File: file.Path, Symbol: function.Name, Call: call, PackageName: packageName})
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return referenceEvidence(result[i]) < referenceEvidence(result[j]) })
	return result
}

func aliasForImport(file goFileFact, suffix string) string {
	for alias, imported := range file.Imports {
		if strings.HasSuffix(imported, suffix) {
			return alias
		}
	}
	return ""
}

func referenceEvidence(reference runtimeReference) string {
	return reference.File + "#" + reference.Symbol + "->" + reference.Call.Name
}

func nilRuntimeReferences(references []runtimeReference, program programIndex) ([]runtimeReference, []runtimeReference) {
	var failed, unknown []runtimeReference
	for _, reference := range references {
		if !runtimeReferenceIsConstruction(reference, program) {
			continue
		}
		node := program.Nodes[functionKey(reference.File, reference.Symbol)]
		for index, argument := range reference.Call.Arguments {
			nilRisk, _ := program.argumentRisk(node, argument)
			if !nilRisk {
				continue
			}
			switch nilArgumentDisposition(node, reference.Call, index, program) {
			case statusFail:
				failed = append(failed, reference)
			case statusUnknown:
				unknown = append(unknown, reference)
			}
			break
		}
	}
	return failed, unknown
}

func nilArgumentDisposition(caller functionNode, call callFact, argumentIndex int, program programIndex) status {
	targets := program.resolveCall(caller, call)
	if len(targets) == 0 {
		return statusUnknown
	}
	allSafe := true
	allUnsafe := true
	for _, target := range targets {
		function := program.Nodes[target].Function
		if argumentIndex >= len(function.ParameterOrder) {
			return statusUnknown
		}
		safe := containsString(function.NilDefaultParameters, function.ParameterOrder[argumentIndex])
		allSafe = allSafe && safe
		allUnsafe = allUnsafe && !safe
	}
	if allSafe {
		return statusPass
	}
	if allUnsafe {
		return statusFail
	}
	return statusUnknown
}

func placeholderRuntimeReferences(references []runtimeReference, program programIndex) []runtimeReference {
	var result []runtimeReference
	for _, reference := range references {
		if !runtimeReferenceIsConstruction(reference, program) {
			continue
		}
		placeholder := placeholderDependencyName(reference.Call.Name)
		node := program.Nodes[functionKey(reference.File, reference.Symbol)]
		for _, argument := range reference.Call.Arguments {
			_, argumentPlaceholder := program.argumentRisk(node, argument)
			placeholder = placeholder || argumentPlaceholder
		}
		if placeholder {
			result = append(result, reference)
		}
	}
	return result
}

func constructorCall(name string) bool {
	base := name
	if index := strings.LastIndex(base, "."); index >= 0 {
		base = base[index+1:]
	}
	return strings.HasPrefix(base, "New") || strings.HasPrefix(base, "Open") || strings.HasPrefix(base, "Build")
}

func domainHasRuntimeIntent(domain domainModel) bool {
	for _, packageName := range domain.Packages {
		if strings.HasSuffix(packageName, "http") || strings.HasSuffix(packageName, "worker") || strings.HasSuffix(packageName, "runtime") {
			return true
		}
	}
	for _, file := range domain.Prod {
		for _, symbol := range file.Symbols {
			if constructorCall(symbol) || strings.HasSuffix(symbol, ".Run") || strings.HasSuffix(symbol, ".ServeHTTP") {
				return true
			}
		}
	}
	return false
}

func routesForDomain(domain domainModel, facts repositoryFacts) []routeFact {
	var result []routeFact
	for _, file := range domain.Prod {
		result = append(result, file.Routes...)
	}
	for _, route := range facts.CentralRoutes {
		if centralRouteReachesDomain(route, domain, facts.Program) {
			result = append(result, route)
			continue
		}
		handler := strings.ToLower(route.Handler)
		if index := strings.LastIndex(handler, "."); index >= 0 {
			handler = handler[index+1:]
		}
		functionFile := facts.CentralFunctions[handler]
		for _, candidate := range append([]string{domain.Name}, domain.Packages...) {
			token := normalize(candidate)
			if token == "" {
				continue
			}
			if strings.Contains(normalize(route.Path), token) || strings.Contains(normalize(route.Handler), token) ||
				strings.Contains(normalize(filepath.Base(functionFile)), token) {
				result = append(result, route)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return routeEvidence(result[i]) < routeEvidence(result[j]) })
	return uniqueRoutes(result)
}

func centralRouteReachesDomain(route routeFact, domain domainModel, program programIndex) bool {
	registration := program.Nodes[functionKey(route.File, route.Symbol)]
	if registration.Key == "" {
		return false
	}
	domainDirs := map[string]bool{}
	for _, packageName := range domain.Packages {
		domainDirs["services/control-api/internal/"+packageName] = true
	}
	handlers := program.resolveName(registration, route.Handler)
	for key := range program.reachableFrom(handlers) {
		node := program.Nodes[key]
		if domainDirs[node.File.PackageDir] {
			return true
		}
		for _, call := range node.Function.Calls {
			if call.PackageAlias != "" && domainDirs[importedPackageDir(node.File, call.PackageAlias)] {
				return true
			}
			field := receiverField(call.Receiver)
			if field != "" && fieldMatchesDomain(field, domain) && runtimeFieldOriginatesFromDomain(field, domainDirs, program) {
				return true
			}
		}
	}
	return false
}

func fieldMatchesDomain(field string, domain domainModel) bool {
	field = normalize(field)
	for _, candidate := range append([]string{domain.Name}, domain.Packages...) {
		token := normalize(strings.TrimSuffix(candidate, "http"))
		if len(token) >= 3 && strings.Contains(field, token) {
			return true
		}
	}
	return false
}

func receiverField(receiver string) string {
	parts := strings.Split(receiver, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

func runtimeFieldOriginatesFromDomain(field string, domainDirs map[string]bool, program programIndex) bool {
	for key := range program.Reachable {
		node := program.Nodes[key]
		binding, ok := node.Function.FieldBindings[field]
		if !ok || !binding.Call {
			continue
		}
		alias := strings.SplitN(binding.Name, ".", 2)[0]
		if alias != binding.Name && domainDirs[importedPackageDir(node.File, alias)] {
			return true
		}
	}
	return false
}

func domainExpectsHTTP(domain domainModel, routes []routeFact) bool {
	if len(routes) > 0 {
		return true
	}
	for _, packageName := range domain.Packages {
		if strings.HasSuffix(packageName, "http") {
			return true
		}
	}
	for _, file := range domain.Prod {
		for _, symbol := range file.Symbols {
			if symbol == "Handler" || strings.HasSuffix(symbol, ".ServeHTTP") || strings.HasSuffix(symbol, ".Handler") {
				return true
			}
		}
	}
	return false
}

func routeEvidence(route routeFact) string {
	return route.File + "#" + route.Symbol + "[" + route.Method + " " + route.Path + "]"
}

func uniqueRoutes(values []routeFact) []routeFact {
	seen := map[string]bool{}
	var result []routeFact
	for _, value := range values {
		key := routeEvidence(value)
		if !seen[key] {
			seen[key] = true
			result = append(result, value)
		}
	}
	return result
}

func fileHasCall(file goFileFact, fragments ...string) bool {
	for _, function := range file.Functions {
		for _, call := range function.Calls {
			lower := strings.ToLower(call.Name)
			for _, fragment := range fragments {
				if strings.Contains(lower, fragment) {
					return true
				}
			}
		}
	}
	return false
}

func domainWrittenTables(domain domainModel) []string {
	var result []string
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			result = append(result, writtenTablesFromStrings(function.Strings)...)
		}
	}
	return uniqueStrings(result)
}

func loadMigrations(source sourceIndex, program programIndex) (migrationIndex, error) {
	var result migrationIndex
	var patterns []string
	for _, file := range source.GoFiles {
		if file.Test || file.PackageDir != "services/control-api/migrations" {
			continue
		}
		for _, embedded := range file.Embeds {
			if embedded.Variable == "FS" && embedded.Type == "embed.FS" {
				patterns = append(patterns, embedded.Patterns...)
			}
		}
	}
	patterns = uniqueStrings(patterns)
	for _, entry := range source.Manifest.Entries {
		if !strings.HasPrefix(entry.Path, "services/control-api/migrations/") {
			continue
		}
		name := filepath.Base(entry.Path)
		match := migrationNamePattern.FindStringSubmatch(name)
		if len(match) == 0 {
			continue
		}
		content := source.Contents[entry.Path]
		embedded := false
		for _, pattern := range patterns {
			matches, matchErr := path.Match(pattern, name)
			if matchErr == nil && matches {
				embedded = true
			}
		}
		ownership := migrationOwnedObjects(content)
		result.Files = append(result.Files, migrationFact{
			Path: entry.Path, Version: match[1],
			Direction: match[3], Owned: ownership.Owned, Uncertain: ownership.Uncertain,
			GlobalUnknown:      ownership.GlobalUnknown,
			LexicallyUncertain: ownership.LexicallyUncertain, Embedded: embedded,
		})
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	for key, node := range program.Nodes {
		if !program.Reachable[key] || !strings.HasPrefix(node.File.Path, "services/control-api/cmd/control-api/") {
			continue
		}
		for _, call := range node.Function.Calls {
			if call.PackageAlias == "" || callBase(call.Name) != "Migrate" ||
				importedPackageDir(node.File, call.PackageAlias) != "services/control-api/internal/database" {
				continue
			}
			for _, target := range program.resolveCall(node, call) {
				migrationNode := program.Nodes[target]
				if migrationNode.Function.Name != "Migrate" {
					continue
				}
				migrationAlias := aliasForImport(migrationNode.File, "/services/control-api/migrations")
				if migrationAlias == "" || !containsString(migrationNode.Function.Selectors, migrationAlias+".FS") {
					continue
				}
				result.RuntimeLoads = true
				result.RuntimeProof = uniqueStrings(append(result.RuntimeProof,
					node.File.Path+"#"+node.Function.Name+"->"+call.Name,
					migrationNode.File.Path+"#"+migrationNode.Function.Name+"->"+migrationAlias+".FS"))
			}
		}
	}
	return result, nil
}

type migrationOwnership struct {
	Owned              []string
	Uncertain          []string
	Unknown            bool
	GlobalUnknown      bool
	LexicallyUncertain bool
}

func migrationOwnedObjects(content []byte) migrationOwnership {
	facts := scanSQL(content)
	ownership := migrationOwnership{
		Owned: migrationObjects(facts.tokens), Unknown: facts.uncertain,
		GlobalUnknown: facts.globalUncertain, LexicallyUncertain: facts.lexicallyUncertain,
	}
	for _, fragment := range facts.uncertainFragments {
		ownership.Uncertain = append(ownership.Uncertain, migrationObjects(fragment)...)
		ownership.Uncertain = append(ownership.Uncertain, writtenSQLObjects(fragment)...)
	}
	if facts.lexicallyUncertain {
		ownership.Uncertain = append(ownership.Uncertain, ownership.Owned...)
	}
	ownership.Uncertain = uniqueStrings(ownership.Uncertain)
	return ownership
}

func loadOpenAPI(root string) ([]openAPIDoc, error) {
	entries, err := filepath.Glob(filepath.Join(root, "api", "*.openapi.yaml"))
	if err != nil {
		return nil, err
	}
	queue := []string{canonicalOpenAPIRoot}
	for _, filePath := range entries {
		relative, relErr := filepath.Rel(root, filePath)
		if relErr != nil {
			return nil, relErr
		}
		queue = append(queue, filepath.ToSlash(relative))
	}
	documents := map[string]openAPIDoc{}
	for len(queue) > 0 {
		relative := queue[0]
		queue = queue[1:]
		if _, exists := documents[relative]; exists {
			continue
		}
		content, err := readOpenAPIFile(root, relative)
		if err != nil {
			return nil, fmt.Errorf("read OpenAPI %s: %w", relative, err)
		}
		document := parseOpenAPI(relative, content)
		if document.ParseError != "" {
			return nil, fmt.Errorf("parse %s: %s", document.Path, document.ParseError)
		}
		documents[relative] = document
		for _, reference := range document.Refs {
			target, _, local, resolveErr := resolveLocalOpenAPIRef(relative, reference)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if local {
				queue = append(queue, target)
			}
		}
	}
	for _, document := range documents {
		for _, reference := range document.Refs {
			target, fragment, local, resolveErr := resolveLocalOpenAPIRef(document.Path, reference)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if !local {
				continue
			}
			targetDocument, ok := documents[target]
			if !ok {
				return nil, fmt.Errorf("OpenAPI ref target was not loaded: %s#ref:%s", document.Path, reference)
			}
			if _, pointerErr := resolveJSONPointer(targetDocument.Document, fragment); pointerErr != nil {
				return nil, fmt.Errorf("invalid OpenAPI ref %s#ref:%s: %w", document.Path, reference, pointerErr)
			}
		}
	}
	result := make([]openAPIDoc, 0, len(documents))
	for _, document := range documents {
		result = append(result, document)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func readOpenAPIFile(root, relative string) ([]byte, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, err
	}
	apiPath := filepath.Join(rootPath, "api")
	realAPI, err := filepath.EvalSymlinks(apiPath)
	if err != nil {
		return nil, err
	}
	if !pathContained(realRoot, realAPI) {
		return nil, fmt.Errorf("api root escapes real repository root")
	}
	candidate := filepath.Join(rootPath, filepath.FromSlash(relative))
	if !pathContained(apiPath, candidate) {
		return nil, fmt.Errorf("OpenAPI path escapes lexical api root")
	}
	if err := rejectSymlinkComponents(rootPath, candidate); err != nil {
		return nil, fmt.Errorf("OpenAPI path escapes real api root or uses audited symlink: %w", err)
	}
	realCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, err
	}
	if !pathContained(realAPI, realCandidate) {
		return nil, fmt.Errorf("OpenAPI path escapes real api root")
	}
	return os.ReadFile(realCandidate)
}

func pathContained(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func resolveLocalOpenAPIRef(documentPath, reference string) (string, string, bool, error) {
	parsed, err := url.Parse(reference)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid OpenAPI ref URL %s#ref:%s: %w", documentPath, reference, err)
	}
	if strings.HasPrefix(reference, "//") || parsed.Scheme != "" || parsed.Host != "" || parsed.Opaque != "" ||
		parsed.RawQuery != "" || strings.HasPrefix(parsed.Path, "/") || strings.Contains(parsed.Path, `\`) {
		return "", "", false, fmt.Errorf("non-local OpenAPI ref rejected: %s#ref:%s", documentPath, reference)
	}
	fragment := ""
	if index := strings.Index(reference, "#"); index >= 0 {
		fragment, err = url.PathUnescape(reference[index+1:])
		if err != nil {
			return "", "", false, fmt.Errorf("invalid OpenAPI ref fragment %s#ref:%s: %w", documentPath, reference, err)
		}
	}
	if err := validateJSONPointer(fragment); err != nil {
		return "", "", false, fmt.Errorf("invalid OpenAPI ref fragment %s#ref:%s: %w", documentPath, reference, err)
	}
	target := documentPath
	if parsed.Path != "" {
		target = path.Clean(path.Join(path.Dir(documentPath), parsed.Path))
	}
	if target == "api" || !strings.HasPrefix(target, "api/") {
		return "", "", false, fmt.Errorf("OpenAPI ref escapes api root: %s#ref:%s", documentPath, reference)
	}
	return target, fragment, true, nil
}

func parseOpenAPI(filePath string, content []byte) openAPIDoc {
	result := openAPIDoc{Path: filePath, Content: append([]byte(nil), content...)}
	var document map[string]any
	if err := yaml.Unmarshal(content, &document); err != nil {
		result.ParseError = err.Error()
		return result
	}
	result.Document = document
	collectDocumentRefs(document, &result.Refs)
	paths, ok := stringMap(document["paths"])
	if !ok {
		return result
	}
	methods := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true, "trace": true}
	pathNames := make([]string, 0, len(paths))
	for routePath := range paths {
		pathNames = append(pathNames, routePath)
	}
	sort.Strings(pathNames)
	for _, routePath := range pathNames {
		pathItem, ok := stringMap(paths[routePath])
		if !ok {
			continue
		}
		methodNames := make([]string, 0, len(pathItem))
		for method := range pathItem {
			if methods[strings.ToLower(method)] {
				methodNames = append(methodNames, method)
			}
		}
		sort.Slice(methodNames, func(i, j int) bool { return strings.ToLower(methodNames[i]) < strings.ToLower(methodNames[j]) })
		for _, method := range methodNames {
			operationMap, _ := stringMap(pathItem[method])
			operationID, _ := operationMap["operationId"].(string)
			hasError, errorID := operationHasStructuredError(operationMap)
			if errorID == "" {
				errorID = strings.ToUpper(method) + " " + routePath
			}
			result.Operations = append(result.Operations, openAPIOperation{
				Path: routePath, Method: strings.ToUpper(method), ID: operationID, HasError: hasError, EvidenceID: errorID,
				Fragment: "/paths/" + escapeJSONPointerToken(routePath) + "/" + escapeJSONPointerToken(method),
			})
		}
	}
	result.Refs = uniqueStrings(result.Refs)
	return result
}

func validateJSONPointer(fragment string) error {
	if fragment == "" {
		return nil
	}
	if !strings.HasPrefix(fragment, "/") {
		return fmt.Errorf("fragment is not a JSON Pointer")
	}
	for _, token := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
		if _, err := decodeJSONPointerToken(token); err != nil {
			return err
		}
	}
	return nil
}

func escapeJSONPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func decodeJSONPointerToken(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '~' {
			result.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) || value[index+1] != '0' && value[index+1] != '1' {
			return "", fmt.Errorf("invalid JSON Pointer escape")
		}
		index++
		if value[index] == '0' {
			result.WriteByte('~')
		} else {
			result.WriteByte('/')
		}
	}
	return result.String(), nil
}

func resolveJSONPointer(document map[string]any, fragment string) (any, error) {
	if err := validateJSONPointer(fragment); err != nil {
		return nil, err
	}
	var current any = document
	if fragment == "" {
		return current, nil
	}
	for _, rawToken := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
		token, _ := decodeJSONPointerToken(rawToken)
		switch typed := current.(type) {
		case map[string]any:
			child, ok := typed[token]
			if !ok {
				return nil, fmt.Errorf("JSON Pointer token %q not found", token)
			}
			current = child
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("JSON Pointer index %q not found", token)
			}
			current = typed[index]
		default:
			return nil, fmt.Errorf("JSON Pointer traverses a scalar at %q", token)
		}
	}
	return current, nil
}

func stringMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func collectRefs(value any, refs *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if strings.HasPrefix(strings.ToLower(key), "x-") {
				continue
			}
			if key == "$ref" {
				if reference, ok := child.(string); ok {
					*refs = append(*refs, reference)
				}
				continue
			}
			collectRefs(child, refs)
		}
	case []any:
		for _, child := range typed {
			collectRefs(child, refs)
		}
	}
}

func collectDocumentRefs(document map[string]any, refs *[]string) {
	for _, key := range []string{"paths", "components", "webhooks"} {
		if subtree, ok := document[key]; ok {
			collectRefs(subtree, refs)
		}
	}
}

func semanticOpenAPIFragment(fragment string) bool {
	if fragment == "" {
		return true
	}
	for _, rawToken := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
		token, err := decodeJSONPointerToken(rawToken)
		if err != nil || strings.HasPrefix(strings.ToLower(token), "x-") {
			return false
		}
	}
	return true
}

func operationHasStructuredError(operation map[string]any) (bool, string) {
	responses, ok := stringMap(operation["responses"])
	if !ok {
		return false, ""
	}
	keys := make([]string, 0, len(responses))
	for code := range responses {
		keys = append(keys, code)
	}
	sort.Strings(keys)
	for _, code := range keys {
		if strings.HasPrefix(code, "2") {
			continue
		}
		response, ok := stringMap(responses[code])
		if !ok {
			continue
		}
		if _, ok := response["$ref"].(string); ok {
			return true, code
		}
		content, ok := stringMap(response["content"])
		if !ok {
			continue
		}
		for _, media := range content {
			mediaMap, _ := stringMap(media)
			if _, exists := mediaMap["schema"]; exists {
				return true, code
			}
		}
	}
	return false, ""
}

func documentsForDomain(domain domainModel, routes []routeFact, documents []openAPIDoc) []openAPIDoc {
	var routePaths []string
	for _, route := range routes {
		routePaths = append(routePaths, route.Path)
	}
	var result []openAPIDoc
	for _, document := range documents {
		nameMatched := false
		base := normalize(strings.TrimSuffix(filepath.Base(document.Path), ".openapi.yaml"))
		for _, candidate := range append([]string{domain.Name}, domain.Packages...) {
			token := normalize(candidate)
			if len(token) >= 4 && strings.Contains(base, token) {
				nameMatched = true
			}
		}
		var matchedOperations []openAPIOperation
		for _, operation := range document.Operations {
			if routeMatchesAny(operation.Path, routePaths) {
				matchedOperations = append(matchedOperations, operation)
			}
		}
		if len(matchedOperations) > 0 {
			filtered := document
			filtered.Operations = matchedOperations
			result = append(result, filtered)
		} else if nameMatched {
			result = append(result, document)
		}
	}
	return result
}

func referencedByAggregator(documentPath, fragment string, all []openAPIDoc) bool {
	documents := map[string]openAPIDoc{}
	for _, document := range all {
		documents[document.Path] = document
	}
	if _, ok := documents[canonicalOpenAPIRoot]; !ok {
		return false
	}
	type fragmentNode struct {
		document string
		fragment string
	}
	reachableOperations := map[string]bool{}
	visitedPathItems := map[string]bool{}
	var queue []fragmentNode
	rootPaths, _ := stringMap(documents[canonicalOpenAPIRoot].Document["paths"])
	rootPathNames := make([]string, 0, len(rootPaths))
	for routePath := range rootPaths {
		if strings.HasPrefix(routePath, "/") {
			rootPathNames = append(rootPathNames, routePath)
		}
	}
	sort.Strings(rootPathNames)
	for _, routePath := range rootPathNames {
		queue = append(queue, fragmentNode{document: canonicalOpenAPIRoot, fragment: "/paths/" + escapeJSONPointerToken(routePath)})
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		key := current.document + "#" + current.fragment
		if visitedPathItems[key] {
			continue
		}
		document, ok := documents[current.document]
		if !ok {
			continue
		}
		subtree, err := resolveJSONPointer(document.Document, current.fragment)
		if err != nil {
			continue
		}
		visitedPathItems[key] = true
		pathItem, ok := stringMap(subtree)
		if !ok {
			continue
		}
		if reference, ok := pathItem["$ref"].(string); ok {
			target, targetFragment, local, err := resolveLocalOpenAPIRef(current.document, reference)
			if err == nil && local && semanticOpenAPIFragment(targetFragment) && targetFragment != "" {
				queue = append(queue, fragmentNode{document: target, fragment: targetFragment})
			}
		}
		for method := range pathItem {
			if !openAPIMethod(method) {
				continue
			}
			operationFragment := current.fragment + "/" + escapeJSONPointerToken(method)
			reachableOperations[current.document+"#"+operationFragment] = true
		}
	}
	return reachableOperations[documentPath+"#"+fragment]
}

func openAPIMethod(value string) bool {
	switch strings.ToLower(value) {
	case "get", "post", "put", "patch", "delete", "head", "options", "trace":
		return true
	default:
		return false
	}
}

func permissionLiteral(value string) bool {
	if strings.ContainsAny(value, " \t\n/") || !strings.Contains(value, ".") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
	}
	return true
}

func authorizationCall(name string) bool {
	base := strings.ToLower(callBase(name))
	return base == "authorize" || strings.HasPrefix(base, "authorizewrite") || strings.HasPrefix(base, "recheckpermission") ||
		base == "requirepermission" || base == "checkpermission" || base == "haspermission"
}

func callUsesIdentifier(call callFact, identifier string) bool {
	for _, candidate := range call.Identifiers {
		if candidate == identifier {
			return true
		}
	}
	return false
}

func functionHasTxParameter(function functionFact) bool {
	for name, parameterType := range function.Parameters {
		if name == "tx" && strings.Contains(strings.ToLower(parameterType), "pgx.tx") {
			return true
		}
	}
	return false
}

func authorizationIsDatabaseBacked(domain domainModel, caller functionNode, call callFact, program programIndex) bool {
	for _, target := range program.resolveCall(caller, call) {
		if functionHasTxParameter(program.Nodes[target].Function) && functionReachesDatabase(target, program, map[string]bool{}) {
			return true
		}
	}
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			key := functionKey(file.Path, function.Name)
			if authorizationCall(function.Name) && functionHasTxParameter(function) && functionReachesDatabase(key, program, map[string]bool{}) {
				return true
			}
		}
	}
	return runtimeAuthorizationAdapterBacked(domain, program)
}

func functionReachesDatabase(key string, program programIndex, seen map[string]bool) bool {
	if seen[key] {
		return false
	}
	seen[key] = true
	node := program.Nodes[key]
	for _, call := range node.Function.Calls {
		base := strings.ToLower(callBase(call.Name))
		if (base == "query" || base == "queryrow" || base == "exec") &&
			(callUsesIdentifier(call, "tx") || strings.HasPrefix(strings.ToLower(call.Receiver), "tx") || call.InTransaction) {
			return true
		}
		for _, target := range program.resolveCall(node, call) {
			if functionReachesDatabase(target, program, seen) {
				return true
			}
		}
		if !callUsesIdentifier(call, "tx") {
			continue
		}
		for alias := range node.File.Imports {
			packageDir := importedPackageDir(node.File, alias)
			for functionName, targets := range program.byPackage[packageDir] {
				if callBase(functionName) != callBase(call.Name) {
					continue
				}
				for _, target := range targets {
					if functionHasTxParameter(program.Nodes[target].Function) && functionReachesDatabase(target, program, seen) {
						return true
					}
				}
			}
		}
	}
	return false
}

func runtimeAuthorizationAdapterBacked(domain domainModel, program programIndex) bool {
	domainDirs := map[string]bool{}
	for _, packageName := range domain.Packages {
		domainDirs["services/control-api/internal/"+packageName] = true
	}
	for key, adapter := range program.Nodes {
		if !strings.HasPrefix(adapter.File.Path, "services/control-api/cmd/control-api/") ||
			callBase(adapter.Function.Name) != "Authorize" || !functionHasTxParameter(adapter.Function) ||
			!functionReachesDatabase(key, program, map[string]bool{}) {
			continue
		}
		usesDomainType := false
		for _, parameterType := range adapter.Function.Parameters {
			packageDir, _ := typeLocation(adapter.File, parameterType)
			usesDomainType = usesDomainType || domainDirs[packageDir]
		}
		if !usesDomainType {
			continue
		}
		adapterType := strings.TrimPrefix(adapter.Function.ReceiverType, "*")
		for runtimeKey := range program.Reachable {
			runtimeNode := program.Nodes[runtimeKey]
			if !isRuntimeRoot(runtimeNode.File.Path) {
				continue
			}
			for variable, binding := range runtimeNode.Function.Bindings {
				if strings.TrimPrefix(binding.Name, "*") != adapterType {
					continue
				}
				for _, call := range runtimeNode.Function.Calls {
					if call.PackageAlias == "" || !domainDirs[importedPackageDir(runtimeNode.File, call.PackageAlias)] ||
						!runtimeConstructionCall(call.Name) || !containsString(call.Identifiers, variable) {
						continue
					}
					return true
				}
			}
		}
	}
	return false
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func functionHasPersistentIdempotency(function functionFact) bool {
	intent := strings.Contains(strings.ToLower(function.Name), "idempot")
	for _, value := range function.Strings {
		intent = intent || strings.Contains(strings.ToLower(value), "idempotenc") && !strings.EqualFold(value, "Idempotency-Key")
	}
	for _, table := range function.Tables {
		intent = intent || strings.Contains(table, "idempot")
	}
	if !intent {
		return false
	}
	transactional := functionHasTxParameter(function)
	database := false
	for _, call := range function.Calls {
		base := strings.ToLower(callBase(call.Name))
		database = database || base == "exec" || base == "query" || base == "queryrow"
		transactional = transactional || transactionCallName(call.Name) || call.InTransaction
	}
	return database && transactional
}

func hasMutationRoute(routes []routeFact) bool {
	for _, route := range routes {
		if route.Method == "POST" || route.Method == "PUT" || route.Method == "PATCH" || route.Method == "DELETE" || route.Method == "*" {
			return true
		}
	}
	return false
}

func domainWorkerEvidence(domain domainModel) string {
	for _, file := range domain.Prod {
		for _, function := range file.Functions {
			lower := strings.ToLower(function.Name)
			receiver := ""
			if index := strings.Index(lower, "."); index >= 0 {
				receiver = lower[:index]
			}
			if (strings.HasSuffix(lower, ".run") || strings.HasSuffix(lower, ".start")) && lifecycleType(receiver) ||
				(lower == "run" || lower == "start") && packageHasLifecycleSuffix(domain.Packages) {
				return file.Path + "#" + function.Name
			}
		}
	}
	return ""
}

func lifecycleType(value string) bool {
	for _, suffix := range []string{"worker", "runtime", "dispatcher", "publisher", "consumer", "syncer"} {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func packageHasLifecycleSuffix(packages []string) bool {
	for _, packageName := range packages {
		if lifecycleType(strings.ToLower(packageName)) {
			return true
		}
	}
	return false
}

func routeTargets(documents []openAPIDoc, routes []routeFact) []string {
	var result []string
	for _, document := range documents {
		for _, operation := range document.Operations {
			result = append(result, operation.Path)
		}
	}
	for _, route := range routes {
		result = append(result, route.Path)
	}
	return uniqueStrings(result)
}

func routeMatchesAny(candidate string, targets []string) bool {
	candidateSegments := routeSegments(candidate)
	for _, target := range targets {
		targetSegments := routeSegments(target)
		if len(candidateSegments) == 0 || len(candidateSegments) != len(targetSegments) {
			continue
		}
		matched := true
		for index := range candidateSegments {
			if routeTemplateSegment(candidateSegments[index]) || routeTemplateSegment(targetSegments[index]) {
				continue
			}
			if candidateSegments[index] != targetSegments[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func routePrefix(value string) string {
	segments := routeSegments(value)
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

func routeSegments(value string) []string {
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func routeTemplateSegment(value string) bool {
	return len(value) >= 3 && strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") ||
		len(value) >= 4 && strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")
}

func normalize(value string) string {
	var result strings.Builder
	for _, character := range strings.ToLower(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func intersects(left, right []string) bool {
	set := map[string]bool{}
	for _, value := range left {
		set[value] = true
	}
	for _, value := range right {
		if set[value] {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func uniqueFindings(values []finding) []finding {
	seen := map[string]bool{}
	result := make([]finding, 0, len(values))
	for _, value := range values {
		key := value.Code + "\x00" + value.Evidence
		if !seen[key] {
			seen[key] = true
			result = append(result, value)
		}
	}
	return result
}
