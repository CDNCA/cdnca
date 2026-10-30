import * as ts from 'typescript'

const pseudoLocalePattern = /^qps(?:-|$)/i

function isPseudoLocaleProperty(name: ts.PropertyName | undefined): boolean {
  return Boolean(
    name &&
      (ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) &&
      pseudoLocalePattern.test(name.text),
  )
}

function isPseudoBundleCall(expression: ts.Expression): boolean {
  if (!ts.isCallExpression(expression) || !ts.isPropertyAccessExpression(expression.expression)) return false
  if (expression.expression.name.text !== 'addResourceBundle') return false
  const locale = expression.arguments[0]
  return Boolean(
    locale &&
      (ts.isStringLiteral(locale) || ts.isNoSubstitutionTemplateLiteral(locale)) &&
      pseudoLocalePattern.test(locale.text),
  )
}

function isPseudoLocaleAssignment(expression: ts.Expression): boolean {
  if (!ts.isBinaryExpression(expression) || expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false
  if (!ts.isElementAccessExpression(expression.left)) return false
  const locale = expression.left.argumentExpression
  return Boolean(
    locale &&
      (ts.isStringLiteral(locale) || ts.isNoSubstitutionTemplateLiteral(locale)) &&
      pseudoLocalePattern.test(locale.text),
  )
}

function isPseudoBindingName(name: ts.BindingName | ts.ModuleExportName): boolean {
  return ts.isIdentifier(name) && /pseudo/i.test(name.text)
}

function containsPseudoLocale(node: ts.Node): boolean {
  let found = false
  const visit: ts.Visitor = (child) => {
    if (
      (ts.isStringLiteral(child) || ts.isNoSubstitutionTemplateLiteral(child)) &&
      pseudoLocalePattern.test(child.text)
    ) {
      found = true
      return undefined
    }
    ts.forEachChild(child, visit)
    return undefined
  }
  visit(node)
  return found
}

function stripPseudoNamedImports(node: ts.ImportDeclaration): ts.ImportDeclaration | undefined {
  if (!node.importClause?.namedBindings || !ts.isNamedImports(node.importClause.namedBindings)) return node
  const elements = node.importClause.namedBindings.elements.filter((element) => (
    !isPseudoBindingName(element.name) &&
    !(element.propertyName && isPseudoBindingName(element.propertyName))
  ))
  if (elements.length === node.importClause.namedBindings.elements.length) return node
  if (elements.length === 0 && !node.importClause.name) return undefined
  const namedBindings = ts.factory.updateNamedImports(node.importClause.namedBindings, elements)
  const importClause = ts.factory.updateImportClause(node.importClause, node.importClause.isTypeOnly, node.importClause.name, namedBindings)
  return ts.factory.updateImportDeclaration(node, node.modifiers, importClause, node.moduleSpecifier, node.attributes)
}

function stripPseudoNamedExports(node: ts.ExportDeclaration): ts.ExportDeclaration | undefined {
  if (!node.exportClause || !ts.isNamedExports(node.exportClause)) return node
  const elements = node.exportClause.elements.filter((element) => (
    !isPseudoBindingName(element.name) &&
    !(element.propertyName && isPseudoBindingName(element.propertyName))
  ))
  if (elements.length === node.exportClause.elements.length) return node
  if (elements.length === 0) return undefined
  return ts.factory.updateExportDeclaration(
    node,
    node.modifiers,
    node.isTypeOnly,
    ts.factory.updateNamedExports(node.exportClause, elements),
    node.moduleSpecifier,
    node.attributes,
  )
}

export function stripProductionPseudoResources(code: string, id: string): { code: string; map: null } | null {
  const isPseudoResourceModule = id.includes('/src/i18n/') ||
    id.includes('/src/pages/node-scheduling/messages.') ||
    id.includes('/src/pages/site-protocols/i18n.')
  if (!isPseudoResourceModule || !id.endsWith('.ts') || id.endsWith('.test.ts')) return null

  // Don't transform index.ts - it already guards pseudoCN with import.meta.env.MODE === 'test'
  if (id.endsWith('/i18n/index.ts')) return null

  const sourceFile = ts.createSourceFile(id, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  let changed = false
  const result = ts.transform(sourceFile, [
    (context) => {
      const visit: ts.Visitor = (node) => {
        if (ts.isImportDeclaration(node)) {
          const stripped = stripPseudoNamedImports(node)
          if (stripped !== node) changed = true
          return stripped
        }
        if (ts.isExportDeclaration(node)) {
          const stripped = stripPseudoNamedExports(node)
          if (stripped !== node) changed = true
          return stripped
        }
        if (ts.isFunctionDeclaration(node) && node.name && /pseudo/i.test(node.name.text)) {
          changed = true
          return ts.factory.createEmptyStatement()
        }
        if (ts.isVariableStatement(node)) {
          const declarations = node.declarationList.declarations.filter((declaration) => !isPseudoBindingName(declaration.name))
          if (declarations.length !== node.declarationList.declarations.length) {
            changed = true
            if (declarations.length === 0) return ts.factory.createEmptyStatement()
            const declarationList = ts.factory.updateVariableDeclarationList(node.declarationList, declarations)
            return ts.factory.updateVariableStatement(node, node.modifiers, declarationList)
          }
        }
        if (ts.isIfStatement(node) && containsPseudoLocale(node.expression)) {
          changed = true
          return ts.factory.createEmptyStatement()
        }
        if (ts.isExpressionStatement(node) && (isPseudoBundleCall(node.expression) || isPseudoLocaleAssignment(node.expression))) {
          changed = true
          return ts.factory.createEmptyStatement()
        }
        if (ts.isPropertyAssignment(node) && isPseudoLocaleProperty(node.name)) {
          changed = true
          return undefined
        }
        return ts.visitEachChild(node, visit, context)
      }
      return (node) => ts.visitNode(node, visit) as ts.SourceFile
    },
  ])

  if (!changed) {
    result.dispose()
    return null
  }

  const transformed = ts.createPrinter().printFile(result.transformed[0] as ts.SourceFile)
  result.dispose()
  return { code: transformed, map: null }
}
