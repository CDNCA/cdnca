package main

import (
	"bytes"
	"math/big"
	"strings"
)

type sqlToken struct {
	text   string
	quoted bool
	symbol byte
}

type sqlFacts struct {
	tokens             []sqlToken
	uncertainFragments [][]sqlToken
	uncertain          bool
	lexicallyUncertain bool
	globalUncertain    bool
}

func scanSQL(content []byte) sqlFacts {
	return scanSQLContent(content, false)
}

func scanSQLContent(content []byte, dynamicBody bool) sqlFacts {
	var result sqlFacts
	executeLiteralPending := false
	for index := 0; index < len(content); {
		lineComment := index+1 < len(content) && content[index] == '-' && content[index+1] == '-'
		blockComment := index+1 < len(content) && content[index] == '/' && content[index+1] == '*'
		if executeLiteralPending && !sqlSpace(content[index]) && !lineComment && !blockComment {
			if content[index] != ';' {
				result.uncertain = true
				result.globalUncertain = true
			}
			executeLiteralPending = false
		}
		switch {
		case sqlSpace(content[index]):
			index++
		case lineComment:
			index += 2
			for index < len(content) && content[index] != '\n' {
				index++
			}
		case blockComment:
			index += 2
			depth := 1
			for index < len(content) && depth > 0 {
				switch {
				case index+1 < len(content) && content[index] == '/' && content[index+1] == '*':
					depth++
					index += 2
				case index+1 < len(content) && content[index] == '*' && content[index+1] == '/':
					depth--
					index += 2
				default:
					index++
				}
			}
			if depth != 0 {
				result.uncertain = true
				result.lexicallyUncertain = true
			}
		case index+1 < len(content) && (content[index] == 'e' || content[index] == 'E') && content[index+1] == '\'':
			doBody := sqlStatementStartsWith(result.tokens, "do")
			executeLiteral := dynamicBody && sqlLastKeyword(result.tokens, "execute")
			var body []byte
			var closed bool
			index, body, closed = readSQLQuoted(content, index+1, true)
			if !closed {
				result.uncertain = true
				result.lexicallyUncertain = true
				result.globalUncertain = result.globalUncertain || doBody || executeLiteral
			} else if doBody {
				appendUncertainSQL(&result, body, true)
			} else if executeLiteral {
				appendUncertainSQL(&result, body, false)
				result.tokens = append(result.tokens, sqlToken{text: "dynamic-literal", quoted: true})
				executeLiteralPending = true
			}
		case content[index] == '\'':
			doBody := sqlStatementStartsWith(result.tokens, "do")
			executeLiteral := dynamicBody && sqlLastKeyword(result.tokens, "execute")
			var body []byte
			var closed bool
			index, body, closed = readSQLQuoted(content, index, false)
			if !closed {
				result.uncertain = true
				result.lexicallyUncertain = true
				result.globalUncertain = result.globalUncertain || doBody || executeLiteral
			} else if doBody {
				appendUncertainSQL(&result, body, true)
			} else if executeLiteral {
				appendUncertainSQL(&result, body, false)
				result.tokens = append(result.tokens, sqlToken{text: "dynamic-literal", quoted: true})
				executeLiteralPending = true
			}
		case content[index] == '$':
			tag, ok := sqlDollarTagAt(content[index:])
			if !ok {
				result.tokens = append(result.tokens, sqlToken{symbol: content[index]})
				index++
				continue
			}
			doBody := sqlStatementStartsWith(result.tokens, "do")
			executeLiteral := dynamicBody && sqlLastKeyword(result.tokens, "execute")
			start := index + len(tag)
			closing := strings.Index(string(content[start:]), string(tag))
			if closing < 0 {
				result.uncertain = true
				result.lexicallyUncertain = true
				result.globalUncertain = result.globalUncertain || doBody || executeLiteral
				index = len(content)
			} else {
				body := content[start : start+closing]
				if doBody {
					appendUncertainSQL(&result, body, true)
				} else if executeLiteral {
					appendUncertainSQL(&result, body, false)
					result.tokens = append(result.tokens, sqlToken{text: "dynamic-literal", quoted: true})
					executeLiteralPending = true
				}
				index = start + closing + len(tag)
			}
		case content[index] == '"':
			var value strings.Builder
			index++
			closed := false
			for index < len(content) {
				if content[index] != '"' {
					value.WriteByte(content[index])
					index++
					continue
				}
				if index+1 < len(content) && content[index+1] == '"' {
					value.WriteByte('"')
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				result.uncertain = true
				result.lexicallyUncertain = true
			}
			result.tokens = append(result.tokens, sqlToken{text: value.String(), quoted: true})
		case sqlIdentifierStart(content[index]):
			start := index
			index++
			for index < len(content) && sqlIdentifierPart(content[index]) {
				index++
			}
			token := sqlToken{text: strings.ToLower(string(content[start:index]))}
			if dynamicBody && sqlLastKeyword(result.tokens, "execute") {
				triggerFunction := sqlKeyword(token, "function") && sqlCurrentStatementContains(result.tokens, "trigger")
				formatRelevant, formatProven := false, false
				if sqlKeyword(token, "format") {
					var expanded []byte
					formatRelevant, formatProven, expanded = executeFormatMayOwnOrWrite(content, index)
					if expanded != nil {
						appendUncertainSQL(&result, expanded, false)
					}
				}
				if !triggerFunction && (!formatProven || formatRelevant) {
					result.uncertain = true
					result.globalUncertain = true
				}
			}
			result.tokens = append(result.tokens, token)
		default:
			if dynamicBody && sqlLastKeyword(result.tokens, "execute") && content[index] != ';' {
				result.uncertain = true
				result.globalUncertain = true
			}
			result.tokens = append(result.tokens, sqlToken{symbol: content[index]})
			index++
		}
	}
	return result
}

func appendUncertainSQL(result *sqlFacts, content []byte, dynamicBody bool) {
	body := scanSQLContent(content, dynamicBody)
	result.uncertain = true
	result.uncertainFragments = append(result.uncertainFragments, body.tokens)
	result.uncertainFragments = append(result.uncertainFragments, body.uncertainFragments...)
	result.globalUncertain = result.globalUncertain || body.globalUncertain || body.lexicallyUncertain
}

func sqlStatementStartsWith(tokens []sqlToken, keyword string) bool {
	index := len(tokens) - 1
	for index >= 0 && tokens[index].symbol != ';' {
		index--
	}
	index++
	return index < len(tokens) && sqlKeyword(tokens[index], keyword)
}

func sqlLastKeyword(tokens []sqlToken, keyword string) bool {
	return len(tokens) > 0 && sqlKeyword(tokens[len(tokens)-1], keyword)
}

func sqlCurrentStatementContains(tokens []sqlToken, keyword string) bool {
	for index := len(tokens) - 1; index >= 0 && tokens[index].symbol != ';'; index-- {
		if sqlKeyword(tokens[index], keyword) {
			return true
		}
	}
	return false
}

func readSQLQuoted(content []byte, index int, backslashEscapes bool) (int, []byte, bool) {
	var value []byte
	index++
	for index < len(content) {
		if backslashEscapes && content[index] == '\\' {
			if index+1 >= len(content) {
				return len(content), value, false
			}
			escaped := content[index+1]
			switch escaped {
			case 'n', 'r', 't', 'b', 'f':
				value = append(value, '\n')
			default:
				value = append(value, escaped)
			}
			index += 2
			continue
		}
		if content[index] != '\'' {
			value = append(value, content[index])
			index++
			continue
		}
		if index+1 < len(content) && content[index+1] == '\'' {
			value = append(value, '\'')
			index += 2
			continue
		}
		return index + 1, value, true
	}
	return index, value, false
}

const (
	maxFormatArguments      = 16
	maxFormatExpansionBytes = 4096
)

type staticFormatArgument struct {
	value  []byte
	static bool
	null   bool
}

func executeFormatMayOwnOrWrite(content []byte, index int) (bool, bool, []byte) {
	var triviaClosed bool
	index, triviaClosed = skipSQLFormatTrivia(content, index)
	if !triviaClosed {
		return false, false, nil
	}
	if index >= len(content) || content[index] != '(' {
		return false, false, nil
	}
	index, triviaClosed = skipSQLFormatTrivia(content, index+1)
	if !triviaClosed {
		return false, false, nil
	}
	if index >= len(content) {
		return false, false, nil
	}
	end, body, closed := readStaticSQLLiteral(content, index)
	if !closed {
		return false, false, nil
	}
	body = append([]byte(nil), body...)
	for {
		literalEnd, adjacent, ok := readAdjacentSQLLiteral(content, end)
		if !ok {
			break
		}
		if len(body)+len(adjacent) > maxFormatExpansionBytes {
			return false, false, nil
		}
		body = append(body, adjacent...)
		end = literalEnd
	}
	arguments, allStatic, callClosed := readStaticFormatArguments(content, end)
	if !callClosed {
		return false, false, nil
	}
	if allStatic {
		if expanded, ok := expandStaticFormat(body, arguments); ok {
			return false, true, expanded
		}
		return true, true, nil
	}
	if formatDynamicAffectsOwnership(body, arguments) {
		return true, true, nil
	}
	if expanded, ok := expandPartialStaticFormat(body, arguments); ok {
		if sqlMayOwnOrWrite(scanSQL(expanded).tokens) {
			return false, true, expanded
		}
		return false, true, nil
	}
	if !sqlMayOwnOrWrite(scanSQL(body).tokens) {
		return false, true, nil
	}
	return true, true, nil
}

func readStaticSQLLiteral(content []byte, index int) (int, []byte, bool) {
	switch {
	case index+1 < len(content) && (content[index] == 'e' || content[index] == 'E') && content[index+1] == '\'':
		return readSQLQuoted(content, index+1, true)
	case index < len(content) && content[index] == '\'':
		return readSQLQuoted(content, index, false)
	case index < len(content) && content[index] == '$':
		tag, ok := sqlDollarTagAt(content[index:])
		if !ok {
			return index, nil, false
		}
		start := index + len(tag)
		closing := strings.Index(string(content[start:]), string(tag))
		if closing < 0 {
			return len(content), nil, false
		}
		return start + closing + len(tag), content[start : start+closing], true
	default:
		return index, nil, false
	}
}

func readStaticFormatArguments(content []byte, index int) ([]staticFormatArgument, bool, bool) {
	var arguments []staticFormatArgument
	allStatic := true
	for {
		var triviaClosed bool
		index, triviaClosed = skipSQLFormatTrivia(content, index)
		if !triviaClosed {
			return nil, false, false
		}
		if index >= len(content) {
			return nil, false, false
		}
		if content[index] == ')' {
			return arguments, allStatic, true
		}
		if content[index] != ',' || len(arguments) >= maxFormatArguments {
			return nil, false, false
		}
		index, triviaClosed = skipSQLFormatTrivia(content, index+1)
		if !triviaClosed {
			return nil, false, false
		}
		end, argument, static := readStaticFormatArgument(content, index)
		if static {
			arguments = append(arguments, argument)
			index = end
			continue
		}
		allStatic = false
		arguments = append(arguments, staticFormatArgument{})
		var closed bool
		index, closed = skipFormatArgument(content, index)
		if !closed {
			return nil, false, false
		}
	}
}

func readStaticFormatArgument(content []byte, index int) (int, staticFormatArgument, bool) {
	if end, value, literal := readStaticSQLLiteral(content, index); literal {
		value = append([]byte(nil), value...)
		for {
			literalEnd, adjacent, ok := readAdjacentSQLLiteral(content, end)
			if !ok {
				var triviaClosed bool
				end, triviaClosed = skipSQLFormatTrivia(content, end)
				if !triviaClosed {
					return index, staticFormatArgument{}, false
				}
				break
			}
			if len(value)+len(adjacent) > maxFormatExpansionBytes {
				return index, staticFormatArgument{}, false
			}
			value = append(value, adjacent...)
			end = literalEnd
		}
		if end < len(content) && (content[end] == ',' || content[end] == ')') {
			return end, staticFormatArgument{value: value, static: true}, true
		}
		return index, staticFormatArgument{}, false
	}

	end := index
	if end < len(content) && (content[end] == '+' || content[end] == '-') {
		end++
	}
	digits := end
	for end < len(content) && content[end] >= '0' && content[end] <= '9' {
		end++
	}
	if end > digits {
		after, triviaClosed := skipSQLFormatTrivia(content, end)
		if !triviaClosed {
			return index, staticFormatArgument{}, false
		}
		if after < len(content) && (content[after] == ',' || content[after] == ')') {
			value, ok := new(big.Int).SetString(string(content[index:end]), 10)
			if ok {
				return after, staticFormatArgument{value: []byte(value.String()), static: true}, true
			}
		}
	}

	for _, keyword := range []struct {
		name  string
		value string
		null  bool
	}{{"null", "", true}, {"true", "t", false}, {"false", "f", false}} {
		keywordEnd := index + len(keyword.name)
		if keywordEnd > len(content) || !strings.EqualFold(string(content[index:keywordEnd]), keyword.name) {
			continue
		}
		after, triviaClosed := skipSQLFormatTrivia(content, keywordEnd)
		if !triviaClosed {
			return index, staticFormatArgument{}, false
		}
		if after < len(content) && (content[after] == ',' || content[after] == ')') {
			return after, staticFormatArgument{value: []byte(keyword.value), static: true, null: keyword.null}, true
		}
	}
	return index, staticFormatArgument{}, false
}

func readAdjacentSQLLiteral(content []byte, end int) (int, []byte, bool) {
	next, triviaClosed := skipSQLFormatTrivia(content, end)
	if !triviaClosed || next == end || !bytes.ContainsRune(content[end:next], '\n') {
		return end, nil, false
	}
	return readStaticSQLLiteral(content, next)
}

func skipSQLSpaces(content []byte, index int) int {
	for index < len(content) && sqlSpace(content[index]) {
		index++
	}
	return index
}

func skipSQLFormatTrivia(content []byte, index int) (int, bool) {
	for {
		index = skipSQLSpaces(content, index)
		switch {
		case index+1 < len(content) && content[index] == '-' && content[index+1] == '-':
			index += 2
			for index < len(content) && content[index] != '\n' {
				index++
			}
		case index+1 < len(content) && content[index] == '/' && content[index+1] == '*':
			index += 2
			depth := 1
			for index < len(content) && depth > 0 {
				switch {
				case index+1 < len(content) && content[index] == '/' && content[index+1] == '*':
					depth++
					index += 2
				case index+1 < len(content) && content[index] == '*' && content[index+1] == '/':
					depth--
					index += 2
				default:
					index++
				}
			}
			if depth != 0 {
				return index, false
			}
		default:
			return index, true
		}
	}
}

func skipFormatArgument(content []byte, index int) (int, bool) {
	parenDepth := 0
	bracketDepth := 0
	for index < len(content) {
		next, triviaClosed := skipSQLFormatTrivia(content, index)
		if !triviaClosed {
			return next, false
		}
		index = next
		if index >= len(content) {
			return index, false
		}
		if end, _, closed := readStaticSQLLiteral(content, index); closed {
			index = end
			continue
		}
		if content[index] == '"' {
			index++
			closed := false
			for index < len(content) {
				if content[index] != '"' {
					index++
					continue
				}
				if index+1 < len(content) && content[index+1] == '"' {
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				return index, false
			}
			continue
		}
		switch content[index] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 && bracketDepth == 0 {
				return index, true
			}
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case ',':
			if parenDepth == 0 && bracketDepth == 0 {
				return index, true
			}
		}
		index++
	}
	return index, false
}

func expandStaticFormat(template []byte, arguments []staticFormatArgument) ([]byte, bool) {
	return expandFormat(template, arguments, false)
}

func expandPartialStaticFormat(template []byte, arguments []staticFormatArgument) ([]byte, bool) {
	return expandFormat(template, arguments, true)
}

func expandFormat(template []byte, arguments []staticFormatArgument, dynamicData bool) ([]byte, bool) {
	result := make([]byte, 0, len(template))
	nextArgument := 0
	for index := 0; index < len(template); {
		if template[index] != '%' {
			result = append(result, template[index])
			index++
			continue
		}
		if index+1 < len(template) && template[index+1] == '%' {
			result = append(result, '%')
			index += 2
			continue
		}
		cursor := index + 1
		positionStart := cursor
		for cursor < len(template) && template[cursor] >= '0' && template[cursor] <= '9' {
			cursor++
		}
		argumentIndex := -1
		if cursor > positionStart && cursor < len(template) && template[cursor] == '$' {
			position := decimalBytes(template[positionStart:cursor])
			if position <= 0 {
				return nil, false
			}
			argumentIndex = position - 1
			cursor++
		} else {
			cursor = positionStart
		}
		rightPad := false
		if cursor < len(template) && template[cursor] == '-' {
			rightPad = true
			cursor++
		}
		widthStart := cursor
		for cursor < len(template) && template[cursor] >= '0' && template[cursor] <= '9' {
			cursor++
		}
		width := decimalBytes(template[widthStart:cursor])
		precision := -1
		if cursor < len(template) && template[cursor] == '.' {
			cursor++
			precisionStart := cursor
			for cursor < len(template) && template[cursor] >= '0' && template[cursor] <= '9' {
				cursor++
			}
			if precisionStart == cursor {
				return nil, false
			}
			precision = decimalBytes(template[precisionStart:cursor])
		}
		if cursor >= len(template) || (template[cursor] != 's' && template[cursor] != 'I' && template[cursor] != 'L') {
			return nil, false
		}
		if argumentIndex < 0 {
			argumentIndex = nextArgument
			nextArgument++
		} else if argumentIndex >= nextArgument {
			nextArgument = argumentIndex + 1
		}
		if argumentIndex >= len(arguments) {
			return nil, false
		}
		argument := arguments[argumentIndex]
		if !argument.static {
			if !dynamicData || template[cursor] != 'L' {
				return nil, false
			}
			argument = staticFormatArgument{static: true, null: true}
		}
		formatted, ok := formatStaticArgument(argument, template[cursor], width, precision, rightPad)
		if !ok {
			return nil, false
		}
		if len(result)+len(formatted) > maxFormatExpansionBytes {
			return nil, false
		}
		result = append(result, formatted...)
		index = cursor + 1
	}
	if len(result) > maxFormatExpansionBytes {
		return nil, false
	}
	return result, true
}

func decimalBytes(value []byte) int {
	result := 0
	for _, digit := range value {
		result = result*10 + int(digit-'0')
		if result > maxFormatExpansionBytes {
			return maxFormatExpansionBytes + 1
		}
	}
	return result
}

func formatStaticArgument(argument staticFormatArgument, kind byte, width, precision int, rightPad bool) ([]byte, bool) {
	formatted := append([]byte(nil), argument.value...)
	if argument.null {
		switch kind {
		case 's':
			formatted = nil
		case 'L':
			formatted = []byte("NULL")
		case 'I':
			return nil, false
		}
	}
	if precision >= 0 && precision < len(formatted) {
		formatted = formatted[:precision]
	}
	if !argument.null {
		switch kind {
		case 'I':
			formatted = []byte(`"` + strings.ReplaceAll(string(formatted), `"`, `""`) + `"`)
		case 'L':
			formatted = []byte("'" + strings.ReplaceAll(string(formatted), "'", "''") + "'")
		}
	}
	if width <= len(formatted) {
		return formatted, true
	}
	padding := make([]byte, width-len(formatted))
	for index := range padding {
		padding[index] = ' '
	}
	if rightPad {
		return append(formatted, padding...), true
	}
	return append(padding, formatted...), true
}

func formatDynamicAffectsOwnership(body []byte, arguments []staticFormatArgument) bool {
	nextArgument := 0
	prefix := make([]byte, 0, len(body))
	templateOwns := sqlMayOwnOrWrite(scanSQL(body).tokens)
	for index := 0; index < len(body); {
		if body[index] != '%' {
			prefix = append(prefix, body[index])
			index++
			continue
		}
		if index+1 < len(body) && body[index+1] == '%' {
			prefix = append(prefix, '%')
			index += 2
			continue
		}
		cursor := index + 1
		positionStart := cursor
		for cursor < len(body) && body[cursor] >= '0' && body[cursor] <= '9' {
			cursor++
		}
		argumentIndex := -1
		if cursor > positionStart && cursor < len(body) && body[cursor] == '$' {
			argumentIndex = decimalBytes(body[positionStart:cursor]) - 1
			cursor++
		} else {
			cursor = positionStart
		}
		rightPad := false
		if cursor < len(body) && body[cursor] == '-' {
			rightPad = true
			cursor++
		}
		widthStart := cursor
		for cursor < len(body) && body[cursor] >= '0' && body[cursor] <= '9' {
			cursor++
		}
		width := decimalBytes(body[widthStart:cursor])
		precision := -1
		if cursor < len(body) && body[cursor] == '.' {
			cursor++
			precisionStart := cursor
			for cursor < len(body) && body[cursor] >= '0' && body[cursor] <= '9' {
				cursor++
			}
			if precisionStart == cursor {
				return true
			}
			precision = decimalBytes(body[precisionStart:cursor])
		}
		if cursor >= len(body) || (body[cursor] != 's' && body[cursor] != 'I' && body[cursor] != 'L') {
			return true
		}
		if argumentIndex < 0 {
			argumentIndex = nextArgument
			nextArgument++
		} else if argumentIndex >= nextArgument {
			nextArgument = argumentIndex + 1
		}
		dynamic := argumentIndex < 0 || argumentIndex >= len(arguments) || !arguments[argumentIndex].static
		if dynamic {
			switch body[cursor] {
			case 's':
				return true
			case 'I':
				if templateOwns {
					return true
				}
			case 'L':
				if formatLiteralIsExecutable(prefix) {
					return true
				}
			}
			prefix = append(prefix, "dynamic"...)
		} else {
			formatted, ok := formatStaticArgument(arguments[argumentIndex], body[cursor], width, precision, rightPad)
			if !ok || len(prefix)+len(formatted) > maxFormatExpansionBytes {
				return true
			}
			prefix = append(prefix, formatted...)
		}
		index = cursor + 1
	}
	return false
}

func formatLiteralIsExecutable(prefix []byte) bool {
	tokens := scanSQL(prefix).tokens
	return sqlStatementStartsWith(tokens, "do") || sqlLastKeyword(tokens, "execute")
}

func sqlMayOwnOrWrite(tokens []sqlToken) bool {
	return sqlMayOwnOrWriteDepth(tokens, 0)
}

const maxSQLWithDepth = 16

func sqlMayOwnOrWriteDepth(tokens []sqlToken, depth int) bool {
	for start := 0; start < len(tokens); {
		for start < len(tokens) && tokens[start].symbol == ';' {
			start++
		}
		end := start
		for end < len(tokens) && tokens[end].symbol != ';' {
			end++
		}
		if sqlStatementMayOwnOrWriteDepth(tokens[start:end], depth) {
			return true
		}
		start = end + 1
	}
	return false
}

func sqlStatementMayOwnOrWrite(tokens []sqlToken) bool {
	return sqlStatementMayOwnOrWriteDepth(tokens, 0)
}

func sqlStatementMayOwnOrWriteDepth(tokens []sqlToken, depth int) bool {
	if len(tokens) == 0 {
		return false
	}
	if sqlKeyword(tokens[0], "with") {
		if depth >= maxSQLWithDepth {
			return sqlTokensMayOwnOrWrite(tokens)
		}
		start, innerWrite, ok := sqlWithStatementStart(tokens, depth)
		if !ok {
			return sqlTokensMayOwnOrWrite(tokens)
		}
		if innerWrite {
			return true
		}
		tokens = tokens[start:]
		if len(tokens) == 0 {
			return false
		}
	}
	if sqlKeyword(tokens[0], "insert") || sqlKeyword(tokens[0], "update") || sqlKeyword(tokens[0], "delete") ||
		sqlKeyword(tokens[0], "merge") {
		return true
	}
	create := sqlKeyword(tokens[0], "create")
	drop := sqlKeyword(tokens[0], "drop")
	if !create && !drop {
		return false
	}
	cursor := 1
	if create && cursor+1 < len(tokens) && sqlKeyword(tokens[cursor], "or") && sqlKeyword(tokens[cursor+1], "replace") {
		cursor += 2
	}
	if create && cursor < len(tokens) && sqlKeyword(tokens[cursor], "unlogged") {
		cursor++
	}
	if cursor < len(tokens) && sqlKeyword(tokens[cursor], "materialized") {
		cursor++
	}
	return cursor < len(tokens) && (sqlKeyword(tokens[cursor], "table") || sqlKeyword(tokens[cursor], "view") ||
		sqlKeyword(tokens[cursor], "function") || sqlKeyword(tokens[cursor], "type"))
}

func sqlWithStatementStart(tokens []sqlToken, depth int) (int, bool, bool) {
	cursor := 1
	if cursor < len(tokens) && sqlKeyword(tokens[cursor], "recursive") {
		cursor++
	}
	innerWrite := false
	for {
		if cursor >= len(tokens) || tokens[cursor].symbol != 0 {
			return 0, false, false
		}
		cursor++
		if cursor < len(tokens) && tokens[cursor].symbol == '(' {
			closing, ok := sqlClosingParen(tokens, cursor)
			if !ok {
				return 0, false, false
			}
			cursor = closing + 1
		}
		if cursor >= len(tokens) || !sqlKeyword(tokens[cursor], "as") {
			return 0, false, false
		}
		cursor++
		if cursor+1 < len(tokens) && sqlKeyword(tokens[cursor], "not") && sqlKeyword(tokens[cursor+1], "materialized") {
			cursor += 2
		} else if cursor < len(tokens) && sqlKeyword(tokens[cursor], "materialized") {
			cursor++
		}
		if cursor >= len(tokens) || tokens[cursor].symbol != '(' {
			return 0, false, false
		}
		closing, ok := sqlClosingParen(tokens, cursor)
		if !ok {
			return 0, false, false
		}
		innerWrite = innerWrite || sqlMayOwnOrWriteDepth(tokens[cursor+1:closing], depth+1)
		cursor = closing + 1
		if cursor >= len(tokens) || tokens[cursor].symbol != ',' {
			return cursor, innerWrite, cursor < len(tokens)
		}
		cursor++
	}
}

func sqlClosingParen(tokens []sqlToken, start int) (int, bool) {
	level := 0
	for index := start; index < len(tokens); index++ {
		switch tokens[index].symbol {
		case '(':
			level++
		case ')':
			level--
			if level == 0 {
				return index, true
			}
			if level < 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func sqlTokensMayOwnOrWrite(tokens []sqlToken) bool {
	for _, token := range tokens {
		if sqlKeyword(token, "insert") || sqlKeyword(token, "update") || sqlKeyword(token, "delete") ||
			sqlKeyword(token, "merge") || sqlKeyword(token, "create") || sqlKeyword(token, "drop") {
			return true
		}
	}
	return false
}

func sqlDollarTagAt(content []byte) ([]byte, bool) {
	if len(content) < 2 || content[0] != '$' {
		return nil, false
	}
	if content[1] == '$' {
		return content[:2], true
	}
	if !sqlIdentifierStart(content[1]) {
		return nil, false
	}
	for index := 2; index < len(content); index++ {
		if content[index] == '$' {
			return content[:index+1], true
		}
		if !sqlIdentifierPart(content[index]) {
			return nil, false
		}
	}
	return nil, false
}

func sqlSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f'
}

func sqlIdentifierStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func sqlIdentifierPart(value byte) bool {
	return sqlIdentifierStart(value) || value >= '0' && value <= '9' || value == '$'
}

func sqlKeyword(token sqlToken, keyword string) bool {
	return !token.quoted && token.symbol == 0 && token.text == keyword
}

func sqlIdentifier(token sqlToken) bool {
	return token.symbol == 0 && token.text != ""
}

func qualifiedSQLObject(tokens []sqlToken, index int) (string, int, bool) {
	if index >= len(tokens) || !sqlIdentifier(tokens[index]) {
		return "", index, false
	}
	leaf := tokens[index].text
	index++
	for index+1 < len(tokens) && tokens[index].symbol == '.' && sqlIdentifier(tokens[index+1]) {
		leaf = tokens[index+1].text
		index += 2
	}
	return strings.ToLower(leaf), index, true
}

func skipSQLIfExists(tokens []sqlToken, index int) (int, bool) {
	if index >= len(tokens) || !sqlKeyword(tokens[index], "if") {
		return index, true
	}
	index++
	if index < len(tokens) && sqlKeyword(tokens[index], "not") {
		index++
	}
	if index < len(tokens) && sqlKeyword(tokens[index], "exists") {
		return index + 1, true
	}
	return index, false
}

func migrationObjects(tokens []sqlToken) []string {
	var result []string
	for index := 0; index < len(tokens); index++ {
		create := sqlKeyword(tokens[index], "create")
		drop := sqlKeyword(tokens[index], "drop")
		if !create && !drop {
			continue
		}
		cursor := index + 1
		if create && cursor+1 < len(tokens) && sqlKeyword(tokens[cursor], "or") && sqlKeyword(tokens[cursor+1], "replace") {
			cursor += 2
		}
		if create && cursor < len(tokens) && sqlKeyword(tokens[cursor], "unlogged") {
			cursor++
		}
		if cursor < len(tokens) && sqlKeyword(tokens[cursor], "materialized") {
			cursor++
			if cursor >= len(tokens) || !sqlKeyword(tokens[cursor], "view") {
				continue
			}
			cursor++
		} else if cursor < len(tokens) && (sqlKeyword(tokens[cursor], "table") || sqlKeyword(tokens[cursor], "view") ||
			sqlKeyword(tokens[cursor], "function") || sqlKeyword(tokens[cursor], "type")) {
			cursor++
		} else {
			continue
		}
		var valid bool
		cursor, valid = skipSQLIfExists(tokens, cursor)
		if !valid {
			continue
		}
		for {
			object, next, ok := qualifiedSQLObject(tokens, cursor)
			if !ok {
				break
			}
			result = append(result, object)
			cursor = next
			if !drop || cursor >= len(tokens) || tokens[cursor].symbol != ',' {
				break
			}
			cursor++
		}
	}
	return uniqueStrings(result)
}

func writtenSQLObjects(tokens []sqlToken) []string {
	var result []string
	for index := 0; index < len(tokens); index++ {
		cursor := index + 1
		switch {
		case sqlKeyword(tokens[index], "insert"):
			if cursor >= len(tokens) || !sqlKeyword(tokens[cursor], "into") {
				continue
			}
			cursor++
			if cursor < len(tokens) && sqlKeyword(tokens[cursor], "only") {
				cursor++
			}
		case sqlKeyword(tokens[index], "update"):
			if cursor < len(tokens) && sqlKeyword(tokens[cursor], "only") {
				cursor++
			}
			if cursor < len(tokens) && sqlKeyword(tokens[cursor], "set") {
				continue
			}
		case sqlKeyword(tokens[index], "delete"):
			if cursor >= len(tokens) || !sqlKeyword(tokens[cursor], "from") {
				continue
			}
			cursor++
			if cursor < len(tokens) && sqlKeyword(tokens[cursor], "only") {
				cursor++
			}
		case sqlKeyword(tokens[index], "merge"):
			if cursor >= len(tokens) || !sqlKeyword(tokens[cursor], "into") {
				continue
			}
			cursor++
			if cursor < len(tokens) && sqlKeyword(tokens[cursor], "only") {
				cursor++
			}
		default:
			continue
		}
		if object, _, ok := qualifiedSQLObject(tokens, cursor); ok {
			result = append(result, object)
		}
	}
	return uniqueStrings(result)
}

func referencedSQLObjects(tokens []sqlToken) []string {
	result := writtenSQLObjects(tokens)
	for index := 0; index+1 < len(tokens); index++ {
		if !sqlKeyword(tokens[index], "from") && !sqlKeyword(tokens[index], "join") {
			continue
		}
		cursor := index + 1
		if cursor < len(tokens) && sqlKeyword(tokens[cursor], "only") {
			cursor++
		}
		if object, _, ok := qualifiedSQLObject(tokens, cursor); ok {
			result = append(result, object)
		}
	}
	return uniqueStrings(result)
}
