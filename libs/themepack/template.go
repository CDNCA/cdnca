package themepack

import (
	"html"
	"regexp"
	"strings"
)

// A logic-less template (ADR 0007 §7.2): {{name}} inserts an HTML-escaped
// value, {{#name}}…{{/name}} renders once for a non-empty string or once per
// list item ({{.}} is the item), {{^name}}…{{/name}} renders when the value is
// empty. There is no raw output, partial, comment, delimiter change or
// lookup outside the declared variables.

const (
	maxTemplateBytes = 32 << 10
	maxTemplateDepth = 4
)

var templateNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type templateNode struct {
	text     string
	variable string // "" for text; "." for the current list item
	section  string // section name for #/^ nodes
	inverted bool
	children []templateNode
}

type compiledTemplate struct {
	nodes []templateNode
}

// templateVariables declares, per template kind, which names exist and
// whether they are lists.
type templateVariables map[string]bool // name -> is list

func compileTemplate(source string, variables templateVariables) (compiledTemplate, error) {
	if source == "" || len(source) > maxTemplateBytes {
		return compiledTemplate{}, invalid("template_size", "")
	}
	nodes, rest, err := parseTemplate(source, variables, "", false, 0)
	if err != nil {
		return compiledTemplate{}, err
	}
	if rest != "" {
		return compiledTemplate{}, invalid("template_syntax", "")
	}
	return compiledTemplate{nodes: nodes}, nil
}

func parseTemplate(source string, variables templateVariables, closing string, inList bool, depth int) ([]templateNode, string, error) {
	var nodes []templateNode
	for source != "" {
		open := strings.Index(source, "{{")
		if open < 0 {
			if strings.Contains(source, "}}") {
				return nil, "", invalid("template_syntax", "")
			}
			nodes = append(nodes, templateNode{text: source})
			return nodes, "", finishParse(closing)
		}
		if strings.Contains(source[:open], "}}") {
			return nil, "", invalid("template_syntax", "")
		}
		if open > 0 {
			nodes = append(nodes, templateNode{text: source[:open]})
		}
		end := strings.Index(source[open+2:], "}}")
		if end < 0 {
			return nil, "", invalid("template_syntax", "")
		}
		tag := source[open+2 : open+2+end]
		source = source[open+2+end+2:]
		switch {
		case tag == ".":
			if !inList {
				return nil, "", invalid("template_variable", ".")
			}
			nodes = append(nodes, templateNode{variable: "."})
		case strings.HasPrefix(tag, "#"), strings.HasPrefix(tag, "^"):
			name := tag[1:]
			list, ok := variables[name]
			if !templateNamePattern.MatchString(name) || !ok {
				return nil, "", invalid("template_variable", name)
			}
			if depth+1 > maxTemplateDepth {
				return nil, "", invalid("template_depth", name)
			}
			inverted := tag[0] == '^'
			children, rest, err := parseTemplate(source, variables, name, inList || (list && !inverted), depth+1)
			if err != nil {
				return nil, "", err
			}
			nodes = append(nodes, templateNode{section: name, inverted: inverted, children: children})
			source = rest
		case strings.HasPrefix(tag, "/"):
			if tag[1:] != closing || closing == "" {
				return nil, "", invalid("template_syntax", tag)
			}
			return nodes, source, nil
		default:
			list, ok := variables[tag]
			if !templateNamePattern.MatchString(tag) || !ok || list {
				return nil, "", invalid("template_variable", tag)
			}
			nodes = append(nodes, templateNode{variable: tag})
		}
	}
	return nodes, "", finishParse(closing)
}

func finishParse(closing string) error {
	if closing != "" {
		return invalid("template_syntax", closing)
	}
	return nil
}

// TemplateContext values are strings or []string.
type TemplateContext map[string]any

func (template compiledTemplate) render(context TemplateContext) string {
	var output strings.Builder
	renderNodes(&output, template.nodes, context, "")
	return output.String()
}

func renderNodes(output *strings.Builder, nodes []templateNode, context TemplateContext, item string) {
	for _, node := range nodes {
		switch {
		case node.section != "":
			value := context[node.section]
			var items []string
			switch typed := value.(type) {
			case string:
				if typed != "" {
					items = []string{item}
				}
			case []string:
				items = typed
			}
			if node.inverted {
				if len(items) == 0 {
					renderNodes(output, node.children, context, item)
				}
				continue
			}
			for _, current := range items {
				renderNodes(output, node.children, context, current)
			}
		case node.variable == ".":
			output.WriteString(html.EscapeString(item))
		case node.variable != "":
			text, _ := context[node.variable].(string)
			output.WriteString(html.EscapeString(text))
		default:
			output.WriteString(node.text)
		}
	}
}
