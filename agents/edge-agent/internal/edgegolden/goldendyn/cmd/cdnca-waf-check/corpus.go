package main

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// evalRequest is one corpus request: a value sent as a query argument and as
// a form field (Body empty, ContentType empty), or a whole request body.
type evalRequest struct {
	ID       string            `json:"id"`
	Category string            `json:"category"`
	Method   string            `json:"method"`
	URI      string            `json:"uri"`
	Headers  map[string]string `json:"headers,omitempty"`
	Data     string            `json:"data,omitempty"`
	Value    string            `json:"value,omitempty"`
	Rule     int               `json:"rule,omitempty"`
	PL       int               `json:"pl,omitempty"`
	Attack   bool              `json:"attack"`
}

// benignCorpus is normal traffic of the kinds the strict tiers misjudged
// (waf-tiers: 30 of 55) and more: JSON APIs and GraphQL as real request
// bodies, template and front-end framework syntax, rich text, Markdown,
// Base64 uploads, search terms, code snippets, multilingual text, passwords
// and everyday form values. Values (category "value:*") go as a query
// argument and as a form field; the rest are whole requests.
func benignCorpus() []evalRequest {
	values := map[string][]string{
		// the waf-tiers corpus (55)
		"tiers": {"hello world", "{{name}}", "{{ user.name }}", "{{user.profile.name}}", "{{ name | upper }}",
			"Hello {{first_name}}, your order {{order_id}} shipped", "{{#each items}}{{this}}{{/each}}", "{{> header}}",
			"${HOME}", "${user}", "#{id}", "{% if user %}hi{% endif %}", "<%= name %>", "price: ${price}",
			`{"a":1,"b":[1,2,3]}`, `{"user":{"name":"Tom","email":"tom@example.com"},"tags":["a","b"]}`,
			`{"template":"{{title}} - {{site}}","version":"2024-10-14"}`, `{"@type":"Person","name":"Jane"}`,
			`{"@context":"https://schema.org","@type":"Product","name":"Phone"}`,
			"<p>Hello <b>world</b></p><ul><li>one</li><li>two</li></ul>", "<h2>Release notes</h2><p>Fixed 3-4 bugs; see {{docs}}.</p>",
			"<blockquote>a * b is multiplication</blockquote>", "Math: 7 * 7 = 49 and 10/2 = 5", "2024-10-14", "10-20 items",
			"data:image/png;base64," + tinyPNG, tinyPNG, "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			"Order O:12 shipped", "ratio 3:4", "the pharmacy is open", "phar is a PHP archive format", "rO0 is not a word",
			"use java.util.HashMap in your code", "com.example.Session", "Java serialization talk at 7pm",
			"Tom and Jerry", "user@example.com", "https://example.com/a?b=1", "O'Brien", "it's a nice day",
			"50% off {{today}}", "#{user.name}", "${user.address.city}", "x = {a: 1}", "function() { return 1 }",
			"review: great product, 5 stars", "search: blue shoes size 42", "Ünïcödé text", "rock and roll", "C# and C++ jobs",
			"page 2 of 10", "SKU-12345-XL", "id=123"},
		"template": {"{{ $t('login.title') }}", "{{ item.price | currency('¥') }}", "{{ count > 1 ? 'items' : 'item' }}",
			"<div v-if=\"show\">{{ message }}</div>", "<li v-for=\"item in items\" :key=\"item.id\">{{ item.text }}</li>",
			"<button @click=\"submit\">{{ label }}</button>", "<input [(ngModel)]=\"name\"> {{ name }}",
			"<p *ngIf=\"user\">Welcome {{ user.firstName }}</p>", "Dear {{customer.name}}, your invoice #{{invoice.number}} is due on {{invoice.due_date}}.",
			"{% for product in collection.products %}{{ product.title }}{% endfor %}", "{{ product.price | money }}",
			"{% raw %}{{ not_rendered }}{% endraw %}", "{{! this is a comment }}", "{{{html_body}}}", "{{#if logged_in}}Logout{{else}}Login{{/if}}",
			"Hi ${name}, welcome to ${company}!", "Path: ${project.basedir}/src", "Total: #{order.total}", "@{/user/profile}",
			"*{firstName}", "<%= link_to 'Home', root_path %>", "<% if @user %>Hello<% end %>", "{$smarty.now|date_format}",
			"[[ user.name ]]", "{{.Title}} - {{.Site.Name}}", "{{ range .Pages }}{{ .Title }}{{ end }}", "{{ trans }}Hello{{ endtrans }}",
			"Use {{double braces}} for variables", "{{ 'now' | date: '%Y-%m-%d' }}", "${{ secrets.GITHUB_TOKEN }}"},
		"richtext": {"<p style=\"text-align:center\"><strong>Big sale</strong> &amp; free shipping</p>",
			"<p>Visit <a href=\"https://example.com/docs\" target=\"_blank\" rel=\"noopener\">our docs</a> for details.</p>",
			"<img src=\"https://cdn.example.com/a.jpg\" alt=\"product\" width=\"300\">",
			"<table><tr><th>Size</th><th>Price</th></tr><tr><td>M</td><td>$20</td></tr></table>",
			"<p><span style=\"color:#ff0000;font-size:14px\">Notice:</span> office closed 10/1-10/7</p>",
			"<ol><li>Open settings</li><li>Click <em>Save</em></li></ol>", "<pre><code>npm install --save lodash</code></pre>",
			"<h1>Title</h1><p>First paragraph.</p><hr><p>Second &lt;tag&gt; text.</p>",
			"<p>Q&amp;A: what's new in 2.0?</p><p>&nbsp;</p>", "<div class=\"note\"><p>Note: use <code>--force</code> carefully</p></div>",
			"<figure><img src=\"/uploads/2024/10/a.png\"><figcaption>Fig. 1</figcaption></figure>",
			"<p>Email us: <a href=\"mailto:support@example.com\">support@example.com</a></p>"},
		"markdown": {"# Title\n\nSome **bold** and _italic_ text.", "- [x] done\n- [ ] todo", "| a | b |\n|---|---|\n| 1 | 2 |",
			"```js\nconst a = [1, 2, 3].map(x => x * 2);\n```", "See [the docs](https://example.com/docs#install) and ![logo](/logo.png)",
			"> quote line\n> second line", "Use `SELECT` only with `LIMIT`.", "1. step one\n2. step two\n   - nested",
			"```bash\ncurl -s https://example.com/api | jq '.items[] | .name'\n```", "Footnote[^1]\n\n[^1]: source",
			"~~old price~~ new price", "```python\ndef add(a, b):\n    return a + b\n```"},
		"search": {"iphone 15 pro max 256gb", "\"red dress\" -long", "laptop OR notebook", "site:example.com pricing", "c++ vector erase",
			"node.js async/await tutorial", "how to fix error 0x80070005", "best pizza near me", "1/2 inch pipe", "100% cotton t-shirt",
			"wireless earbuds (noise cancelling)", "what is 2+2", "rock & roll", "AT&T plans", "o'reilly books", "size:42 color:blue",
			"python 'list index out of range'", "select a gift for mom", "drop shipping business", "union station parking",
			"order by price desc", "where to buy from china", "delete account how", "insert coin", "update ubuntu kernel"},
		"code": {"for (let i = 0; i < n; i++) { sum += a[i]; }", "if (a && b || !c) { return; }", "x = y > 0 ? y : -y;",
			"SELECT name, price FROM products WHERE price > 10 ORDER BY price;", "git commit -m \"fix: handle null user\"",
			"docker run --rm -p 8080:80 nginx", "import numpy as np; np.array([1, 2, 3])", "<?php echo 'hi'; ?>",
			"public static void main(String[] args) { System.out.println(\"hi\"); }", "printf(\"%d\\n\", x);",
			"$ ls -la /var/www", "kubectl get pods -n kube-system", "const {a, b} = obj;", "arr.filter(x => x % 2 === 0)",
			"#include <stdio.h>", "SELECT COUNT(*) FROM orders;", "echo $PATH", "a = b // integer division", "/* block comment */ x++;",
			"`npm run build`"},
		"multilingual": {"你好，世界！这是一段中文测试文本。", "请于 10 月 1 日前提交“年度报告”（含附件）。", "日本語のテキストです。", "한국어 텍스트입니다",
			"مرحبا بالعالم", "Привет, мир! Как дела?", "Γειά σου Κόσμε", "שלום עולם", "สวัสดีชาวโลก", "Xin chào thế giới",
			"😀👍🎉 great!", "价格：￥199.00（包邮）", "地址：北京市朝阳区建国路 88 号 3 单元 501 室", "【限时】买一送一！！！",
			"Ça va? Très bien, merci.", "Grüße aus München — Straße 5", "¿Dónde está la biblioteca?", "東京都渋谷区1-2-3"},
		"form": {"P@ssw0rd!2024#Secure", "Tr0ub4dor&3", "correct-horse-battery-staple", "Xk9#mP2$vL7@nQ4!", "aB3$dE6^gH9*jK2(",
			"+86 138-0013-8000", "(555) 123-4567", "John O'Connor-Smith", "Apt. #4B, 123 Main St.", "10:30-12:00",
			"1,234.56", "-12.5", "50%", "a/b/c", "C:\\Users\\Public\\Documents", "/home/user/docs/report.pdf",
			"https://www.example.com/path/to/page?x=1&y=2#frag", "ftp://files.example.com/pub/", "john.doe+tag@example.co.uk",
			"192.168.1.1", "2001:db8::1", "#FF5733", "rgba(0, 0, 0, 0.5)", "true", "null", "[]", "{}", "N/A",
			"I'm interested; please call me back.", "Yes -- definitely!", "Re: Re: Fwd: meeting @ 3pm", "Score: 3-1 (OT)",
			"Section 3.2(a)(iv)", "#hashtag #another", "@mention hello", "~/.bashrc", "key=value; other=thing",
			"2024-10-19T14:10:00+08:00", "Mon, 19 Oct 2024 06:10:00 GMT"},
		"base64": {base64.StdEncoding.EncodeToString([]byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 4))),
			base64.StdEncoding.EncodeToString([]byte(`{"user":1,"exp":1730000000}`)),
			base64.URLEncoding.EncodeToString([]byte("a binary-ish \x00\x01\x02 payload with ~ and ?")),
			"data:application/pdf;base64,JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURlY29kZT4+CnN0cmVhbQp4nDPQM1Qo5ypUMFAw0DMwslAwtTTVMzIxV7AwMdSzMDNWKErlCtdSyOMyVDAAQhSXh6WeKZheaV8AAIgFCs8KZW5kc3RyZWFtCmVuZG9iagoK",
			"data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=",
			"data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="red"/></svg>`))},
	}
	var corpus []evalRequest
	for _, category := range []string{"tiers", "template", "richtext", "markdown", "search", "code", "multilingual", "form", "base64"} {
		for index, value := range values[category] {
			corpus = append(corpus, evalRequest{ID: "benign-" + category + "-" + strconv.Itoa(index), Category: "value:" + category, Value: value})
		}
	}
	jsonType := map[string]string{"Content-Type": "application/json"}
	bodies := map[string][]string{
		"json_api": {`{"username":"tom","password":"P@ss#123!","remember":true}`,
			`{"items":[{"sku":"A-1","qty":2,"price":19.9},{"sku":"B-2","qty":1,"price":5}],"coupon":null,"note":"leave at door; thanks!"}`,
			`{"filter":{"status":["open","pending"],"created_at":{"gte":"2024-10-01","lt":"2024-11-01"}},"sort":"-created_at","page":2}`,
			`{"title":"Release 2.0","body":"<p>New <b>features</b>: dark mode &amp; export</p>","tags":["release","2.0"]}`,
			`{"template":"Hello {{name}}, your code is {{code}}","vars":{"name":"Li","code":"123456"}}`,
			`{"query":"SELECT name FROM users","explain":true,"comment":"docs example for the SQL tutorial page"}`,
			`{"address":{"line1":"Apt. #4B, 123 Main St.","city":"São Paulo","zip":"01310-100"},"phone":"+55 (11) 91234-5678"}`,
			`{"event":"click","props":{"path":"/a/b?c=1&d=2","ref":"https://example.com/","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}}`,
			`{"@context":"https://schema.org","@type":"Article","headline":"Hi","author":{"@type":"Person","name":"Jane"}}`,
			`{"settings":{"theme":"dark","shortcuts":{"save":"Ctrl+S","find":"Ctrl+F"},"regex":"^[a-z0-9_-]{3,16}$"}}`,
			`[{"id":1,"op":"replace","path":"/name","value":"Tom"},{"id":2,"op":"add","path":"/tags/-","value":"vip"}]`,
			`{"message":"你好，请问 10 月 1 日营业吗？","lang":"zh-CN"}`,
			`{"markdown":"# Title\n\n` + "```js\\nconst x = a && b || c;\\n```" + `\n\n| a | b |\n|---|---|"}`,
			`{"image":"data:image/png;base64,` + tinyPNG + `","name":"avatar.png"}`,
			`{"script":"function f(a, b) { return a > b ? a : b; }","lang":"javascript"}`,
			`{"expr":"price * qty - discount","cron":"*/5 * * * *","path":"C:\\\\data\\\\files"}`},
		"graphql": {`{"query":"query GetUser($id: ID!) { user(id: $id) { id name email posts(first: 10) { edges { node { id title } } } } }","variables":{"id":"42"}}`,
			`{"query":"mutation CreatePost($input: PostInput!) { createPost(input: $input) { id title } }","variables":{"input":{"title":"Hello","body":"First post!"}}}`,
			`{"query":"{ products(filter: {price_gt: 10, category: \"shoes\"}, orderBy: PRICE_DESC) { name price } }"}`,
			`{"operationName":"Search","query":"query Search($q: String!) { search(q: $q) { ... on Product { name } ... on Article { title } } }","variables":{"q":"red shoes"}}`,
			`{"query":"fragment UserParts on User { id name } query { me { ...UserParts friends { ...UserParts } } }"}`,
			`{"query":"subscription { messageAdded(room: \"general\") { id text author { name } } }"}`},
	}
	for _, category := range []string{"json_api", "graphql"} {
		for index, body := range bodies[category] {
			corpus = append(corpus, evalRequest{ID: "benign-" + category + "-" + strconv.Itoa(index), Category: category, Method: "POST",
				URI: "/api/v1/" + category, Headers: jsonType, Data: body})
		}
	}
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	png, _ := base64.StdEncoding.DecodeString(tinyPNG)
	multipart := func(name, file, kind string, content []byte) string {
		return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nMy photo (2024)\r\n--" + boundary +
			"\r\nContent-Disposition: form-data; name=\"" + name + "\"; filename=\"" + file + "\"\r\nContent-Type: " + kind + "\r\n\r\n" +
			string(content) + "\r\n--" + boundary + "--\r\n"
	}
	uploads := []string{multipart("file", "photo.png", "image/png", png),
		multipart("file", "notes.txt", "text/plain", []byte("Meeting notes: {{agenda}} at 3pm; bring laptop & charger.\n")),
		multipart("file", "data.csv", "text/csv", []byte("id,name,price\n1,\"Shoe, red\",19.90\n2,O'Neil Hat,5\n")),
		multipart("file", "config.json", "application/json", []byte(`{"debug":false,"items":[1,2,3]}`))}
	for index, body := range uploads {
		corpus = append(corpus, evalRequest{ID: "benign-upload-" + strconv.Itoa(index), Category: "upload", Method: "POST", URI: "/upload",
			Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=" + boundary}, Data: body})
	}
	browser := map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Referer": "https://www.google.com/",
		"Cookie": "_ga=GA1.2.1234567890.1700000000; _gid=GA1.2.987654321.1700000000; session=eyJ1aWQiOjQyfQ.ZxYz.abc-DEF_123; theme=dark; cart=%7B%22items%22%3A%5B1%2C2%5D%7D"}
	for index, uri := range []string{"/", "/products?category=shoes&sort=price_desc&page=2", "/search?q=%E7%BA%A2%E8%89%B2%E8%BF%9E%E8%A1%A3%E8%A3%99",
		"/a/b/c.html?utm_source=newsletter&utm_medium=email&utm_campaign=2024-10", "/api/items?ids=1,2,3&fields=id,name,price",
		"/blog/2024/10/how-to-use-select-and-union-types", "/static/js/app.3f2a1b.js", "/user/profile?tab=orders&from=2024-01-01&to=2024-10-19"} {
		corpus = append(corpus, evalRequest{ID: "benign-browse-" + strconv.Itoa(index), Category: "browse", Method: "GET", URI: uri, Headers: browser})
	}
	return corpus
}
