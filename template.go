package main

// escaped data
const tpl = `#### VirusTotal
{{- if eq .ResponseCode 1 }}
| Ratio      | Link         | API         | Scanned     |
|------------|--------------|-------------|-------------|
| {{.Ratio}} | [link]({{.Permalink}}) | {{if .FirstSeen}}Private{{else}}Public{{end}} | {{.ScanDate}} |
{{- else }}
- Not found
{{- end }}
`

// var vt ResultsData
// err := mapstructure.Decode(virustotal, &vt)
// utils.Assert(err)
//
// fmt.Println("#### VirusTotal")
// if vt.ResponseCode == 0 {
// 	fmt.Println(" - Not found")
// } else {
// 	table := clitable.New([]string{"Ratio", "Link", "API", "Scanned"})
// 	table.AddRow(map[string]interface{}{
// 		"Ratio": getRatio(vt.Positives, vt.Total),
// 		"Link":  fmt.Sprintf("[link](%s)", vt.Permalink),
// 		"API":   "Public",
// 		// "API":     vt.ApiType,
// 		"Scanned": vt.ScanDate,
// 	})
// 	table.Markdown = true
// 	table.Print()
// }
