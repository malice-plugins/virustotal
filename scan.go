package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	"github.com/crackcomm/go-clitable"
	"github.com/parnurzeal/gorequest"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

// virustotal json object
type virustotal struct {
	Results ResultsData `json:"virustotal"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected"`
	Result   string `json:"result"`
	Engine   string `json:"engine"`
	Known    string `json:"known"`
	Updated  string `json:"updated"`
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// RunCommand runs cmd on file
func RunCommand(cmd string, args ...string) string {

	cmdOut, err := exec.Command(cmd, args...).Output()
	if len(cmdOut) == 0 {
		assert(err)
	}

	return string(cmdOut)
}

// ParsevirustotalOutput convert virustotal output into virustotal struct
func ParsevirustotalOutput(clamout string) ResultsData {

	virustotal := ResultsData{}

	lines := strings.Split(clamout, "\n")
	// Extract AV Scan Result
	result := lines[0]
	if len(result) != 0 {
		pathAndResult := strings.Split(result, ":")
		if strings.Contains(pathAndResult[1], "OK") {
			virustotal.Infected = false
		} else {
			virustotal.Infected = true
			virustotal.Result = strings.TrimSpace(strings.TrimRight(pathAndResult[1], "FOUND"))
		}
	} else {
		fmt.Println("[ERROR] empty scan result: ", result)
		os.Exit(2)
	}
	// Extract Clam Details from SCAN SUMMARY
	for _, line := range lines[1:] {
		if len(line) != 0 {
			keyvalue := strings.Split(line, ":")
			if len(keyvalue) != 0 {
				switch {
				case strings.Contains(keyvalue[0], "Known viruses"):
					virustotal.Known = strings.TrimSpace(keyvalue[1])
				case strings.Contains(line, "Engine version"):
					virustotal.Engine = strings.TrimSpace(keyvalue[1])
				}
			}
		}
	}

	virustotal.Updated = BuildTime

	return virustotal
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printMarkDownTable(virustotal virustotal) {
	fmt.Println("#### virustotal")
	table := clitable.New([]string{"Infected", "Result", "Engine", "Updated"})
	table.AddRow(map[string]interface{}{
		"Infected": virustotal.Results.Infected,
		"Result":   virustotal.Results.Result,
		"Engine":   virustotal.Results.Engine,
		// "Known":    virustotal.Results.Known,
		"Updated": virustotal.Results.Updated,
	})
	table.Markdown = true
	table.Print()
}

func updateAV() {
	fmt.Println("Updating virustotal...")
	fmt.Println(RunCommand("freshclam"))
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]

{{.Usage}}

Version: {{.Version}}{{if or .Author .Email}}

Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()
	app.Name = "virustotal"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice VirusTotal Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "post, p",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) {
				updateAV()
			},
		},
	}
	app.Action = func(c *cli.Context) {
		path := c.Args().First()

		if _, err := os.Stat(path); os.IsNotExist(err) {
			assert(err)
		}

		virustotal := virustotal{
			Results: ParsevirustotalOutput(RunCommand("/usr/bin/clamscan", "--stdout", path)),
		}

		if c.Bool("table") {
			printMarkDownTable(virustotal)
		} else {
			fprotJSON, err := json.Marshal(virustotal)
			assert(err)
			if c.Bool("post") {
				request := gorequest.New()
				if c.Bool("proxy") {
					request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
				}
				request.Post(os.Getenv("MALICE_ENDPOINT")).
					Set("Task", path).
					Send(fprotJSON).
					End(printStatus)
			}
			fmt.Println(string(fprotJSON))
		}
	}

	err := app.Run(os.Args)
	assert(err)
}
