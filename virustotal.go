package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crackcomm/go-clitable"
	"github.com/levigross/grequests"
	"github.com/maliceio/go-plugin-utils/database/elasticsearch"
	"github.com/maliceio/go-plugin-utils/utils"
	"github.com/mitchellh/mapstructure"
	"github.com/urfave/cli"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "virustotal"
	category = "intel"
)

// VirusTotal is a type
type VirusTotal struct {
	Data interface{} `json:"data" structs:"data"`
	Now  string      `json:"now" structs:"now"`
}

type pluginResults struct {
	ID string     `json:"id" structs:"id,omitempty"`
	VT VirusTotal `json:"virustotal" structs:"virustotal"`
}

// virustotal json object
type virustotal struct {
	Results ResultsData `json:"virustotal"`
}

// ResultsData json object
type ResultsData struct {
	Scans        map[string]Scan `json:"scans"`
	Permalink    string          `json:"permalink"`
	Resource     string          `json:"resource"`
	ResponseCode int             `json:"response_code" mapstructure:"response_code"`
	Total        int             `json:"total"`
	Positives    int             `json:"positives"`
	ScanID       string          `json:"scan_id" mapstructure:"scan_id"`
	ScanDate     string          `json:"scan_date" mapstructure:"scan_date"`
	VerboseMsg   string          `json:"verbose_msg" mapstructure:"verbose_msg"`
	MD5          string          `json:"md5"`
	Sha1         string          `json:"sha1"`
	Sha256       string          `json:"sha256"`
}

// Scan is a VirusTotal AV scan JSON object
type Scan struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

// ScanResults json object
type ScanResults struct {
	Permalink    string `json:"permalink"`
	Resource     string `json:"resource"`
	ResponseCode int    `json:"response_code" mapstructure:"response_code"`
	ScanID       string `json:"scan_id" mapstructure:"scan_id"`
	VerboseMsg   string `json:"verbose_msg" mapstructure:"verbose_msg"`
	MD5          string `json:"md5"`
	Sha1         string `json:"sha1"`
	Sha256       string `json:"sha256"`
}

type bitly struct {
	StatusCode int       `json:"status_code"`
	StatusTxt  string    `json:"status_txt"`
	Data       bitlyData `json:"data"`
}

type bitlyData struct {
	LongURL    string `json:"long_url"`
	URL        string `json:"url"`
	NewHash    int    `json:"new_hash"`
	Hash       string `json:"hash"`
	GlobalHash string `json:"global_hash"`
}

// scanFile uploads file to virustotal
func scanFile(path string, apikey string) string {
	// fmt.Println("Uploading file to virustotal...")
	fd, err := grequests.FileUploadFromDisk(path)

	if err != nil {
		log.Println("Unable to open file: ", err)
	}

	// This will upload the file as a multipart mime request
	resp, err := grequests.Post("https://www.virustotal.com/vtapi/v2/file/scan",
		&grequests.RequestOptions{
			Files: fd,
			Params: map[string]string{
				"apikey": apikey,
				// "notify_url": notify_url,
				// "notify_changes_only": bool,
			},
		})

	if err != nil {
		log.Println("Unable to make request", resp.Error)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())

	var scanResults ScanResults
	resp.JSON(&scanResults)
	// fmt.Printf("%#v", scanResults)

	// TODO: wait for an hour!?!?!? or create a notify URL endpoint?!?!?!
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": scanResults.Sha256,
			"scan_id":  scanResults.ScanID,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err = grequests.Get("https://www.virustotal.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	// fmt.Println(resp.String())
	return resp.String()
}

// lookupHash retreieves the virustotal file report for the given hash
func lookupHash(hash string, apikey string) map[string]interface{} {
	// NOTE: https://godoc.org/github.com/levigross/grequests
	// fmt.Println("Getting virustotal report...")
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": hash,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err := grequests.Get("https://www.virustotal.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.StatusCode == 204 {
		log.Fatalln("Used more than 4 queries per minute")
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	var results map[string]interface{}

	resp.JSON(&results)
	// resp.JSON(&vtResult)

	// var vtResult ResultsData
	// err = mapstructure.Decode(results.Data, &vtResult)
	// utils.Assert(err)

	// vtJSON, err := json.Marshal(vtResult)
	// utils.Assert(err)
	// // write to stdout
	// fmt.Println(string(vtJSON))

	// results.Now = time.Now().Format(time.RFC3339Nano)

	// t, _ := time.Parse("2006-01-02 15:04:05", vtResult.ScanDate)
	// vtResult.ScanDate = t.Format("Mon 2006Jan02 15:04:05")

	return results
}

func getRatio(positives int, total int) string {
	ratio := 100.0 * float64(positives) / float64(total)
	return fmt.Sprintf("%.f%%", ratio)
}

func shortenPermalink(longURL string) string {
	// NOTE: http://dev.bitly.com/api.html
	// https://github.com/bitly/go-simplejson
	var btl bitly

	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"access_token": "23382325dd472aed14518ec5b8c8f4c2293e114a",
			"longUrl":      longURL,
		},
	}
	resp, err := grequests.Get("https://api-ssl.bitly.com/v3/shorten", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	fmt.Println(resp.String())
	resp.JSON(&btl)

	return btl.Data.URL
}

func printMarkDownTable(virustotal map[string]interface{}) {

	var vt ResultsData
	err := mapstructure.Decode(virustotal, &vt)
	utils.Assert(err)

	fmt.Println("#### VirusTotal")
	if vt.ResponseCode == 0 {
		fmt.Println(" - Not found")
	} else {
		table := clitable.New([]string{"Ratio", "Link", "API", "Scanned"})
		table.AddRow(map[string]interface{}{
			"Ratio": getRatio(vt.Positives, vt.Total),
			"Link":  fmt.Sprintf("[link](%s)", vt.Permalink),
			"API":   "Public",
			// "API":     vt.ApiType,
			"Scanned": vt.ScanDate,
		})
		table.Markdown = true
		table.Print()
	}
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
	var apikey string
	var elasitcsearch string
	var table bool
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
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
		cli.BoolFlag{
			Name:        "table, t",
			Usage:       "output as Markdown table",
			Destination: &table,
		},
		cli.StringFlag{
			Name:        "api",
			Value:       "",
			Usage:       "VirusTotal API key",
			EnvVar:      "MALICE_VT_API",
			Destination: &apikey,
		},
		cli.StringFlag{
			Name:        "elasitcsearch",
			Value:       "",
			Usage:       "elasitcsearch address for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH",
			Destination: &elasitcsearch,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "scan",
			Aliases:   []string{"s"},
			Usage:     "Upload binary to VirusTotal for scanning",
			ArgsUsage: "FILE to upload to VirusTotal",
			Action: func(c *cli.Context) error {
				// Check for valid apikey
				if apikey == "" {
					log.Fatal(fmt.Errorf("Please supply a valid VT_API key with the flag '--api'."))
				}
				if c.Bool("verbose") {
					log.SetLevel(log.DebugLevel)
				}
				if c.Args().Present() {
					path := c.Args().First()
					// Check that file exists
					if _, err := os.Stat(path); os.IsNotExist(err) {
						utils.Assert(err)
					}
					// upload file to virustotal.com
					scanFile(path, apikey)
				} else {
					log.Fatal(fmt.Errorf("Please supply a file to upload to VirusTotal."))
				}
				return nil
			},
		},
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Get file hash scan report",
			ArgsUsage: "MD5/SHA1/SHA256 hash of file",
			Action: func(c *cli.Context) error {
				// Check for valid apikey
				if apikey == "" {
					log.Fatal(fmt.Errorf("Please supply a valid VT_API key with the flag '--api'."))
				}
				if c.Bool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				if c.Args().Present() {
					hash := c.Args().First()
					vtReport := lookupHash(hash, apikey)

					// upsert into Database
					elasticsearch.InitElasticSearch()
					elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
						ID:       utils.Getopt("MALICE_SCANID", hash),
						Name:     name,
						Category: category,
						Data:     vtReport,
					})

					if table {
						printMarkDownTable(vtReport)
					} else {
						vtJSON, err := json.Marshal(vtReport)
						utils.Assert(err)
						// write to stdout
						fmt.Println(string(vtJSON))
					}
				} else {
					log.Fatal(fmt.Errorf("Please supply a MD5/SHA1/SHA256 hash to query."))
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	utils.Assert(err)
}
