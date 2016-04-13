package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/tealeg/xlsx"
)

const (
	version = "0.0.2"
	tool    = "drone-xlsx"
	usage   = `
Usage:
  drone-issues-xlsx <id> <filename>
  export LAIR_ID=<id>; drone-issues-xlsx <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
`
)

func getcomment(hosts *[]lair.Host, title, ip string, port int) string {
	for _, host := range *hosts {
		if host.IPv4 == ip {
			for _, service := range host.Services {
				if service.Port == port {
					for _, note := range service.Notes {
						if strings.Contains(note.Title, title) {
							return note.Content
						}
					}
				}
			}
		}
	}
	return ""
}

func gethostname(ip string, hosts *[]lair.Host) string {
	for _, host := range *hosts {
		if host.IPv4 == ip {
			return strings.Join(host.Hostnames, "\n")
		}
	}
	return ""
}

func writesheet(project *lair.Project, outfile string) {
	header := []string{
		"#",
		"Title",
		"CVSS",
		"Rating",
		"Description",
		"Evidence",
		"Solution",
		"CVEs",
		"References",
		"Host",
		"Hostname(s)",
		"Port",
		"Service Note",
		"Issue Note(s)",
	}

	var file *xlsx.File
	var sheet *xlsx.Sheet
	var row *xlsx.Row
	var cell *xlsx.Cell

	file = xlsx.NewFile()
	sheet, err := file.AddSheet(project.Name)
	if err != nil {
		log.Printf(err.Error())
	}
	row = sheet.AddRow()
	for _, h := range header {
		cell = row.AddCell()
		cell.Value = h
	}

	for count, issue := range project.Issues {
		var issuenote string
		for _, note := range issue.Notes {
			issuenote += note.Title
			issuenote += note.Content + "\n"
		}
		for _, host := range issue.Hosts {
			var refs []string
			for _, ref := range issue.References {
				refs = append(refs, ref.Link)
			}

			row = sheet.AddRow()
			cell = row.AddCell()
			cell.SetInt(count + 1)
			cell = row.AddCell()
			cell.Value = issue.Title
			cell = row.AddCell()
			cell.SetFloat(issue.CVSS)
			cell = row.AddCell()
			cell.Value = issue.Rating
			cell = row.AddCell()
			cell.Value = issue.Description
			cell = row.AddCell()
			cell.Value = issue.Evidence
			cell = row.AddCell()
			cell.Value = issue.Solution
			cell = row.AddCell()
			cell.Value = strings.Join(issue.CVEs, "\n")
			cell = row.AddCell()
			cell.Value = strings.Join(refs, "\n")
			cell = row.AddCell()
			cell.Value = host.IPv4
			cell = row.AddCell()
			cell.Value = gethostname(host.IPv4, &project.Hosts)
			cell = row.AddCell()
			cell.SetInt(host.Port)
			cell = row.AddCell()
			cell.Value = getcomment(&project.Hosts, issue.Title, host.IPv4, host.Port)
			cell = row.AddCell()
			cell.Value = issuenote
		}
	}
	err = file.Save(outfile)
	if err != nil {
		log.Fatal("Fatal: Unable to write file")
	}
}

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")

	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")

	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})
	if err != nil {
		log.Fatalf("Fatal: Error setting up client. Error %s", err.Error())
	}

	project, err := c.ExportProject(lairPID)
	if err != nil {
		log.Fatalf("Fatal: Unable to export project. Error %s", err.Error())
	}

	writesheet(&project, filename)

	log.Println("Success: Operation completed successfully")
}
