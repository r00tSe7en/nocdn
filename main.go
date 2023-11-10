package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/projectdiscovery/cdncheck"
)

func main() {
	// Define command line arguments
	inputFile := flag.String("i", "", "Input file name containing IP addresses")
	outputFile := flag.String("o", "", "Output file name")
	flag.Parse()

	client := cdncheck.New()

	var input *os.File
	var output *os.File
	var err error

	// Check if input file name is provided
	if *inputFile != "" {
		// Read IP addresses from a file
		input, err = os.Open(*inputFile)
		if err != nil {
			fmt.Printf("Failed to open input file: %s\n", err.Error())
			return
		}
		defer input.Close()
	} else {
		// Check if data is being piped in through standard input
		fileInfo, _ := os.Stdin.Stat()
		if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			input = os.Stdin
		} else {
			fmt.Println("Please provide an input file name or pipe the data through standard input")
			return
		}
	}

	// Decide whether to write to a file or print to the console
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Failed to create output file: %s\n", err.Error())
			return
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Create a writer for the output file or console
	writer := bufio.NewWriter(output)

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		ipStr := scanner.Text()
		ipStr = strings.TrimSpace(ipStr)

		ip := net.ParseIP(ipStr)
		if ip == nil {
			fmt.Fprintf(writer, "Invalid IP address: %s\n", ipStr)
			continue
		}

		matchedCDN, _, err := client.CheckCDN(ip)
		if err != nil {
			fmt.Fprintf(writer, "CDN check error: %s\n", err.Error())
			continue
		}

		matchedWAF, _, err := client.CheckWAF(ip)
		if err != nil {
			fmt.Fprintf(writer, "WAF check error: %s\n", err.Error())
			continue
		}

		if !matchedCDN && !matchedWAF {
			fmt.Fprintln(writer, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Failed to read input: %s\n", err.Error())
	}

	// Flush the buffer and write to the output file or console
	writer.Flush()

	if *outputFile != "" {
		fmt.Println("Processing completed. Output written to", *outputFile)
	}
}