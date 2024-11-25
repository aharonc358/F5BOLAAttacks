package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type LogEntry struct {
	Request struct {
		URL               string `json:"url"`
		QueryStringParams string `json:"query_string_params"`
		Headers           string `json:"headers"`
	} `json:"request"`
	Response struct {
		StatusClass string `json:"status_class"`
	} `json:"response"`
}

type SuspiciousActivity struct {
	URL         string
	Token       string
	StatusClass string
}

type UserSuspiciousActivities struct {
	TotalSuspiciousMovements int
	Activities               []SuspiciousActivity
}

func extractToken(headers string) string {
	for _, line := range strings.Split(headers, "\n") {
		if strings.HasPrefix(line, "Authorization: Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Authorization: Bearer "))
		}
	}
	return ""
}

func DetectBOLAAttacks(filename string) (map[string]UserSuspiciousActivities, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	userActivities := make(map[string]UserSuspiciousActivities)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal([]byte(scanner.Text()), &entry); err != nil {
			continue // Skip invalid entries
		}

		// Check if response status is 4xx
		if entry.Response.StatusClass == "4xx" {
			token := extractToken(entry.Request.Headers)
			if token != "" {
				// Get current user activities or create new entry
				currentActivities := userActivities[token]

				// Add new suspicious activity
				suspiciousActivity := SuspiciousActivity{
					URL:         entry.Request.URL,
					Token:       token,
					StatusClass: entry.Response.StatusClass,
				}
				currentActivities.Activities = append(currentActivities.Activities, suspiciousActivity)
				currentActivities.TotalSuspiciousMovements++

				userActivities[token] = currentActivities
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return userActivities, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <log_file>")
		os.Exit(1)
	}

	userActivities, err := DetectBOLAAttacks(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Identify potential attackers (more than 3 suspicious movements)
	potentialAttackers := 0
	for token, activities := range userActivities {
		if activities.TotalSuspiciousMovements > 3 {
			potentialAttackers++
			fmt.Printf("\nPotential Attacker Detected:\n")
			fmt.Println(strings.Repeat("-", 80))
			fmt.Printf("Token: %s\n", token)
			fmt.Printf("Total Suspicious Movements: %d\n", activities.TotalSuspiciousMovements)

			fmt.Println("\nDetailed Suspicious Activities:")
			for _, activity := range activities.Activities {
				fmt.Printf("URL: %s\n", activity.URL)
				fmt.Printf("Status: %s\n", activity.StatusClass)
				fmt.Println(strings.Repeat("-", 40))
			}
		}
	}

	if potentialAttackers == 0 {
		fmt.Println("No potential attackers detected.")
	} else {
		fmt.Printf("\nTotal Potential Attackers: %d\n", potentialAttackers)
	}
}
