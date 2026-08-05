package matcher

import (
	"fmt"
	"log"
	"os"
	"time"

	"nvd-engine/pkd/models"

	"github.com/resendlabs/resend-go"
)

// SendCveEmails sends email notifications for newly created CVE tickets
// using the Resend API. Only sends for tickets where owner_email is set.
//
// Pipeline stage 6b: Called by main.go after CreateTickets.
// Emails are sent only to the owner of the affected asset.
//
// Requires the RESEND_API_KEY environment variable to be set.
// If the key is missing, a warning is logged and no emails are sent.
func SendCveEmails(tickets []models.CveTicket) {
	if len(tickets) == 0 {
		return
	}

	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Println("WARNING: RESEND_API_KEY not set, skipping email notifications")
		return
	}

	client := resend.NewClient(apiKey)

	// Group tickets by asset so we send one email per device, not one per CVE.
	ticketsByAsset := make(map[string][]models.CveTicket)
	for _, ticket := range tickets {
		assetKey := ticket.AssetID.String()
		ticketsByAsset[assetKey] = append(ticketsByAsset[assetKey], ticket)
	}

	var sent, skipped int
	for _, assetTickets := range ticketsByAsset {
		if len(assetTickets) == 0 {
			continue
		}

		ownerEmail := assetTickets[0].OwnerEmail
		if ownerEmail == "" {
			skipped++
			continue
		}

		hostname := assetTickets[0].Hostname
		ipAddress := assetTickets[0].IPAddress
		assetSummary := fmt.Sprintf("Device: %s (%s)", hostname, ipAddress)
		if hostname == "" {
			assetSummary = fmt.Sprintf("Device ID: %s", assetTickets[0].AssetID.String())
		}

		subject := fmt.Sprintf("[CVE Alert] %d new vulnerabilities for %s", len(assetTickets), assetSummary)

		var rows string
		for _, ticket := range assetTickets {
			days := int(time.Until(ticket.DueDate).Hours() / 24)
			if days < 0 {
				days = 0
			}
			rows += fmt.Sprintf(
				`<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>%s</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%d</td><td style="padding: 8px; border-bottom: 1px solid #ddd;">%s</td></tr>`,
				ticket.CveID,
				ticket.Severity,
				fmt.Sprintf("%.1f", ticket.CvssScore),
				ticket.Product,
				ticket.Version,
				ticket.Priority,
				days,
				ticket.DueDate.Format("2006-01-02"),
			)
		}

		body := fmt.Sprintf(`
<html>
<body style="font-family: Arial, sans-serif; padding: 20px;">
<h2 style="color: #d9534f;">CVE Vulnerabilities Detected</h2>
<p style="margin-bottom: 16px;">%s</p>
<table style="border-collapse: collapse; width: 100%%; max-width: 800px;">
<tr>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">CVE ID</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Severity</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">CVSS</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Product</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Version</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Priority</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Days</th>
<th style="padding: 8px; border-bottom: 2px solid #ddd; text-align: left;">Due Date</th>
</tr>
%s
</table>
<p style="margin-top: 20px; color: #666;">
This notification summarizes newly created CVE tickets for the device. Please remediate the vulnerabilities within the SLA timeframe.
</p>
</body>
</html>`, assetSummary, rows)

		params := &resend.SendEmailRequest{
			From:    "CVE Matcher <onboarding@resend.dev>",
			To:      []string{ownerEmail},
			Subject: subject,
			Html:    body,
		}

		_, err := client.Emails.Send(params)
		if err != nil {
			log.Printf("Error sending email to %s for asset %s: %v", ownerEmail, assetTickets[0].AssetID.String(), err)
			continue
		}
		sent++
	}

	log.Printf("Sent %d/%d device notifications (%d skipped - no owner email)", sent, len(ticketsByAsset), skipped)
}
