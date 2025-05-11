package ssl

import (
	"errors"
	"fmt"
	"wired/modules/logger"
	"wired/modules/postgresql"
	"wired/modules/types"

	wired_dns "wired/services/dns"

	"github.com/miekg/dns"

	"golang.org/x/crypto/acme"
)

func dns01Handling(domains map[string]string, authzURL string) error {
	for recordId, domain := range domains {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}

		if authz.Status == acme.StatusValid {
			logger.Printf("Authorization for %s is already valid\n", domain)
			return nil
		}

		if authz.Status != acme.StatusPending {
			return fmt.Errorf("authorization status '%s' not pending", authz.Status)
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}

		if chal == nil {
			return errors.New("authorization challenge not available")
		}

		challengeText, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}

		var id string
		var user = postgresql.Users[wired_dns.IdIndex[recordId].Record.Metadata.OwnerID]

		if id, err, _ = user.AddRecord(dns.Fqdn(domain), &types.DNSRecord{
			Record: &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn("_acme-challenge." + domain),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Txt: []string{challengeText},
			},
			Metadata: types.RecordMetadata{
				Protected: false,
				Geo:       false,
			},
		}); err != nil {
			return err
		}

		_, err = client.Accept(ctx, chal)
		if err != nil {
			return err
		}

		_, err = client.WaitAuthorization(ctx, chal.URI)
		if err != nil {
			return err
		}

		defer func() {
			if err, ok := user.RemoveRecord(id); ok {
				logger.Printf("Removed DNS record for %s: %v\n", domain, err)
			} else {
				logger.Printf("Failed to remove DNS record for %s: %v\n", domain, err)
			}
		}()
	}

	return nil
}
