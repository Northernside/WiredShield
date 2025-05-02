package ssl

import (
	"errors"
	"fmt"
	"wired/modules/logger"
	"wired/modules/types"
	wired_dns "wired/services/dns"

	"github.com/miekg/dns"

	"golang.org/x/crypto/acme"
)

func dns01Handling(domain, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}

	if authz.Status == acme.StatusValid {
		logger.Println(fmt.Sprintf("Authorization for %s is already valid", domain))
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

	id, err := wired_dns.AddRecord(domain+".", types.DNSRecord{
		Record: &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_acme-challenge." + domain + ".",
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
	})
	if err != nil {
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
		err := wired_dns.RemoveRecord(id)
		if err != nil {
			fmt.Printf("Error removing record: %v\n", err)
		}
	}()

	return nil
}
