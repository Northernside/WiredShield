package ssl

import (
	"errors"
	"fmt"
	"wired/modules/logger"
	"wired/modules/postgresql"
	"wired/modules/types"

	"github.com/miekg/dns"

	wired_dns "wired/services/dns"

	"golang.org/x/crypto/acme"
)

func dns01Handling(domains []string, authzURL string) error {
	for _, domain := range domains {
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
		var owner *types.User

		postgresql.UsersMu.RLock()
		defer func() {
			err := wired_dns.DeleteRecord(owner, id)
			if err != nil {
				return
			}

			postgresql.UsersMu.RUnlock()
		}()

		owner = postgresql.Users[wired_dns.DomainDataIndexName[domain].Owner]
		if owner == nil {
			postgresql.Users[wired_dns.DomainDataIndexName[domain].Owner] = &types.User{
				Id: wired_dns.DomainDataIndexName[domain].Owner,
			}
		}

		err = postgresql.GetUser(owner)
		if err != nil {
			return err
		}

		id, err = wired_dns.CreateRecord(owner, wired_dns.DomainDataIndexName[domain].Id, &types.DNSRecord{
			RR: &dns.TXT{
				Hdr: dns.RR_Header{Name: dns.Fqdn("_acme-challenge." + domain), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
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
	}

	return nil
}
