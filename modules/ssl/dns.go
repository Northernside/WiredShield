package ssl

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/acme"
)

func dns01Handling(domain, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}

	if authz.Status != acme.StatusPending {
		return errors.New(fmt.Sprintf("authorization status '%s' not pending", authz.Status))
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

	/*challengeText, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}

	var id uint64
	snowflake, err := snowflake.NewSnowflake(512)
	if err != nil {
		return err
	}

	id = snowflake.GenerateID()
	txtRecord := db.TXTRecord{
		ID:        id,
		Domain:    "_acme-challenge." + domain,
		Text:      challengeText,
		Protected: false,
	}

	err = db.InsertRecord(txtRecord, false)
	if err != nil {
		return errors.Errorf("failed to update TXT record: %v", err)
	}*/

	_, err = client.Accept(ctx, chal)
	if err != nil {
		return err
	}

	_, err = client.WaitAuthorization(ctx, chal.URI)
	if err != nil {
		return err
	}

	/*defer func() {
		err = db.DeleteRecord(id, "_acme-challenge."+domain, false)
		if err != nil {
			fmt.Printf("failed to delete TXT record: %v", err)
		}
	}()*/

	return nil
}
