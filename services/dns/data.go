package dns

import (
	"fmt"
	"strings"
	"wired/modules/event"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var (
	DNSEventChannel = make(chan event.Event)
	DNSEventBus     = event.NewEventBus("dns")
)

func ListRecordsByZone(zone string) ([]*types.DNSRecord, error) {
	zone = strings.ToLower(zone)
	reversedLabels := reverse(domainToLabels(dns.Fqdn(zone)))

	Zones.mu.RLock()
	defer Zones.mu.RUnlock()

	currentNode := Zones.root
	for _, label := range reversedLabels {
		child, ok := currentNode.children[label]
		if !ok {
			return nil, fmt.Errorf("zone %s not found", zone)
		}

		currentNode = child
	}

	var records []*types.DNSRecord
	var walk func(*trieNode)
	walk = func(node *trieNode) {
		records = append(records, node.records...)
		for _, child := range node.children {
			walk(child)
		}
	}

	walk(currentNode)
	return records, nil
}

func ListRecords() map[string][]*types.DNSRecord {
	result := make(map[string][]*types.DNSRecord)

	var walk func(node *trieNode, path []string)
	walk = func(node *trieNode, path []string) {
		if len(node.records) > 0 {
			domain := strings.Join(reverse(path), ".")
			result[dns.Fqdn(domain)] = node.records
		}

		for label, child := range node.children {
			walk(child, append(path, label))
		}
	}

	Zones.mu.RLock()
	defer Zones.mu.RUnlock()
	walk(Zones.root, []string{})

	return result
}
