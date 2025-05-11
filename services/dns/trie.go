package dns

import (
	"strings"
	"sync"
	"wired/modules/types"

	"slices"

	"github.com/miekg/dns"
)

var (
	ZonesMutex = &sync.RWMutex{}
	UserZones  = make(map[string]map[string]*trieNode)
	Zones      = &dnsTrie{
		root: &trieNode{
			children: make(map[string]*trieNode),
			records:  []*types.DNSRecord{},
		},
	}
	IdIndex = make(map[string]*indexedRecord)
)

type trieNode struct {
	children map[string]*trieNode
	records  []*types.DNSRecord
}

type indexedRecord struct {
	Record *types.DNSRecord
	Node   *trieNode
	Index  int
	Path   []string
}

type dnsTrie struct {
	root *trieNode
	mu   sync.RWMutex
}

func (trie *dnsTrie) Insert(userId string, record *types.DNSRecord) *trieNode {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	if UserZones[userId] == nil {
		UserZones[userId] = make(map[string]*trieNode)
	}

	domain := record.Record.Header().Name
	labels := reverse(domainToLabels(domain))
	node := trie.root

	for _, label := range labels {
		if node.children[label] == nil {
			node.children[label] = &trieNode{
				children: make(map[string]*trieNode),
			}
		}

		node = node.children[label]
	}

	record.Record.Header().Name = dns.Fqdn(domain)
	node.records = append(node.records, record)

	UserZones[userId][domain] = node
	IdIndex[record.Metadata.ID] = &indexedRecord{
		Record: record,
		Node:   node,
		Index:  len(node.records) - 1,
	}

	return node
}

func (trie *dnsTrie) Get(domain string) ([]*types.DNSRecord, bool) {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	fqdn := dns.Fqdn(domain)
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	reversedLabels := reverse(labels)

	node := trie.root
	for _, label := range reversedLabels {
		if node.children[label] == nil {
			return nil, false
		}

		node = node.children[label]
	}

	if len(node.records) == 0 {
		return nil, false
	}

	return node.records, true
}

func (trie *dnsTrie) Delete(userId, recordId string) bool {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	indexed, ok := IdIndex[recordId]
	if !ok {
		return false
	}

	node := indexed.Node
	idx := indexed.Index

	if userZones, ok := UserZones[userId]; ok {
		for domain, n := range userZones {
			if n == node {
				delete(userZones, domain)
				break
			}
		}
	}

	node.records = slices.Delete(node.records, idx, idx+1)
	delete(IdIndex, recordId)

	for i := idx; i < len(node.records); i++ {
		rec := node.records[i]
		IdIndex[rec.Metadata.ID] = &indexedRecord{
			Record: rec,
			Node:   node,
			Index:  i,
			Path:   indexed.Path,
		}
	}

	curr := trie.root
	for _, label := range indexed.Path {
		child := curr.children[label]
		if len(child.records) == 0 && len(child.children) == 0 {
			delete(curr.children, label)
			break
		}

		curr = child
	}

	return true
}

func reverse(s []string) []string {
	reversed := make([]string, len(s))
	for i, j := 0, len(s)-1; j >= 0; i, j = i+1, j-1 {
		reversed[i] = s[j]
	}

	return reversed
}

func domainToLabels(domain string) []string {
	return strings.Split(strings.TrimSuffix(domain, "."), ".")
}
