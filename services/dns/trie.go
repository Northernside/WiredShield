package dns

import (
	"strings"
	"sync"
	"wired/modules/types"

	"slices"

	"github.com/miekg/dns"
)

var (
	Zones = &dnsTrie{
		root: &trieNode{
			children: make(map[string]*trieNode),
			records:  []types.DNSRecord{},
		},
		idIndex: make(map[string]indexedRecord),
	}
)

type trieNode struct {
	children map[string]*trieNode
	records  []types.DNSRecord
}

type indexedRecord struct {
	record *types.DNSRecord
	node   *trieNode
	index  int
	path   []string
}

type dnsTrie struct {
	root    *trieNode
	mu      sync.RWMutex
	idIndex map[string]indexedRecord
}

func (trie *dnsTrie) insert(domain string, record types.DNSRecord) {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	labels := domainToLabels(domain)
	reversedLabels := reverse(labels)
	node := trie.root
	var path []string

	for _, label := range reversedLabels {
		path = append(path, label)
		if node.children[label] == nil {
			node.children[label] = &trieNode{
				children: make(map[string]*trieNode),
			}
		}

		node = node.children[label]
	}

	record.Record.Header().Name = dns.Fqdn(domain)
	node.records = append(node.records, record)

	id := record.Metadata.ID
	trie.idIndex[id] = indexedRecord{
		record: &node.records[len(node.records)-1],
		node:   node,
		index:  len(node.records) - 1,
		path:   path,
	}
}

func (trie *dnsTrie) get(domain string) ([]types.DNSRecord, bool) {
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

	records := make([]types.DNSRecord, len(node.records))
	copy(records, node.records)

	return records, true
}

func (trie *dnsTrie) deleteByID(id string) bool {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	indexed, ok := trie.idIndex[id]
	if !ok {
		return false
	}

	node := indexed.node
	idx := indexed.index
	node.records = slices.Delete(node.records, idx, idx+1)
	delete(trie.idIndex, id)

	for i := idx; i < len(node.records); i++ {
		rec := &node.records[i]
		trie.idIndex[rec.Metadata.ID] = indexedRecord{
			record: rec,
			node:   node,
			index:  i,
			path:   indexed.path,
		}
	}

	curr := trie.root
	for _, label := range indexed.path {
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
