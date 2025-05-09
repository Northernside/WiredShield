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
	}
)

type trieNode struct {
	children map[string]*trieNode
	records  []types.DNSRecord
}

type dnsTrie struct {
	root *trieNode
	mu   sync.RWMutex
}

func (trie *dnsTrie) insert(domain string, record types.DNSRecord) {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	labels := domainToLabels(domain)
	reversedLabels := reverse(labels)
	node := trie.root
	for _, label := range reversedLabels {
		if node.children[label] == nil {
			node.children[label] = &trieNode{
				children: make(map[string]*trieNode),
			}
		}

		node = node.children[label]
	}

	record.Record.Header().Name = dns.Fqdn(domain)
	node.records = append(node.records, record)
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

func (trie *dnsTrie) walkTrieByID(id string, action func(node *trieNode, path []string, index int) (done bool)) {
	var walk func(node *trieNode, path []string) bool
	walk = func(node *trieNode, path []string) bool {
		for i, record := range node.records {
			if record.Metadata.ID == id {
				return action(node, path, i)
			}
		}

		for label, child := range node.children {
			if walk(child, append(path, label)) {
				return true
			}
		}

		return false
	}

	walk(trie.root, []string{})
}

func (trie *dnsTrie) getByID(id string) (types.DNSRecord, bool) {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	var found types.DNSRecord
	var ok bool

	trie.walkTrieByID(id, func(node *trieNode, path []string, index int) bool {
		found = node.records[index]
		ok = true
		return true
	})

	return found, ok
}

func (trie *dnsTrie) deleteByID(id string) bool {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	var deleted bool
	var cleanupPath []struct {
		node  *trieNode
		label string
	}

	trie.walkTrieByID(id, func(node *trieNode, path []string, index int) bool {
		node.records = slices.Delete(node.records, index, index+1)
		deleted = true

		n := trie.root
		for _, label := range path {
			cleanupPath = append(cleanupPath, struct {
				node  *trieNode
				label string
			}{node: n, label: label})

			n = n.children[label]
		}

		return true
	})

	for i := len(cleanupPath) - 1; i >= 0; i-- {
		parent := cleanupPath[i].node
		label := cleanupPath[i].label
		child := parent.children[label]
		if len(child.records) == 0 && len(child.children) == 0 {
			delete(parent.children, label)
		}
	}

	return deleted
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
