package dns

import (
	"sync"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var (
	ZonesMutex      sync.RWMutex
	ZoneFileMutexes = make(map[string]*sync.Mutex) // domain group -> mutex

	UserZones = make(map[string]map[string]map[string]*TrieNode) // userId -> domain -> zone -> TrieNode

	Zones = make(map[string]*TrieNode) // zone -> TrieNode

	ZoneIndexId         = make(map[string]*IndexedRecord)     // recordId -> IndexedRecord
	DomainIndexId       = make(map[string]*TrieNode)          // domainId -> TrieNode
	DomainIndexName     = make(map[string]*TrieNode)          // domainName -> TrieNode
	DomainRecordIndexId = make(map[string][]*types.DNSRecord) // domainId -> DNSRecord

	DomainDataIndexId   = make(map[string]*DomainData)   // domainId/domainName -> DomainData
	DomainDataIndexName = make(map[string]*DomainData)   // domainName -> DomainData
	UserDomainIndexId   = make(map[string][]*DomainData) // userId -> DomainData

	HeaderNameIndex = make(map[string][]*types.DNSRecord) // headerName -> DNSRecord
)

type TrieNode struct {
	Owner  string
	Domain string
	Zone   string

	Children map[string]*TrieNode
	Records  []*types.DNSRecord
}

type IndexedRecord struct {
	Domain string
	Zone   string

	Record *types.DNSRecord
}

type DomainData struct {
	Id     string
	Domain string
	Owner  string
}

func InsertRecord(domainData *DomainData, record *types.DNSRecord) {
	ZonesMutex.Lock()
	defer ZonesMutex.Unlock()

	domainName := dns.Fqdn(domainData.Domain)
	zone := domainName

	labels := dns.SplitDomainName(record.RR.Header().Name)
	root := getOrCreateTrie(domainData, Zones, zone)

	node := root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.Children == nil {
			node.Children = make(map[string]*TrieNode)
		}

		if _, exists := node.Children[label]; !exists {
			node.Children[label] = &TrieNode{
				Owner:    domainData.Owner,
				Domain:   record.RR.Header().Name,
				Zone:     zone,
				Children: make(map[string]*TrieNode),
			}
		}

		node = node.Children[label]
	}

	node.Records = append(node.Records, record)
	ZoneIndexId[record.Metadata.Id] = &IndexedRecord{
		Domain: record.RR.Header().Name,
		Zone:   zone,
		Record: record,
	}

	DomainRecordIndexId[domainData.Id] = append(DomainRecordIndexId[domainData.Id], record)

	if _, ok := UserZones[domainData.Owner]; !ok {
		UserZones[domainData.Owner] = make(map[string]map[string]*TrieNode)
	}

	if _, ok := UserZones[domainData.Owner][domainName]; !ok {
		UserZones[domainData.Owner][domainName] = make(map[string]*TrieNode)
	}

	if _, ok := HeaderNameIndex[record.RR.Header().Name]; !ok {
		HeaderNameIndex[record.RR.Header().Name] = make([]*types.DNSRecord, 0)
	}
	HeaderNameIndex[record.RR.Header().Name] = append(HeaderNameIndex[record.RR.Header().Name], record)

	UserZones[domainData.Owner][domainName][zone] = root
}

func getOrCreateTrie(domainData *DomainData, storage map[string]*TrieNode, zone string) *TrieNode {
	if node, ok := storage[zone]; ok {
		return node
	}

	node := &TrieNode{
		Owner:    domainData.Owner,
		Domain:   zone,
		Zone:     zone,
		Children: make(map[string]*TrieNode),
	}

	storage[zone] = node
	return node
}

func EnsureDomainIndexes(domain DomainData) {
	if _, ok := DomainIndexId[domain.Id]; !ok {
		root := &TrieNode{
			Owner:    domain.Owner,
			Domain:   domain.Domain,
			Zone:     domain.Domain,
			Children: make(map[string]*TrieNode),
		}

		DomainIndexId[domain.Id] = root
		DomainIndexName[domain.Domain] = root
	}
}
