package main

import (
	"fmt"
	"hash/fnv"
	"slices"
	"sort"

	"github.com/google/uuid"
)

// Server represents a physical server with a UUID.
type Server struct {
	ID      uuid.UUID
	Address string
}

// VirtualNode represents a virtual node with a UUID.
type VirtualNode struct {
	ID     uuid.UUID
	Hash   uint32
	Server *Server
}

// ConsistentHashRing implements a consistent hash ring with virtual nodes.
type ConsistentHashRing struct {
	vnodeHashes      []uint32               // Sorted list of vnode hashes
	hashToServer     map[uint32]*Server     // Map from vnode hash to server
	serverToVnodeMap map[uuid.UUID][]uint32 // Map from server ID to its vnode hashes
	vnodesPerServer  int
}

// NewConsistentHashRing creates a new hash ring.
func NewConsistentHashRing(vnodesPerServer int) *ConsistentHashRing {
	return &ConsistentHashRing{
		hashToServer:     make(map[uint32]*Server),
		serverToVnodeMap: make(map[uuid.UUID][]uint32),
		vnodesPerServer:  vnodesPerServer,
	}
}

// hashFunc hashes a string to a uint32 using FNV-1a.
func hashFunc(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}

// AddServer adds a physical server with multiple virtual nodes.
func (ring *ConsistentHashRing) AddServer(server *Server) {
	vnodeHashes := make([]uint32, 0, ring.vnodesPerServer)
	for range ring.vnodesPerServer {
		vnodeID := uuid.New() // Unique UUID for each vnode
		hash := hashFunc(vnodeID.String())
		// Avoid duplicate vnodes (very rare)
		if _, exists := ring.hashToServer[hash]; exists {
			continue
		}
		ring.vnodeHashes = append(ring.vnodeHashes, hash)
		ring.hashToServer[hash] = server
		vnodeHashes = append(vnodeHashes, hash)
	}
	ring.serverToVnodeMap[server.ID] = vnodeHashes
	slices.Sort(ring.vnodeHashes)
}

// RemoveServer removes all virtual nodes for a server.
func (ring *ConsistentHashRing) RemoveServer(server *Server) {
	vnodeHashes, exists := ring.serverToVnodeMap[server.ID]
	if !exists {
		return
	}
	// Remove vnodes from hashToServer
	for _, hash := range vnodeHashes {
		delete(ring.hashToServer, hash)
	}
	// Remove vnodes from vnodeHashes slice
	newVnodeHashes := make([]uint32, 0, len(ring.vnodeHashes)-len(vnodeHashes))
	vnodeSet := make(map[uint32]struct{}, len(vnodeHashes))
	for _, hash := range vnodeHashes {
		vnodeSet[hash] = struct{}{}
	}
	for _, hash := range ring.vnodeHashes {
		if _, found := vnodeSet[hash]; !found {
			newVnodeHashes = append(newVnodeHashes, hash)
		}
	}
	ring.vnodeHashes = newVnodeHashes
	// Remove from serverToVnodeMap
	delete(ring.serverToVnodeMap, server.ID)
}

// GetServer returns the server responsible for the given request UUID.
func (ring *ConsistentHashRing) GetServer(requestID uuid.UUID) *Server {
	if len(ring.vnodeHashes) == 0 {
		return nil
	}
	keyHash := hashFunc(requestID.String())
	idx := sort.Search(len(ring.vnodeHashes), func(i int) bool {
		return ring.vnodeHashes[i] >= keyHash
	})
	if idx == len(ring.vnodeHashes) {
		idx = 0 // Wrap around
	}
	vnodeHash := ring.vnodeHashes[idx]
	return ring.hashToServer[vnodeHash]
}

// Example usage
func main() {
	ring := NewConsistentHashRing(100) // 100 virtual nodes per server

	s1 := &Server{ID: uuid.New(), Address: "10.0.0.1"}
	s2 := &Server{ID: uuid.New(), Address: "10.0.0.2"}
	s3 := &Server{ID: uuid.New(), Address: "10.0.0.3"}

	ring.AddServer(s1)
	ring.AddServer(s2)
	ring.AddServer(s3)

	// Map some request UUIDs to servers
	fmt.Println("Initial mapping:")
	for i := 0; i < 50; i++ {
		reqID := uuid.New()
		server := ring.GetServer(reqID)
		fmt.Printf("Request %s is handled by server %s (ID: %s)\n", reqID, server.Address, server.ID)
	}

	// Remove a server and see remapping
	fmt.Printf("\nRemoving server %s...\n", s2.Address)
	ring.RemoveServer(s2)
	for i := 0; i < 50; i++ {
		reqID := uuid.New()
		server := ring.GetServer(reqID)
		fmt.Printf("Request %s is now handled by server %s (ID: %s)\n", reqID, server.Address, server.ID)
	}
}
