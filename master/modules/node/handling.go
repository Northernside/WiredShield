package node

import (
	"fmt"
	"time"
	packet "wired/modules/packets"
	"wired/modules/protocol"
	"wired/modules/utils"
)

func SendChallenge(connection *protocol.Conn, recvLoginPacket *packet.Login) error {
	// challenge text -> "$key-$time.Now().UnixMilli()-$random-8-char-string"
	challenge := fmt.Sprintf("%s-%d-%s",
		recvLoginPacket.Key,
		time.Now().UnixMilli(),
		utils.RandomString(8),
	)

	packet.PendingChallenges[challenge] = packet.Challenge{
		Challenge: challenge,
		Key:       recvLoginPacket.Key,
	}

	return connection.SendPacket(packet.ID_ChallengeStart, packet.Challenge{
		Challenge: challenge,
	})
}

/*
	node := new(types.NodeInfo)
	// node.NodeConfig =
	node.Conn = connection
		   	if !types.ValidArch(login.ARCH) {
		   		node.SendError("Invalid Arch")
		   		return nil, errs.CloseNow
		   	}

		   node.Address, err = getAddress(node.Conn.RemoteAddr().String())

		   	if err != nil {
		   		node.SendError("something failed")
		   		return nil, errs.CloseNow
		   	}

		   //get nodetemplate based on key

		   var nt *localtypes.NodeTemplate
		   storage.NodeTemplatesMux.Lock()

		   	for _, v := range storage.NodeTemplates {
		   		if v.Key == login.Key {
		   			nt = v
		   			break
		   		}
		   	}

		   storage.NodeTemplatesMux.Unlock()

		   	if nt == nil {
		   		node.SendError("Invalid Key")
		   		return nil, errs.CloseNow
		   	}

		   node.Mux = &sync.Mutex{}

		   if nt.IsOnline() /*&& !nt.AttachedNode.Upgrading
		{
			node.SendError("Node is already Online")
			return nil, errs.CloseNow
		}

		if len(login.Listeners) < 1 {
			node.SendError("Need at least one listener")
			return nil, errs.CloseNow
		}

		node.Name = nt.Name
		node.Connected = time.Now().Unix()
		node.Version = login.Version
		node.Listeners = login.Listeners
		node.PID = login.PID
		node.TemplateID = nt.ID
		node.Hash = nt.Hash
		node.BinaryHash = login.Hash
		node.TunnelPubKey = login.TunnelPubkey
		node.Arch = login.ARCH
		node.LastPing = new(int64)
		node.LastPong = new(int64)
		node.QuicPort = int(login.QuicPort)
		node.OS = "linux"
		node.Inheritor = node

		err = node.SendPacket(packet.ID_Ping, nil)
		if err != nil {
			return nil, err
		}

		node.Mux.Lock()
		atomic.StoreInt64(node.LastPing, time.Now().UnixMilli())

		node.Mux.Unlock()

		err = node.SendPacket(packet.ID_Config, storage.NodeConfig)
		if err != nil {
			return nil, err
		}

		debug(node.SendPacket(packet.ID_NodeSelfInfo, packet.NodeSelfInfo{
			ID:   nt.ID,
			Name: node.Name,
		}))

		nodeHash, err := getRightNodeHash(node)
		if err != nil {
			node.SendError(err.Error())
			return nil, errs.CloseNow
		}
		rightHash := bytes.Equal(login.Hash, nodeHash) || constants.IsDev()

		newInstance := isUpgradedInstance(nt.Name, *node.Address) && !node.Upgrading

		if !newInstance && !rightHash {
			Upgrade(&node.Connectable)
			return nil, nil
		}

		if !rightHash {
			return nil, nil
		}

		s, err := json.Marshal(storage.Samples.EntrySet())
		if err != nil {
			return nil, err
		}

		err = node.SendPacket(packet.ID_Routes, packet.Routes{
			Routes:  storage.Routes.Values(),
			Samples: s,
		})
		if err != nil {
			return nil, err
		}

		// get players
		err = node.SendPacket(packet.ID_GetPlayers, nil)
		if err != nil {
			debug(err)
			return nil, nil
		}

		// send banned players
		debug(node.SendPacket(packet.ID_WSBannedPlayers, storage.BannedPlayers.EntrySet()))

		for _, v := range GetTunnels() {
			_ = node.SendPacket(packet.ID_TunnelAdd, v)
		}

		if newInstance && rightHash {
			constants.Colorln(constants.Sprintf("Node '%s' Upgraded Successfully", nt.Name), constants.ColorGreen)
			removeUpgradingNode(nt.Name, node.Address.IP)
		}

		//normal
		if !newInstance && rightHash {
			log.Printf("%s Node '%s' (%s)\n", constants.Color("[+]", constants.ColorGreen), node.Name, node.Address.IP)
			_ = db.InsertNodeActivity(nt.ID, true)
		}

		storage.AddNode(node)
		hostname, err := node.ToHostname()
		if err == nil {
			storage.NodesLookup.Set(node.Name, hostname+config.Cloudflare.FQDN)
			login.Location.Domain = hostname + config.Cloudflare.FQDN
			storage.NodesLookupFull.Set(node.Name, login.Location)
		} else {
			utils.Debug(err)
		}
		nt.AttachedNode = node

		err = node.SendPacket(packet.ID_Ready, nil)
		if err != nil {
			return nil, err
		}*/

//for i, v := range node.Listeners {
//	rec := raydns.Record{
//		Id:    7000 + uint32((nt.ID*100)+i),
//		Name:  "geo.ray.rip.",
//		TTL:   300,
//		Smart: true,
//		Lat:   login.Location.Lat,
//		Lon:   login.Location.Lon,
//		IP:    net.ParseIP(v.IP),
//		Type:  raydns.TypeA,
//	}
//	if rec.IP.To4() == nil {
//		rec.Type = raydns.TypeAAAA
//	}
//
//	debug(raydns.AddRecord(rec))
//}
/*
	go dns.SyncGeoComplete()

	err = node.SendPacket(packet.ID_BlacklistedIPs, storage.BlockedIPS.Values())
	if err != nil {
		return nil, err
	}

	routes, err := redis.GetRoutes()
	if err != nil {
		return nil, err
	}
	return &node.Connectable, node.SendPacket(packet.ID_TempRoutes, routes)*/
