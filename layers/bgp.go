package layers

import (
	"encoding/binary"
	"github.com/google/gopacket"
)

func decodeBGP(data []byte, p gopacket.PacketBuilder) error {
	bgp := &BGP{}
	err := bgp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(bgp)
	p.SetApplicationLayer(bgp)
	return nil
}

type BGP struct {
	BaseLayer

	Length      uint16
	MessageType BGPMessageType
	Message     BGPMessage
}

// LayerType returns gopacket.LayerTypeBGP
func (b *BGP) LayerType() gopacket.LayerType { return LayerTypeBGP }

// Decode bgp message header. Then decode message type
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                                                               +
// |                           Marker                              |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Length               |      Type     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Taken from: https://tools.ietf.org/html/rfc4271

type BGPMessage interface {
}

type BGPMessageType uint8

const (
	BGPMessageTypeOpen         BGPMessageType = 1
	BGPMessageTypeUpdate       BGPMessageType = 2
	BGPMessageTypeNotification BGPMessageType = 3
	BGPMessageTypeKeepAlive    BGPMessageType = 4
	BGPMessageTypeRouteRefresh BGPMessageType = 5
)

func (bmt BGPMessageType) String() string {
	switch bmt {
	default:
		return "Unknown"
	case BGPMessageTypeOpen:
		return "Open"
	case BGPMessageTypeUpdate:
		return "Update"
	case BGPMessageTypeNotification:
		return "Notification"
	case BGPMessageTypeKeepAlive:
		return "KeepAlive"
	case BGPMessageTypeRouteRefresh:
		return "RouteRefresh"
	}
}

// DecodeFromBytes decodes the given bytes into this layer.
func (b *BGP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	b.BaseLayer = BaseLayer{Contents: data}

	data = data[16:] // first 16 bytes are for compatibility so we can skip
	data, b.Length = data[2:], binary.BigEndian.Uint16(data[:2])
	data, b.MessageType = data[1:], BGPMessageType(data[0])

	if len(data) > 0 { // decode bgp message
		switch b.MessageType {
		case BGPMessageTypeOpen:
			if message, err := decodeBGPOpenMessage(data, b); err == nil {
				b.Message = message
			} else {
				return err
			}
		case BGPMessageTypeUpdate:
			if message, err := decodeBGPUpdateMessage(data, b); err == nil {
				b.Message = message
			} else {
				return err
			}
		case BGPMessageTypeNotification:
		case BGPMessageTypeKeepAlive:
			// keep alive message just consists out of the message header
			break
		}
	}

	return nil
}

// CanDecode implements gopacket.DecodingLayer.
func (b *BGP) CanDecode() gopacket.LayerClass {
	return LayerTypeBGP
}

// NextLayerType implements gopacket.DecodingLayer.
func (b *BGP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns nil.
func (b *BGP) Payload() []byte {
	return nil
}

// Decode bgp open message
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+
// |    Version    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     My Autonomous System      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Hold Time           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         BGP Identifier                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Opt Parm Len  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |             Optional Parameters (variable)                    |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Taken from: https://tools.ietf.org/html/rfc4271

type BGPCapabilityCode uint8

const (
	BGPCapabilityCodeReserved               BGPCapabilityCode = 0
	BGPCapabilityCodeMultiProtocol          BGPCapabilityCode = 1
	BGPCapabilityCodeRouteRefresh           BGPCapabilityCode = 2
	BGPCapabilityCodeOutboundRouteFiltering BGPCapabilityCode = 3
	BGPCapabilityCodeAddPath                BGPCapabilityCode = 69
)

type BGPCapability struct {
	Type   BGPCapabilityCode
	Length uint8
	Value  []byte
}

type BGPOpenMessage struct {
	BGPMessage
	Version            uint8
	ASN                uint16
	HoldTime           uint16
	Identifier         uint32
	CapabilitiesLength uint8
	Capabilities       []BGPCapability
}

func decodeBGPOpenMessage(data []byte, bgp *BGP) (BGPOpenMessage, error) {
	bom := BGPOpenMessage{}

	data, bom.Version = data[1:], uint8(data[0])
	data, bom.ASN = data[2:], binary.BigEndian.Uint16(data[:2])
	data, bom.HoldTime = data[2:], binary.BigEndian.Uint16(data[:2])
	data, bom.Identifier = data[4:], binary.BigEndian.Uint32(data[:4])
	data, bom.CapabilitiesLength = data[1:], uint8(data[0])

	if bom.CapabilitiesLength > 0 {
		for len(data) > 0 {
			bgpc := BGPCapability{}
			data, bgpc.Type = data[1:], BGPCapabilityCode(data[0])
			data, bgpc.Length = data[1:], uint8(data[0])
			data, bgpc.Value = data[bgpc.Length:], data[:bgpc.Length]
			bom.Capabilities = append(bom.Capabilities, bgpc)
		}
	}

	return bom, nil
}

// Decode bgp update message
//
// +-----------------------------------------------------+
// |   Withdrawn Routes Length (2 octets)                |
// +-----------------------------------------------------+
// |   Withdrawn Routes (variable)                       |
// +-----------------------------------------------------+
// |   Total Path Attribute Length (2 octets)            |
// +-----------------------------------------------------+
// |   Path Attributes (variable)                        |
// +-----------------------------------------------------+
// |   Network Layer Reachability Information (variable) |
// +-----------------------------------------------------+
// Taken from: https://tools.ietf.org/html/rfc4271

type BGPUpdateMessage struct {
	BGPMessage
	WithdrawnRoutesLength    uint16
	TotalPathAttributeLength uint16
	Prefixes                 [][]byte
}

func decodeBGPUpdateMessage(data []byte, bgp *BGP) (BGPUpdateMessage, error) {
	bm := BGPUpdateMessage{}

	data, bm.WithdrawnRoutesLength = data[2:], binary.BigEndian.Uint16(data[:2])
	if bm.WithdrawnRoutesLength > 0 {
		data, _ = data[bm.WithdrawnRoutesLength:], data[:bm.WithdrawnRoutesLength]
	}

	data, bm.TotalPathAttributeLength = data[2:], binary.BigEndian.Uint16(data[:2])
	if bm.TotalPathAttributeLength > 0 {
		data, _ = data[bm.TotalPathAttributeLength:], data[:bm.TotalPathAttributeLength]

		nlriLength := bgp.Length
		nlriLength -= bm.WithdrawnRoutesLength    // remove the withdrawn routes length
		nlriLength -= bm.TotalPathAttributeLength // remove path attribtute length
		nlriLength -= 19                          // remove header
		nlriLength -= 4                           // remove fields

		for len(data) > 0 {
			var prefixLength uint8
			data, prefixLength = data[1:], uint8(data[0])
			if prefixLength > 0 {
				var prefix []byte
				data, prefix = data[(prefixLength/8):], data[:(prefixLength/8)]
				bm.Prefixes = append(bm.Prefixes, prefix)
			}
		}
	}

	return bm, nil
}
