package evasion

// MimicrySettings holds the parameters to make ICMP traffic look legitimate.
type MimicrySettings struct {
	TTL         int
	TypeCode    [2]byte
	IDPattern   string
	SeqPattern  string
	PayloadFill byte
}

// Mimicker makes tunnel traffic resemble legitimate ICMP ping patterns.
type Mimicker struct {
	osSignature string
}

// NewMimicker creates a new protocol mimicker.
func NewMimicker(osSignature string) *Mimicker {
	return &Mimicker{osSignature: osSignature}
}

// Settings returns the mimicry settings based on the configured OS signature.
func (m *Mimicker) Settings() *MimicrySettings {
	switch m.osSignature {
	case "windows":
		return &MimicrySettings{
			TTL: 128, TypeCode: [2]byte{8, 0},
			IDPattern: "fixed", SeqPattern: "sequential", PayloadFill: 'a',
		}
	case "macos", "darwin":
		return &MimicrySettings{
			TTL: 64, TypeCode: [2]byte{8, 0},
			IDPattern: "random", SeqPattern: "sequential", PayloadFill: 0x08,
		}
	default: // linux
		return &MimicrySettings{
			TTL: 64, TypeCode: [2]byte{8, 0},
			IDPattern: "sequential", SeqPattern: "sequential", PayloadFill: 0x10,
		}
	}
}

// ApplyToHeaders modifies ICMP packet fields to match OS-specific patterns.
func (m *Mimicker) ApplyToHeaders(icmpPacket []byte, seqCounter uint16) {
	if len(icmpPacket) < 8 {
		return
	}
	settings := m.Settings()
	icmpPacket[0] = settings.TypeCode[0]
	icmpPacket[1] = settings.TypeCode[1]
	icmpPacket[6] = byte(seqCounter >> 8)
	icmpPacket[7] = byte(seqCounter)
}
