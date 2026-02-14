package evasion

// MimicrySettings holds the parameters to make ICMP traffic look legitimate.
type MimicrySettings struct {
	TTL         int
	TypeCode    [2]byte // ICMP type and code
	IDPattern   string  // "sequential", "random", "fixed"
	SeqPattern  string  // "sequential" vs "random"
	PayloadFill byte    // Fill byte for payload padding (Windows uses 'a'-'w', Linux uses 0x10-0x37)
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
			TTL:         128,
			TypeCode:    [2]byte{8, 0}, // Echo request
			IDPattern:   "fixed",
			SeqPattern:  "sequential",
			PayloadFill: 'a', // Windows ping fills with 'a' through 'w'
		}
	case "macos", "darwin":
		return &MimicrySettings{
			TTL:         64,
			TypeCode:    [2]byte{8, 0},
			IDPattern:   "random",
			SeqPattern:  "sequential",
			PayloadFill: 0x08,
		}
	default: // linux
		return &MimicrySettings{
			TTL:         64,
			TypeCode:    [2]byte{8, 0},
			IDPattern:   "sequential",
			SeqPattern:  "sequential",
			PayloadFill: 0x10, // Linux ping uses 0x10 through 0x37
		}
	}
}

// ApplyToHeaders modifies ICMP packet fields to match OS-specific patterns.
// Takes a raw ICMP packet (starting at ICMP header) and modifies in place.
func (m *Mimicker) ApplyToHeaders(icmpPacket []byte, seqCounter uint16) {
	if len(icmpPacket) < 8 {
		return
	}

	settings := m.Settings()
	icmpPacket[0] = settings.TypeCode[0]
	icmpPacket[1] = settings.TypeCode[1]

	// Set sequence number
	icmpPacket[6] = byte(seqCounter >> 8)
	icmpPacket[7] = byte(seqCounter)
}
