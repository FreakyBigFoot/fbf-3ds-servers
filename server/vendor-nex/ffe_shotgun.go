package nex

// ffeShotgun emits one CONNECT-ACK per (signature, connection-signature-field)
// interpretation, so a single console retry tests the entire space. The console
// accepts the one whose signature it can validate and discards the others.
func ffeShotgun(pep *PRUDPEndPoint, connection *PRUDPConnection, ack *PRUDPPacketV1, req PRUDPPacketInterface) {
	sigInputs := map[string][]byte{
		"theirs": req.GetConnectionSignature(),
		"ours":   connection.Signature,
		"empty":  {},
	}
	fields := map[string][]byte{
		"zeros":  make([]byte, 16),
		"ours":   connection.Signature,
		"theirs": req.GetConnectionSignature(),
	}
	for _, fieldName := range []string{"zeros", "ours", "theirs"} {
		for _, sigName := range []string{"theirs", "ours", "empty"} {
			ack.SetConnectionSignature(fields[fieldName])
			ack.SetSignature(ack.CalculateSignature([]byte{}, sigInputs[sigName]))
			pep.Server.SendRaw(connection.Socket, ack.Bytes())
		}
	}
}
