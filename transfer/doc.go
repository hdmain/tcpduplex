// Package transfer provides encrypted, resumable file and stream transfers over a
// tcpduplex.Conn (module path github.com/hdmain/tcpduplex/transfer).
//
// Payloads ride inside existing AES-256-GCM MsgText records, so transfers inherit
// the session's encryption without a second crypto layer. Large chunks and a
// sliding ACK window keep the TCP pipe full for near line-rate throughput.
//
// Each transfer has a stable 16-byte ID. If the connection drops mid-transfer,
// Send/Receive (with Options.Redial) re-offer the same ID; the receiver reports
// how many bytes it already has, and the sender continues from that offset so
// already-written data is never re-sent or lost.
//
// While a transfer is in progress the Conn must not be used for other Send/Receive
// traffic—frames share the MsgText channel.
package transfer
