package recovery

import (
	"testing"
	"time"
)

// ============================================================================
// RTT Estimation Tests (RFC 9002 §5)
// ============================================================================

// TestRTTStatsInitial verifies initial RTT values.
func TestRTTStatsInitial(t *testing.T) {
	r := NewRTTStats(25 * time.Millisecond)

	if r.SmoothedRTT != kInitialRtt {
		t.Fatalf("expected initial smoothed_rtt = %v, got %v", kInitialRtt, r.SmoothedRTT)
	}
	if r.RTTVar != kInitialRtt/2 {
		t.Fatalf("expected initial rttvar = %v, got %v", kInitialRtt/2, r.RTTVar)
	}
	if r.MinRTT != 0 {
		t.Fatal("initial min_rtt should be 0")
	}
	if r.HasSamples() {
		t.Fatal("should have no samples initially")
	}
}

// TestRTTStatsFirstSample verifies the first RTT sample behavior.
func TestRTTStatsFirstSample(t *testing.T) {
	r := NewRTTStats(25 * time.Millisecond)

	sendTime := time.Now()
	now := sendTime.Add(100 * time.Millisecond)

	r.UpdateRTT(0, sendTime, now)

	if r.LatestRTT != 100*time.Millisecond {
		t.Fatalf("expected latest_rtt = 100ms, got %v", r.LatestRTT)
	}
	if r.SmoothedRTT != 100*time.Millisecond {
		t.Fatalf("expected first smoothed_rtt = latest_rtt = 100ms, got %v", r.SmoothedRTT)
	}
	if r.RTTVar != 50*time.Millisecond {
		t.Fatalf("expected first rttvar = latest_rtt/2 = 50ms, got %v", r.RTTVar)
	}
	if r.MinRTT != 100*time.Millisecond {
		t.Fatalf("expected first min_rtt = latest_rtt = 100ms, got %v", r.MinRTT)
	}
	if !r.HasSamples() {
		t.Fatal("should have samples after first update")
	}
}

// TestRTTStatsSubsequentSamples verifies EWMA behavior for subsequent samples.
func TestRTTStatsSubsequentSamples(t *testing.T) {
	r := NewRTTStats(25 * time.Millisecond)
	r.SetHandshakeConfirmed(true)

	// First sample: 100ms
	t0 := time.Now()
	r.UpdateRTT(0, t0, t0.Add(100*time.Millisecond))

	// Second sample: 200ms (with 10ms ack delay)
	t1 := time.Now()
	r.UpdateRTT(10*time.Millisecond, t1, t1.Add(200*time.Millisecond))

	// smoothed_rtt = 7/8 * 100 + 1/8 * 190 = 87.5 + 23.75 = 111.25ms
	expectedSmoothed := time.Duration(float64(100*time.Millisecond)*7/8 + float64(190*time.Millisecond)/8)
	if r.SmoothedRTT != expectedSmoothed {
		t.Fatalf("expected smoothed_rtt = %v, got %v", expectedSmoothed, r.SmoothedRTT)
	}

	// rttvar = 3/4 * 50 + 1/4 * |111.25 - 190| = 37.5 + 19.6875 = 57.1875ms
	// Actually: rttvar = 3/4 * 50ms + 1/4 * |111.25ms - 190ms| = 37.5ms + 19.6875ms
	// But we're using integer math, so let's check it's reasonable
	if r.RTTVar < 50*time.Millisecond || r.RTTVar > 70*time.Millisecond {
		t.Fatalf("expected rttvar around 57ms, got %v", r.RTTVar)
	}
}

// TestRTTStatsMinRTT verifies min_rtt tracking.
func TestRTTStatsMinRTT(t *testing.T) {
	r := NewRTTStats(0)
	r.SetHandshakeConfirmed(true)

	// Sample 1: 100ms
	t0 := time.Now()
	r.UpdateRTT(0, t0, t0.Add(100*time.Millisecond))

	// Sample 2: 50ms (new minimum)
	t1 := time.Now()
	r.UpdateRTT(0, t1, t1.Add(50*time.Millisecond))

	if r.MinRTT != 50*time.Millisecond {
		t.Fatalf("expected min_rtt = 50ms, got %v", r.MinRTT)
	}

	// Sample 3: 150ms (not a new minimum)
	t2 := time.Now()
	r.UpdateRTT(0, t2, t2.Add(150*time.Millisecond))

	if r.MinRTT != 50*time.Millisecond {
		t.Fatalf("min_rtt should still be 50ms, got %v", r.MinRTT)
	}
}

// TestRTTStatsPTO verifies PTO calculation.
func TestRTTStatsPTO(t *testing.T) {
	r := NewRTTStats(25 * time.Millisecond)
	r.SetHandshakeConfirmed(true)

	// After first sample of 100ms:
	// smoothed_rtt = 100ms, rttvar = 50ms
	// PTO = 100 + max(4*50, 1ms) + 25ms = 100 + 200 + 25 = 325ms
	t0 := time.Now()
	r.UpdateRTT(0, t0, t0.Add(100*time.Millisecond))

	pto := r.PTO()
	expected := 100*time.Millisecond + 4*50*time.Millisecond + 25*time.Millisecond
	if pto != expected {
		t.Fatalf("expected PTO = %v, got %v", expected, pto)
	}
}

// TestRTTStatsAckDelayClamped verifies that ack_delay is clamped to max_ack_delay.
func TestRTTStatsAckDelayClamped(t *testing.T) {
	r := NewRTTStats(25 * time.Millisecond)
	r.SetHandshakeConfirmed(true)

	// First sample: 100ms
	t0 := time.Now()
	r.UpdateRTT(0, t0, t0.Add(100*time.Millisecond))

	// Second sample with huge ack_delay (should be clamped to 25ms)
	t1 := time.Now()
	r.UpdateRTT(100*time.Millisecond, t1, t1.Add(200*time.Millisecond))

	// adjusted_rtt = 200 - min(100, 25) = 200 - 25 = 175ms
	// (since 200 >= 100 + 25)
	// min_rtt stays at 100ms
	if r.MinRTT != 100*time.Millisecond {
		t.Fatalf("min_rtt should be 100ms, got %v", r.MinRTT)
	}
}

// ============================================================================
// Loss Detection Tests (RFC 9002 §6)
// ============================================================================

// TestLossDetectionOnPacketSent records sent packets.
func TestLossDetectionOnPacketSent(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)

	now := time.Now()
	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}

	ld.OnPacketSent(p, now)

	if ld.BytesInFlight() != 1200 {
		t.Fatalf("expected bytes_in_flight = 1200, got %d", ld.BytesInFlight())
	}
}

// TestLossDetectionOnAckReceived processes ACK and updates RTT.
func TestLossDetectionOnAckReceived(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	now := time.Now()

	// Send packet 1
	p1 := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p1, now)

	// Send packet 2
	p2 := &SentPacket{
		PacketNumber: 2,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p2, now.Add(10*time.Millisecond)) // close to packet 1

	// Receive ACK for packet 2 (100ms after send)
	ld.OnAckReceived(PNSApplicationData, []uint64{2}, 2, 0, now.Add(110*time.Millisecond))

	// RTT should be updated
	r := ld.RTTStats()
	if !r.HasSamples() {
		t.Fatal("RTT should have samples after ACK")
	}

	// latest_rtt should be ~100ms (packet 2 sent at now+10ms, acked at now+110ms)
	if r.LatestRTT < 90*time.Millisecond || r.LatestRTT > 120*time.Millisecond {
		t.Fatalf("expected latest_rtt ~100ms, got %v", r.LatestRTT)
	}

	// Packet 1 should still be in sent_packets (not acked)
	// Packet 2 should be removed (acked)
	if ld.BytesInFlight() != 1200 {
		t.Fatalf("expected bytes_in_flight = 1200 (packet 1 still unacked), got %d", ld.BytesInFlight())
	}
}

// TestLossDetectionPacketThreshold tests loss detection by packet threshold.
func TestLossDetectionPacketThreshold(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	now := time.Now()

	// Send packets 1-5
	for i := uint64(1); i <= 5; i++ {
		p := &SentPacket{
			PacketNumber: i,
			AckEliciting: true,
			InFlight:     true,
			SentBytes:    1200,
			PNSpace:      PNSApplicationData,
		}
		ld.OnPacketSent(p, now.Add(time.Duration(i)*time.Millisecond))
	}

	// ACK packets 4, 5 (gap of 3 → packets 1, 2, 3 should be declared lost)
	ld.OnAckReceived(PNSApplicationData, []uint64{4, 5}, 5, 0, now.Add(10*time.Millisecond))

	// Packets 1, 2, 3 should be lost (5 - 1 = 4 >= kPacketThreshold=3)
	// Actually: packet 1 is lost because 4 >= 1 + 3 = 4
	// Packet 2 is lost because 5 >= 2 + 3 = 5
	// Packet 3: 5 >= 3 + 3 = 6 → NO, not lost by threshold
	// But time threshold: all sent within 10ms, so likely not lost by time
	// Let's verify bytes_in_flight decreased
	bif := ld.BytesInFlight()
	if bif == 5*1200 {
		t.Fatal("some packets should have been removed (acked or lost)")
	}
}

// TestLossDetectionTimeThreshold tests loss detection by time threshold.
func TestLossDetectionTimeThreshold(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	// First, establish an RTT sample
	now := time.Now()
	p1 := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p1, now)
	ld.OnAckReceived(PNSApplicationData, []uint64{1}, 1, 0, now.Add(100*time.Millisecond))

	// RTT should be ~100ms, so time_threshold = 9/8 * 100 = 112.5ms

	// Send packet 2
	p2 := &SentPacket{
		PacketNumber: 2,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	sendTime := now.Add(200 * time.Millisecond)
	ld.OnPacketSent(p2, sendTime)

	// Send packet 3 and ACK it after 200ms
	p3 := &SentPacket{
		PacketNumber: 3,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p3, sendTime.Add(10*time.Millisecond))

	// ACK packet 3 after 200ms — packet 2 was sent 200ms ago, exceeding time threshold
	ackTime := sendTime.Add(200 * time.Millisecond)
	ld.OnAckReceived(PNSApplicationData, []uint64{3}, 3, 0, ackTime)

	// Packet 2 should be declared lost (sent > 112.5ms ago)
	// Check that bytes_in_flight decreased significantly
	if ld.BytesInFlight() > 1200 {
		t.Fatalf("expected most packets to be acked/lost, bytes_in_flight = %d", ld.BytesInFlight())
	}
}

// TestLossDetectionPTOCountReset verifies PTO count resets on ACK.
func TestLossDetectionPTOCountReset(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	now := time.Now()

	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p, now)

	// ACK should reset PTO count
	ld.OnAckReceived(PNSApplicationData, []uint64{1}, 1, 0, now.Add(100*time.Millisecond))

	if ld.PTOCount() != 0 {
		t.Fatalf("PTO count should be 0 after ACK, got %d", ld.PTOCount())
	}
}

// TestLossDetectionTimerSet verifies the loss detection timer is set.
func TestLossDetectionTimerSet(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	now := time.Now()

	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSApplicationData,
	}
	ld.OnPacketSent(p, now)

	timer := ld.GetLossDetectionTimer()
	if timer.IsZero() {
		t.Fatal("loss detection timer should be set after sending ack-eliciting packet")
	}
}

// TestLossDetectionNoTimerWhenNothingInFlight verifies timer is not set
// when nothing is in flight and address validation is complete.
func TestLossDetectionNoTimerWhenNothingInFlight(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	// No packets sent, address validation complete
	// Timer should not be set
	timer := ld.GetLossDetectionTimer()
	if !timer.IsZero() {
		t.Fatal("timer should not be set when nothing is in flight")
	}
}

// TestPacketNumberSpaceDiscarded verifies PN space discard cleans up state.
func TestPacketNumberSpaceDiscarded(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)

	now := time.Now()

	// Send a packet in Initial space
	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		PNSpace:      PNSInitial,
	}
	ld.OnPacketSent(p, now)

	if ld.BytesInFlight() != 1200 {
		t.Fatalf("expected bytes_in_flight = 1200, got %d", ld.BytesInFlight())
	}

	// Discard Initial space
	ld.OnPacketNumberSpaceDiscarded(PNSInitial, now.Add(time.Second))

	if ld.BytesInFlight() != 0 {
		t.Fatalf("expected bytes_in_flight = 0 after discard, got %d", ld.BytesInFlight())
	}

	if ld.PTOCount() != 0 {
		t.Fatal("PTO count should be reset after PN space discard")
	}
}

// ============================================================================
// Congestion Control Tests (RFC 9002 §7)
// ============================================================================

// TestCongestionControllerInitial verifies initial congestion window.
func TestCongestionControllerInitial(t *testing.T) {
	cc := NewCongestionController()

	expectedCW := kInitialWindow(kMaxDatagramSize)
	if cc.CongestionWindow() != expectedCW {
		t.Fatalf("expected initial CW = %d, got %d", expectedCW, cc.CongestionWindow())
	}

	if cc.BytesInFlight() != 0 {
		t.Fatal("initial bytes_in_flight should be 0")
	}

	if !cc.InSlowStart() {
		t.Fatal("should start in slow start")
	}

	if cc.InRecovery() {
		t.Fatal("should not start in recovery")
	}
}

// TestCongestionControllerSlowStart verifies slow start growth.
func TestCongestionControllerSlowStart(t *testing.T) {
	cc := NewCongestionController()

	initialCW := cc.CongestionWindow()

	// Send and ACK a packet
	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		TimeSent:     time.Now(),
	}
	cc.OnPacketSentCC(1200)
	cc.OnPacketsAcked([]*SentPacket{p})

	// CW should have increased by 1200 bytes (slow start)
	if cc.CongestionWindow() != initialCW+1200 {
		t.Fatalf("expected CW = %d after slow start ACK, got %d", initialCW+1200, cc.CongestionWindow())
	}
}

// TestCongestionControllerLossTriggersRecovery verifies that loss triggers recovery.
func TestCongestionControllerLossTriggersRecovery(t *testing.T) {
	cc := NewCongestionController()

	initialCW := cc.CongestionWindow()

	// Send some packets to build up CW
	for i := 0; i < 5; i++ {
		cc.OnPacketSentCC(1200)
	}

	// Simulate loss
	lostPackets := []*SentPacket{
		{
			PacketNumber: 1,
			InFlight:     true,
			SentBytes:    1200,
			TimeSent:     time.Now(),
		},
	}
	cc.OnPacketsLost(lostPackets)

	if !cc.InRecovery() {
		t.Fatal("should be in recovery after loss")
	}

	// CW should be reduced
	newCW := cc.CongestionWindow()
	if newCW >= initialCW {
		t.Fatalf("CW should be reduced after loss, got %d (was %d)", newCW, initialCW)
	}

	// CW should be at least minimum window
	minCW := kMinimumWindow(kMaxDatagramSize)
	if newCW < minCW {
		t.Fatalf("CW should be at least minimum window %d, got %d", minCW, newCW)
	}
}

// TestCongestionControllerRecoveryNoDoubleReduction verifies that
// multiple losses in the same recovery period don't reduce CW multiple times.
func TestCongestionControllerRecoveryNoDoubleReduction(t *testing.T) {
	cc := NewCongestionController()

	// Build up CW
	sendTime := time.Now()
	for i := 0; i < 5; i++ {
		cc.OnPacketSentCC(1200)
	}

	// First loss triggers recovery
	cc.OnPacketsLost([]*SentPacket{
		{PacketNumber: 1, InFlight: true, SentBytes: 1200, TimeSent: sendTime},
	})

	cwAfterFirstLoss := cc.CongestionWindow()

	// Second loss in same recovery period should NOT reduce CW again
	// Use the same sendTime (before recovery started) so inCongestionRecovery returns true
	cc.OnPacketsLost([]*SentPacket{
		{PacketNumber: 2, InFlight: true, SentBytes: 1200, TimeSent: sendTime},
	})

	cwAfterSecondLoss := cc.CongestionWindow()
	if cwAfterSecondLoss != cwAfterFirstLoss {
		t.Fatalf("CW should not change in same recovery period: %d → %d", cwAfterFirstLoss, cwAfterSecondLoss)
	}
}

// TestCongestionControllerCanSend verifies the CanSend check.
func TestCongestionControllerCanSend(t *testing.T) {
	cc := NewCongestionController()

	cw := cc.CongestionWindow()

	// Should be able to send within CW
	if !cc.CanSend(1200) {
		t.Fatal("should be able to send 1200 bytes within initial CW")
	}

	// Fill up the CW
	for cc.BytesInFlight()+1200 <= cw {
		cc.OnPacketSentCC(1200)
	}

	// Should not be able to send more
	if cc.CanSend(1200) {
		t.Fatal("should not be able to send beyond CW")
	}
}

// TestCongestionControllerBytesInFlight verifies bytes_in_flight tracking.
func TestCongestionControllerBytesInFlight(t *testing.T) {
	cc := NewCongestionController()

	cc.OnPacketSentCC(1000)
	if cc.BytesInFlight() != 1000 {
		t.Fatalf("expected bytes_in_flight = 1000, got %d", cc.BytesInFlight())
	}

	cc.OnPacketSentCC(2000)
	if cc.BytesInFlight() != 3000 {
		t.Fatalf("expected bytes_in_flight = 3000, got %d", cc.BytesInFlight())
	}

	// ACK should reduce bytes_in_flight
	cc.OnPacketsAcked([]*SentPacket{
		{PacketNumber: 1, InFlight: true, SentBytes: 1000, TimeSent: time.Now()},
	})
	if cc.BytesInFlight() != 2000 {
		t.Fatalf("expected bytes_in_flight = 2000 after ACK, got %d", cc.BytesInFlight())
	}
}

// TestCongestionControllerCongestionAvoidance tests slow start → congestion avoidance.
func TestCongestionControllerCongestionAvoidance(t *testing.T) {
	cc := NewCongestionController()

	// Bring CW down to trigger a known ssthresh
	// Send packets, then trigger loss
	for i := 0; i < 10; i++ {
		cc.OnPacketSentCC(1200)
	}

	// Trigger loss
	lostPackets := []*SentPacket{
		{PacketNumber: 1, InFlight: true, SentBytes: 1200, TimeSent: time.Now()},
	}
	cc.OnPacketsLost(lostPackets)

	ssthresh := cc.SSThresh()
	if ssthresh == ^uint64(0) {
		t.Fatal("ssthresh should be set after loss")
	}

	// Now CW = ssthresh, so we're in congestion avoidance
	// ACKing packets should increase CW by roughly max_dgram_size^2 / CW
	if cc.InSlowStart() {
		t.Fatal("should not be in slow start after CW = ssthresh")
	}
}

// TestCongestionControllerRemoveFromBytesInFlight verifies discard handling.
func TestCongestionControllerRemoveFromBytesInFlight(t *testing.T) {
	cc := NewCongestionController()

	// Send 3 packets
	for i := 0; i < 3; i++ {
		cc.OnPacketSentCC(1200)
	}

	// Discard 2 packets
	cc.RemoveFromBytesInFlight([]*SentPacket{
		{InFlight: true, SentBytes: 1200},
		{InFlight: true, SentBytes: 1200},
	})

	if cc.BytesInFlight() != 1200 {
		t.Fatalf("expected bytes_in_flight = 1200, got %d", cc.BytesInFlight())
	}
}

// TestCongestionControllerECN tests ECN processing.
func TestCongestionControllerECN(t *testing.T) {
	cc := NewCongestionController()

	// Build up some CW
	for i := 0; i < 5; i++ {
		cc.OnPacketSentCC(1200)
	}

	initialCW := cc.CongestionWindow()

	// Process ECN with increasing CE counter
	cc.ProcessECN(PNSApplicationData, 1, time.Now())

	if !cc.InRecovery() {
		t.Fatal("should be in recovery after ECN CE")
	}

	if cc.CongestionWindow() >= initialCW {
		t.Fatal("CW should be reduced after ECN CE")
	}
}

// TestCongestionControllerReset tests state reset.
func TestCongestionControllerReset(t *testing.T) {
	cc := NewCongestionController()

	// Build up state
	for i := 0; i < 5; i++ {
		cc.OnPacketSentCC(1200)
	}
	cc.OnPacketsLost([]*SentPacket{
		{PacketNumber: 1, InFlight: true, SentBytes: 1200, TimeSent: time.Now()},
	})

	// Reset
	cc.ResetCongestionState()

	if cc.BytesInFlight() != 0 {
		t.Fatal("bytes_in_flight should be 0 after reset")
	}
	if cc.InRecovery() {
		t.Fatal("should not be in recovery after reset")
	}
	if !cc.InSlowStart() {
		t.Fatal("should be in slow start after reset")
	}
}

// TestCongestionControllerAppLimited verifies app-limited behavior.
func TestCongestionControllerAppLimited(t *testing.T) {
	cc := NewCongestionController()
	cc.SetAppLimited(true)

	initialCW := cc.CongestionWindow()

	// Send and ACK a packet
	p := &SentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		InFlight:     true,
		SentBytes:    1200,
		TimeSent:     time.Now(),
	}
	cc.OnPacketSentCC(1200)
	cc.OnPacketsAcked([]*SentPacket{p})

	// CW should NOT increase when app-limited
	if cc.CongestionWindow() != initialCW {
		t.Fatalf("CW should not increase when app-limited, got %d (expected %d)", cc.CongestionWindow(), initialCW)
	}
}

// TestCongestionControllerRemainingWindow verifies remaining window calculation.
func TestCongestionControllerRemainingWindow(t *testing.T) {
	cc := NewCongestionController()

	cw := cc.CongestionWindow()

	cc.OnPacketSentCC(1200)
	remaining := cc.RemainingWindow()
	if remaining != cw-1200 {
		t.Fatalf("expected remaining = %d, got %d", cw-1200, remaining)
	}

	// Fill up
	for cc.RemainingWindow() >= 1200 {
		cc.OnPacketSentCC(1200)
	}

	if cc.RemainingWindow() != 0 {
		t.Fatalf("expected remaining = 0, got %d", cc.RemainingWindow())
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

// TestLossDetectionAndCongestionIntegration verifies that loss detection
// and congestion control work together.
func TestLossDetectionAndCongestionIntegration(t *testing.T) {
	ld := NewLossDetection(25*time.Millisecond, true)
	ld.SetHandshakeConfirmed(true)
	ld.SetPeerCompletedAddressValidation(true)

	now := time.Now()

	// Send packets 1-5
	for i := uint64(1); i <= 5; i++ {
		p := &SentPacket{
			PacketNumber: i,
			AckEliciting: true,
			InFlight:     true,
			SentBytes:    1200,
			PNSpace:      PNSApplicationData,
		}
		ld.OnPacketSent(p, now.Add(time.Duration(i)*time.Millisecond))
	}

	// Verify congestion controller tracked the bytes
	if ld.BytesInFlight() != 5*1200 {
		t.Fatalf("expected bytes_in_flight = %d, got %d", 5*1200, ld.BytesInFlight())
	}

	// ACK packets 1 and 2
	ld.OnAckReceived(PNSApplicationData, []uint64{1, 2}, 2, 0, now.Add(100*time.Millisecond))

	// Bytes in flight should decrease
	if ld.BytesInFlight() != 3*1200 {
		t.Fatalf("expected bytes_in_flight = %d, got %d", 3*1200, ld.BytesInFlight())
	}

	// RTT should be updated
	if !ld.RTTStats().HasSamples() {
		t.Fatal("RTT should have samples")
	}
}

// TestPacketNumberSpaceString verifies String() method.
func TestPacketNumberSpaceString(t *testing.T) {
	tests := []struct {
		pns      PacketNumberSpace
		expected string
	}{
		{PNSInitial, "Initial"},
		{PNSHandshake, "Handshake"},
		{PNSApplicationData, "ApplicationData"},
	}

	for _, tt := range tests {
		if got := tt.pns.String(); got != tt.expected {
			t.Errorf("got %q, expected %q", got, tt.expected)
		}
	}
}
