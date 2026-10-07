from traffic_analyzer import PacketRecord, service_for, summarize


def test_service_mapping():
    assert service_for(443) == "https"
    assert service_for(65500) is None


def test_metadata_summary_does_not_save_payloads():
    records = [
        PacketRecord(1.0, "10.0.0.2", "8.8.8.8", "UDP", 53000, 53, 100, "example.org"),
        PacketRecord(2.0, "10.0.0.2", "10.0.0.5", "TCP", 40000, 23, 80),
    ]
    report = summarize(records)
    assert report["metadata_only"] is True
    assert report["payloads_saved"] is False
    assert report["packet_injection"] is False
    assert report["packet_count"] == 2
    assert report["protocols"] == {"UDP": 1, "TCP": 1}
    assert report["dns_queries"][0]["query"] == "example.org"


def test_cleartext_service_is_reported():
    record = PacketRecord(1.0, "10.0.0.2", "10.0.0.8", "TCP", 40000, 23, 80)
    findings = summarize([record])["findings"]
    assert any(item["type"] == "plaintext-service" for item in findings)


def test_port_scan_signal():
    records = [
        PacketRecord(float(i), "10.0.0.2", "10.0.0.8", "TCP", 40000, i, 60)
        for i in range(20, 40)
    ]
    findings = summarize(records)["findings"]
    assert any(item["type"] == "possible-port-scan" for item in findings)


def test_service_detection_uses_source_port_for_responses():
    response = PacketRecord(
        1.0, "10.0.0.8", "10.0.0.2", "TCP", 23, 40000, 80
    )
    report = summarize([response])
    assert report["services"] == {"telnet": 1}
    assert any(item["type"] == "plaintext-service" for item in report["findings"])
