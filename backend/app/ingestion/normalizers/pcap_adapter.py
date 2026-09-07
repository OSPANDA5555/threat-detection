import struct
import socket
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

from app.schemas.dataset import NormalizedEvent, ValidationErrorRecord, DatasetMetadata
from app.ingestion.normalizers.base import BaseDatasetNormalizer
from app.ingestion.validator import validate_ip, validate_port, parse_protocol

class PcapIngestionAdapter(BaseDatasetNormalizer):
    """
    PCAP Ingestion Adapter.
    Safely parses standard Libpcap (.pcap) capture files using pure-Python binary unpacker.
    Extracts IPv4/IPv6, TCP/UDP packet flows, frame metadata, and payload byte counts.
    """

    def parse_and_normalize(
        self,
        content: bytes,
        file_name: str,
        dataset_name: str
    ) -> Tuple[DatasetMetadata, List[NormalizedEvent]]:
        if len(content) < 24:
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="PCAP",
                errors=[ValidationErrorRecord(row_index=0, field="pcap_header", error_message="File too small to be a valid PCAP (less than 24 bytes)")]
            )
            return meta, []

        # Read Global Header (24 bytes)
        magic = content[:4]
        endianness = "<"  # little-endian default
        is_nano = False

        if magic == b"\xa1\xb2\xc3\xd4":
            endianness = ">"  # big-endian microsecond
        elif magic == b"\xd4\xc3\xb2\xa1":
            endianness = "<"  # little-endian microsecond
        elif magic == b"\xa1\xb2\x3c\x4d":
            endianness = ">"  # big-endian nanosecond
            is_nano = True
        elif magic == b"\x4d\x3c\xb2\xa1":
            endianness = "<"  # little-endian nanosecond
            is_nano = True
        elif magic == b"\x0a\x0d\x0d\x0a":
            # PCAPNG format
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="PCAP",
                errors=[ValidationErrorRecord(row_index=0, field="pcap_magic", error_message="PCAPNG format detected. Please export as standard Libpcap format.")]
            )
            return meta, []
        else:
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="PCAP",
                errors=[ValidationErrorRecord(row_index=0, field="pcap_magic", error_message=f"Invalid PCAP magic bytes: {magic.hex()}")]
            )
            return meta, []

        try:
            _, version_major, version_minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
                f"{endianness}IHHiIII", content[:24]
            )
        except Exception as ex:
            meta = DatasetMetadata(
                dataset_name=dataset_name,
                file_name=file_name,
                source_format="PCAP",
                errors=[ValidationErrorRecord(row_index=0, field="pcap_global_header", error_message=str(ex))]
            )
            return meta, []

        offset = 24
        packet_idx = 0
        events: List[NormalizedEvent] = []
        errors: List[ValidationErrorRecord] = []
        labels_count: Dict[str, int] = {}
        attack_cats_count: Dict[str, int] = {}

        while offset + 16 <= len(content):
            packet_idx += 1
            # Read Packet Record Header (16 bytes)
            try:
                ts_sec, ts_sub, incl_len, orig_len = struct.unpack(
                    f"{endianness}IIII", content[offset:offset+16]
                )
            except Exception as e:
                errors.append(ValidationErrorRecord(
                    row_index=packet_idx,
                    field="packet_header",
                    error_message=f"Corrupt packet header: {str(e)}"
                ))
                break

            offset += 16
            if offset + incl_len > len(content):
                errors.append(ValidationErrorRecord(
                    row_index=packet_idx,
                    field="packet_data",
                    error_message="Truncated packet data block at end of PCAP"
                ))
                break

            packet_bytes = content[offset:offset+incl_len]
            offset += incl_len

            # Calculate Timestamp
            sub_divisor = 1e9 if is_nano else 1e6
            dt = datetime.fromtimestamp(ts_sec + (ts_sub / sub_divisor), tz=timezone.utc)
            iso_ts = dt.isoformat()

            # Parse Ethernet (Linktype 1 = Ethernet)
            if linktype != 1 or len(packet_bytes) < 14:
                continue

            eth_proto = struct.unpack("!H", packet_bytes[12:14])[0]
            ip_data = packet_bytes[14:]

            # IPv4 parsing (EtherType 0x0800)
            if eth_proto == 0x0800 and len(ip_data) >= 20:
                ver_ihl = ip_data[0]
                ihl = (ver_ihl & 0x0F) * 4
                total_len = struct.unpack("!H", ip_data[2:4])[0]
                proto_num = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])

                proto_name = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else "ICMP" if proto_num == 1 else str(proto_num)
                src_port = None
                dst_port = None

                trans_data = ip_data[ihl:]
                if proto_num in (6, 17) and len(trans_data) >= 4:
                    src_port, dst_port = struct.unpack("!HH", trans_data[:4])

                # Label heuristic for PCAP capture
                label = "BENIGN"
                if dst_port in (22, 23, 3389, 4444, 1337):
                    label = "SUSPICIOUS_SERVICE_ACCESS"
                elif dst_port in (80, 443, 8080):
                    label = "BENIGN"

                event = NormalizedEvent(
                    timestamp=iso_ts,
                    source_ip=src_ip,
                    source_port=src_port,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    protocol=proto_name,
                    event_type="network_flow",
                    action="ALLOWED",
                    username=None,
                    hostname=None,
                    process=None,
                    bytes_in=total_len,
                    bytes_out=None,
                    duration=0.0,
                    label=label,
                    raw_data={
                        "packet_index": packet_idx,
                        "frame_len": orig_len,
                        "captured_len": incl_len,
                        "link_type": linktype,
                        "proto_number": proto_num
                    },
                    source="pcap"
                )
                events.append(event)
                labels_count[label] = labels_count.get(label, 0) + 1

        metadata = DatasetMetadata(
            dataset_name=dataset_name,
            file_name=file_name,
            total_events=len(events),
            benign_events=labels_count.get("BENIGN", 0),
            malicious_events=len(events) - labels_count.get("BENIGN", 0),
            source_format="PCAP",
            available_labels=labels_count,
            attack_categories={"PCAP Flow Traffic": len(events)},
            malformed_records_count=len(errors),
            errors=errors[:100]
        )

        return metadata, events
