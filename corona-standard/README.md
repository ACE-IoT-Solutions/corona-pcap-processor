# Corona topology vocabulary

`topology.ttl` extends the BACnet metrics used by this repository with observed
communication edges and Modbus/TCP identities. It uses the existing Corona and
ASHRAE BACnet namespace IRIs so a collector can attach these triples to BACnet
device and interface metrics in the same RDF graph.

Each `corona:CommunicationEdge` is directed and has a source device, a
destination device, a protocol, and a total message count. One
`corona:MessageObservation` per message type holds its count on that edge.
Collectors should keep stable endpoint IDs even if a later BACnet I-Am reveals
an instance number. A BACnet address and a Modbus address at the same IP are
separate protocol endpoints.

For Modbus/TCP, the server IP identifies the TCP endpoint. Unit IDs 1 through
247 identify addressable units behind that endpoint; `corona:routesTo` links
the gateway and the unit. Unit ID 255 is the recommended direct TCP server
value, while 0 can also address a direct server. The presence of a significant
unit ID is evidence of a gateway, but passive capture alone cannot prove that
the physical downstream link uses RTU. Consumers should treat
`corona:ModbusRtuUnit` as an inferred logical unit unless corroborated by
inventory or a serial capture. See the [Modbus/TCP implementation guide](https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf).

The `ot-pcap-processor file capture.pcap --corona network.ttl` command emits
this vocabulary alongside its OTLP metrics and communication log events.
