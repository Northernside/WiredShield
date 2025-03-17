### 1. Aufbau eines Ethernet-Frames

- **Präambel (7 Bytes):** Dient zur Synchronisation.
- **Start Frame Delimiter (SFD) (1 Byte):** Markiert den Beginn des eigentlichen Frames.
- **Ziel-MAC-Adresse (6 Bytes):** Adresse des Empfängers.
- **Quell-MAC-Adresse (6 Bytes):** Adresse des Senders.
- **EtherType (2 Bytes):** Gibt das verwendete Protokoll an (z.B. IPv4, IPv6).
- **Nutzlast (46-1500 Bytes):** Die eigentlichen Daten, die übertragen werden.
- **Frame Check Sequence (FCS) (4 Bytes):** Fehlererkennungscode (CRC).

### 2. Größe eines Ethernet-Frames

Zwischen 64 und 1518 Bytes

### 3. Größe der Nutzlast eines Ethernet-Frames

Zwischen 46 und 1500 Bytes

### 4. Anzahl der übertragenen Frames

4 Frames

### 5. Größe der einzelnen Frames

- Die ersten drei Frames sind vollständig gefüllt und haben jeweils eine Nutzlast von 1500 Bytes.
- Der letzte Frame enthält die restlichen 500 Bytes der Nutzlast.

### 6. Gesamte Datenmenge

Die gesamte Datenmenge umfasst die Nutzlast aller Frames plus die Overhead-Daten (Header und FCS) jedes Frames.

- **Nutzlast:** 5000 Bytes
- **Overhead pro Frame:** 18 Bytes (14 Bytes Header + 4 Bytes FCS)
- **Gesamte Overhead:** 4 Frames * 18 Bytes = 72 Bytes

Die gesamte Datenmenge beträgt somit 5000 Bytes (Nutzlast) + 72 Bytes (Overhead) = 5072 Bytes.

## IEEE 802.1Q Standard

Der IEEE 802.1Q Standard definiert ein Protokoll für Virtual Local Area Networks (VLANs) auf Ethernet-Netzwerken. Er ermöglicht die Segmentierung eines physischen Netzwerks in mehrere logische Netzwerke, wodurch die Netzwerkverwaltung und -sicherheit verbessert werden. Der Standard spezifiziert die Verwendung von VLAN-Tags in Ethernet-Frames, um die Zugehörigkeit zu einem bestimmten VLAN zu kennzeichnen.

### Begriffe „tagged“ und „untagged“

- **Tagged:** Ein „tagged“ Frame enthält einen VLAN-Tag, der angibt, zu welchem VLAN der Frame gehört. Diese Tags werden von Switches verwendet, um den Datenverkehr zwischen verschiedenen VLANs zu steuern. Tagged Frames werden typischerweise zwischen Switches oder Routern verwendet, die VLAN-fähig sind.

- **Untagged:** Ein „untagged“ Frame enthält keinen VLAN-Tag. Diese Frames werden normalerweise von Endgeräten gesendet, die nicht VLAN-fähig sind, oder wenn der Switch so konfiguriert ist, dass er Frames ohne VLAN-Tag auf einem bestimmten Port akzeptiert. Der Switch weist untagged Frames einem Standard-VLAN (native VLAN) zu.
