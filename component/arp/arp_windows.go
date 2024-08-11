package arp

func GetARPTable() (map[string]string, error) {
	table, err := GetIpNetTable2()
	if err != nil {
		return nil, err
	}

	entries := make(map[string]string)
	for _, row := range table {
		entry := row.ToARPEntry()

		if IsReserved(entry.IP) {
			continue
		}

		if entry.IP.IsGlobalUnicast() {
			entries[entry.IP.String()] = entry.MAC.String()
		}
	}
	return entries, nil
}
