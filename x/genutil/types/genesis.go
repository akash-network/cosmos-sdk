package types

//// AppGenesisFromFile reads the AppGenesis from the provided file.
//func AppGenesisFromFile(genFile string) (*AppGenesis, error) {
//	file, err := os.Open(filepath.Clean(genFile))
//	if err != nil {
//		return nil, err
//	}
//
//	appGenesis, err := AppGenesisFromReader(bufio.NewReader(file))
//	if err != nil {
//		return nil, fmt.Errorf("failed to read genesis from file %s: %w", genFile, err)
//	}
//
//	if err := file.Close(); err != nil {
//		return nil, err
//	}
//
//	return appGenesis, nil
//}
//
