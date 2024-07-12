package certmanager

type IStorage interface {
	GetFile(path string) ([]byte, error)
	SaveFile(path string, data []byte) error
	ListDir(path string) ([]string, error)
}
