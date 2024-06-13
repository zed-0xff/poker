package poker

type Module struct {
	BaseOfDll   uintptr // Base address of the module
	SizeOfImage uint32  // Size of the module, in bytes
	EntryPoint  uintptr // Entry point of the module

	Name string // Name of the module (not in windows.ModuleInfo)
}
