package aide

const (
	DB_OLD            uint64 = 1<<0
	DB_WRITE          uint64 = 1<<1
	DB_NEW            uint64 = 1<<2
	NODE_ADDED        uint64 = 1<<4
	NODE_REMOVED      uint64 = 1<<5
	NODE_CHANGED      uint64 = 1<<6
	NODE_FREE         uint64 = 1<<7
	DB_DISK           uint64 = 1<<8

	NODE_TRAVERSE     uint64 = 1<<9
	NODE_CHECKED      uint64 = 1<<10
	NODE_MOVED_OUT    uint64 = 1<<11
	NODE_MOVED_IN     uint64 = 1<<12
	NODE_ALLOW_NEW    uint64 = 1<<13
	NODE_ALLOW_RM	  uint64 = 1<<14
)
