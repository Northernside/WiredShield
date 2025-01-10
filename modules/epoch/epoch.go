// thanks chadgpt
package epoch

import (
	"fmt"
	"sync"
	"time"
)

const (
	epoch         = int64(1735928607047)
	timestampBits = 41
	machineIDBits = 10
	sequenceBits  = 12

	machineIDMax = -1 ^ (-1 << machineIDBits)
	sequenceMax  = -1 ^ (-1 << sequenceBits)

	machineIDShift = sequenceBits
	timestampShift = sequenceBits + machineIDBits
)

type Snowflake struct {
	machineID int64
	lastTime  int64
	sequence  int64
	mutex     sync.Mutex
}

func NewSnowflake(machineID int64) (*Snowflake, error) {
	if machineID < 0 || machineID > machineIDMax {
		return nil, fmt.Errorf("machine ID must be between 0 and %d", machineIDMax)
	}

	return &Snowflake{
		machineID: machineID,
		lastTime:  -1,
	}, nil
}

func (s *Snowflake) GenerateID() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now().UnixMilli()

	if now < s.lastTime {
		panic("Clock moved backwards, unable to generate ID")
	}

	if now == s.lastTime {
		s.sequence = (s.sequence + 1) & sequenceMax
		if s.sequence == 0 {
			for now <= s.lastTime {
				now = time.Now().UnixMilli()
			}
		}
	} else {
		s.sequence = 0
	}

	s.lastTime = now

	id := ((now - epoch) << timestampShift) |
		(s.machineID << machineIDShift) |
		s.sequence

	return uint64(id)
}
