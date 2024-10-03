package util

import (
	"fmt"
	"time"
)

func ParseInterval(in string) (time.Duration, error) {
	var (
		digit uint64
		unit  string
	)

	if _, err := fmt.Sscanf(in, "%d%s", &digit, &unit); err != nil {
		return 0, fmt.Errorf("Error parsing interval from %q : %e", in, err)
	}

	switch unit {
	case "ns":
		return time.Duration(digit) * time.Nanosecond, nil
	case "us":
		return time.Duration(digit) * time.Microsecond, nil
	case "ms":
		return time.Duration(digit) * time.Millisecond, nil
	case "s":
		return time.Duration(digit) * time.Second, nil
	case "min":
		return time.Duration(digit) * time.Minute, nil
	default:
		return 0, fmt.Errorf("Unknown units %q. Supported units: ns, us, ms, s or min", in)
	}
}
