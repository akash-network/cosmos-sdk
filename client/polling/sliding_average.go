package polling

type slidingAverage struct {
	data []float64
	sum  float64
	idx  int
}

func newSlidingAverage(initialValue float64, sampleCount int) *slidingAverage {
	result := &slidingAverage{
		data: make([]float64, sampleCount),
	}

	for i := range result.data {
		result.data[i] = initialValue
		result.sum += initialValue
	}

	return result
}

func (sa *slidingAverage) push(v float64) {
	// Deduct from the sum the value being evicted
	sa.sum -= sa.data[sa.idx]
	// Evict the value, replacing it with the new sample
	sa.data[sa.idx] = v
	// Add to the sum the new value
	sa.sum += v
	// Increment the destination for new samples
	sa.idx++
	// Loop around if past the end of the array
	if sa.idx == len(sa.data) {
		sa.idx = 0
	}
}

func (sa *slidingAverage) getAverage() float64 {
	return sa.sum / float64(len(sa.data))
}
