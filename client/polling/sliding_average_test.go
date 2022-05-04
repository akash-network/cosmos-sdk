package polling

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"math/rand"
)

func TestSlidingAverage(t *testing.T) {
	const sampleCount = 100
	sa := newSlidingAverage(1.0, sampleCount)
	assert.Equal(t, sa.getAverage(), 1.0)

	sa.push(0.0)
	assert.Equal(t, sa.getAverage(), 0.99)

	for i := 0; i != sampleCount; i++ {
		sa.push(0.0)
	}
	assert.Equal(t, sa.getAverage(), 0.0)

	randomNumber := rand.Float64()
	for i := 0; i != sampleCount; i++ {
		sa.push(randomNumber)
	}
	assert.InEpsilon(t, randomNumber, sa.getAverage(), 0.0000001)

	total := 0.0
	for i := 0; i != sampleCount; i++ {
		total += float64(i)
		sa.push(float64(i))
	}
	assert.InEpsilon(t, total/sampleCount, sa.getAverage(), 0.001)
}
