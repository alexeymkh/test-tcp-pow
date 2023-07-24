package quotes

import "math/rand"

var quotes = []string{
	"The only true wisdom is in knowing you know nothing.",
	"In the midst of chaos, there is also opportunity.",
	"If you are not willing to learn, no one can help you.",
	"Foolishness is a twin sister of wisdom.",
	"Do now what your future you will thank you for.",
}

func GetQuote() string {
	return "Behold the word of wisdom! " + quotes[rand.Intn(len(quotes))]
}
