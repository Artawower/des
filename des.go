package des

import "errors"

type Crypto interface {
	Encrypt() (string, error)
	Decrypt() (string, error)
}

type des struct {
	text string
	key  [64]byte
}

func (s *des) Encrypt() (string, error) {
	steps := len(s.text) / encryptBlockSize
	encryptedBytes := []byte{}
	for step := 0; step < steps; step++ {
		sliceOfText := s.text[step*encryptBlockSize : encryptBlockSize*step+encryptBlockSize]
		encryptedChunk := encryptByChunk([]byte(sliceOfText), s.key)
		encryptedBytes = append(encryptedBytes, encryptedChunk...)
	}
	encryptedBits := viewBytesAsBits(encryptedBytes)
	return string(encryptedBits), nil
}

func encryptByChunk(chunk []byte, key [64]byte) []byte {
	bits := viewBitsAsBytes(chunk)
	var bitsArr [64]byte
	copy(bitsArr[:], bits)
	startPermutation := startPermutation(bitsArr)
	encryptedData := encryptCycle(startPermutation, key)
	return encryptedData[:]
}

func startPermutation(chunk [64]byte) [64]byte {
	permutatedChunk := [64]byte{}
	for i := range startPermutationPositions {
		permutatedChunk[i] = chunk[startPermutationPositions[i]-1]
	}
	return permutatedChunk
}

func encryptCycle(bytesBlock, key [64]byte) [64]byte {
	var r [32]byte
	var l [32]byte
	var tmp [32]byte
	copy(r[:], bytesBlock[0:32])
	copy(l[:], bytesBlock[32:64])

	for i := 0; i < 16; i++ {
		kIter := generate48BitKey(key, encryptShiftingPositions, i)
		tmp = l
		l = r
		r = bytesXor(tmp, convertByFestel(r, kIter))
	}

	var encryptedBytes [64]byte
	t := append(l[:], r[:]...)
	copy(encryptedBytes[:], t)
	resBytes := lastPermutation(encryptedBytes)

	return resBytes
}

func generate48BitKey(extendedKey [64]byte, sequence []byte, i int) [48]byte {
	var round64key [64]byte

	for i, val := range extendKeyPositionsC {
		round64key[i] = extendedKey[val-1]
	}

	shiftedKey := cycleLeftShift(extendedKey, sequence[i])
	for i, val := range extendKeyPositionsD {
		round64key[i+32] = shiftedKey[val-1]
	}

	var key [48]byte
	key = getFinalRoundKey(round64key)
	return key
}

func getFinalRoundKey(roundKey [64]byte) [48]byte {
	var finalRoundKey [48]byte

	for i, val := range finalKeyRoundPermutationPosisitions {
		finalRoundKey[i] = roundKey[val-1]
	}
	return finalRoundKey
}

func convertByFestel(cryptedBits [32]byte, key [48]byte) [32]byte {
	extendedCryptedBits := permutatePreFestel(cryptedBits)
	for i, val := range extendedCryptedBits {
		extendedCryptedBits[i] = val ^ key[i]
	}
	var festelResult []byte
	for i := 0; i < 8; i++ {
		bits := extendedCryptedBits[i*6 : 6*i+6]
		row := getNumberFromPseudoBits([]byte{bits[0], bits[len(bits)-1]})
		col := getNumberFromPseudoBits(bits[1 : len(bits)-1])
		festelResult = append(festelResult, getPseudoBitsFromNumber(byte(sBlocks[i][row][col]))...)
	}
	var bBlocks [32]byte
	copy(bBlocks[:], festelResult)
	res := permutateFestelResult(bBlocks)
	return res
}

func permutatePreFestel(vector [32]byte) [48]byte {
	var externedVector [48]byte

	for i, val := range extenssionTablePositionsE {
		externedVector[i] = vector[val-1]
	}
	return externedVector
}

func permutateFestelResult(chunk [32]byte) [32]byte {
	var res [32]byte
	for i, val := range permutationFestelPositions {
		res[i] = chunk[val-1]
	}
	return res
}

func lastPermutation(encryptedBytes [64]byte) [64]byte {
	var permutatedBytes [64]byte

	for i, val := range lastPermutationPositions {
		permutatedBytes[i] = encryptedBytes[val-1]
	}
	return permutatedBytes
}

func (s *des) Decrypt() (string, error) {
	steps := len(s.text) / encryptBlockSize
	decryptedBytes := []byte{}
	bytesText := []byte(s.text)
	var arrOfTextBytes [64]byte
	for i := 0; i < steps; i++ {
		sliceOfText := bytesText[i*encryptBlockSize : encryptBlockSize*i+encryptBlockSize]
		pseudoBits := viewBitsAsBytes([]byte(sliceOfText))
		copy(arrOfTextBytes[:], pseudoBits)
		decryptedChunk := decryptByChunk(arrOfTextBytes, s.key)
		decryptedBytes = append(decryptedBytes, decryptedChunk[:]...)
	}
	decryptedText := viewBytesAsBits(decryptedBytes)
	return string(decryptedText), nil
}

func decryptByChunk(decryptedChunk [64]byte, key [64]byte) [64]byte {
	startPermutatedChunk := startPermutation(decryptedChunk)
	decryptedData := decryptByCycle(startPermutatedChunk, key)
	return decryptedData
}

func decryptByCycle(bytesBlock [64]byte, key [64]byte) [64]byte {
	var r [32]byte
	var l [32]byte
	var tmp [32]byte
	copy(r[:], bytesBlock[0:32])
	copy(l[:], bytesBlock[32:64])
	for i := 15; i >= 0; i-- {
		kIter := generate48BitKey(key, decryptShiftingPositions, i)
		tmp = l
		l = r
		r = bytesXor(tmp, convertByFestel(r, kIter))
	}
	var decryptedBytes [64]byte
	copy(decryptedBytes[:], append(l[:], r[:]...))
	resBytes := lastPermutation(decryptedBytes)
	return resBytes
}

func NewDes(text, key string) (Crypto, error) {
	if isEmpty(text) || isEmpty(key) {
		return nil, emptyStringError()
	}
	var rawText Crypto
	convertedKey := getInitialKey(key)
	text = tryExpandText(text)
	rawText = &des{text: text, key: convertedKey}
	return rawText, nil
}

func isEmpty(text string) bool {
	return len(text) <= 0
}

func emptyStringError() error {
	err := errors.New("String is empty")
	return err
}

func getInitialKey(key string) [64]byte {
	byteKey := []byte(key)
	byteKey = viewBitsAsBytes(byteKey)
	var convertedKey [56]byte
	copy(convertedKey[:], byteKey)
	extendedKey := generateOddBitKey(convertedKey)
	return extendedKey
}

func generateOddBitKey(key [56]byte) [64]byte {
	countOneBit := 0
	extendedKey := []byte{}

	for i, val := range key {
		if val == 1 {
			countOneBit++
		}
		extendedKey = append(extendedKey, val)
		if (i+1)%7 == 0 {
			if countOneBit%2 == 0 {
				extendedKey = append(extendedKey, 1)
			} else {
				extendedKey = append(extendedKey, 0)
			}
			countOneBit = 0
		}
	}

	var premutationExceptedKey [64]byte
	copy(premutationExceptedKey[:], extendedKey)
	return premutationExceptedKey
}

func tryExpandText(text string) string {
	for len(text)%8 != 0 {
		text += " "
	}
	return text
}
