package des

func getNumberFromPseudoBits(bits []byte) byte {
	var res byte
	res = 0
	for i, val := range bits {
		res |= val
		if i != len(bits)-1 {
			res <<= 1
		}
	}
	return res
}

func getPseudoBitsFromNumber(n byte) []byte {
	var bytesFromBit []byte
	for i := 0; i < 8; i++ {
		bytesFromBit = append(bytesFromBit, (n&(1<<uint(i)))>>uint(i))
	}
	return bytesFromBit
}

func viewBytesAsBits(chunk []byte) []byte {
	var convertedBytes []byte
	var tmpByte byte
	for i, val := range chunk {
		tmpByte |= val
		if (i+1)%8 == 0 {
			convertedBytes = append(convertedBytes, tmpByte)
			tmpByte = 0
		} else {
			tmpByte <<= 1
		}
	}
	return convertedBytes
}

func viewBitsAsBytes(chunk []byte) []byte {
	var bytesFromBit []byte
	for i := range chunk {
		for bitNumber := encryptBlockSize - 1; bitNumber >= 0; bitNumber-- {
			bytesFromBit = append(bytesFromBit, (chunk[i]&(1<<uint(bitNumber)))>>uint(bitNumber))
		}
	}
	return bytesFromBit
}

func bytesXor(arr1, arr2 [32]byte) [32]byte {
	var res [32]byte
	for i, val := range arr1 {
		res[i] = val ^ arr2[i]
	}
	return res
}

func cycleLeftShift(arr [64]byte, shiftCount byte) [64]byte {
	leftBlock := arr[0:shiftCount]
	rightBlock := arr[shiftCount:64]
	resultSlice := append(rightBlock, leftBlock...)
	var resArr [64]byte
	copy(resArr[:], resultSlice)
	return resArr
}
