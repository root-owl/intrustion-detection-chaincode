package aide

import "fmt"

const (
	B64_BUF = 16384
	FAIL = -1
	SKIP = -2
)

/* Returns NULL on error */
/* FIXME Possible buffer overflow on outputs larger than B64_BUF */
func encode_base64(src []byte, ssize int64) []byte {
	var tob64 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

	var outbuf []byte = nil
	var retbuf []byte = nil

	var pos int
	//var i, l int
	var left int64
	var i, l, triple uint64
	//var inb *byte

	//error(235, "encode base64");
	fmt.Printf("encode_base64()\n")
	/* Exit on empty input */
	if ssize == 0 || src == nil {
		//error(240,"\n");
		return nil
	}
	outbuf = make([]byte, B64_BUF)

	/* Initialize working pointers */
	//inb = src
	var inbIdx = 0
	i = 0
	triple = 0
	pos = 0
	left = ssize
	//error(235, ", data length: %d\n", left);
	fmt.Printf(", data length: %d\n", left)
	/*
	 * Process entire inbuf.
	 */
	for ;left != 0; {
		i++
		left--

		triple = (triple << 8) | uint64(src[inbIdx])
		if i == 3 || left == 0 {
			switch i {
				case 1:
					triple = triple << 4
					break
				case 2:
					triple = triple << 2
					break
				default:
					break
			}

			for l = i; l >= 0; l-- {
				/* register */
				//int rr;
				rr := 0x3f & (triple >> (6 * l))
				//assert (rr < 64);
				if rr < 64 {
					fmt.Printf("-------------------- encode_base64() ---------------------\n")
				}
				outbuf[pos] = tob64[rr]
				pos++
			}
			if left == 0 {
				switch i {
					case 2:
						outbuf[pos] = '='
						pos++
						break
					case 1:
						outbuf[pos] = '='
						pos++
						outbuf[pos] = '='
						pos++
						break
					default:
						break
				}
			}

			triple = 0
			i = 0
		}
		inbIdx++
	}

	/* outbuf is not completely used so we use retbuf */
	/*
	retbuf=(char*)malloc(sizeof(char)*(pos+1));
	memcpy(retbuf,outbuf,pos);
	retbuf[pos]='\0';
	free(outbuf);
	*/
	retbuf = []byte(string(outbuf) + "\x00")

	return retbuf
}

