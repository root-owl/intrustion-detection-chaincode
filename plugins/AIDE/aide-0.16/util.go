package aide

import "fmt"

func perm_to_char(perm mode_t) []byte {

	var pc = make([]byte, 11)
	var i = 0

	for i = 0; i < 10; i++ {
		pc[i]='-'
	}
	pc[10] = '\x00'

	if S_ISDIR(perm) {
		pc[0] = 'd'
	}
	/*
	#ifdef S_ISFIFO
	if(S_ISFIFO(perm))
	pc[0]='p';
	#endif
	*/
	if S_ISLNK(perm) {
		pc[0] = 'l'
	}
	if S_ISBLK(perm) {
		pc[0] = 'b'
	}
	if S_ISCHR(perm) {
		pc[0]='c'
	}
	/*
	#ifdef S_ISDOOR
	if(S_ISDOOR(perm))
	pc[0]='|';
	#endif
	#ifdef S_ISSOCK
	if(S_ISSOCK(perm))
	pc[0]='s';
	#endif
	*/

	if (S_IRUSR & perm) == S_IRUSR {
		pc[1] = 'r'
	}
	if (S_IWUSR & perm) == S_IWUSR {
		pc[2] = 'w'
	}
	if (S_IXUSR & perm) == S_IXUSR {
		pc[3] = 'x'
	}
	if (S_IRGRP & perm) == S_IRGRP {
		pc[4] = 'r'
	}
	if (S_IWGRP & perm) == S_IWGRP {
		pc[5] = 'w'
	}
	if (S_IXGRP & perm) == S_IXGRP {
		pc[6] = 'x'
	}
	if (S_IROTH & perm) == S_IROTH {
		pc[7] = 'r'
	}
	if (S_IWOTH & perm) == S_IWOTH {
		pc[8] = 'w'
	}
	if (S_IXOTH & perm) == S_IXOTH {
		pc[9] = 'x'
	}

	if (S_ISUID & perm) == S_ISUID {
		if (S_IXUSR & perm) == S_IXUSR {
			pc[3] = 's'
		} else {
			pc[3] = 'S'
		}
	}

	if (S_ISGID & perm) == S_ISGID {
		if (S_IXGRP & perm) == S_IXGRP {
			pc[6] = 's'
		} else {
			pc[6] = 'l'
		}
	}
	/*
	#if defined (S_ISVTX) && defined (S_IXOTH)
	if((S_ISVTX&perm)==S_ISVTX){
	if((S_IXOTH&perm)==S_IXOTH){
	pc[9]='t';
	} else {
	pc[9]='T';
	}
	}
	#endif
	*/

	fmt.Printf("perm_to_char(): %d -> %s\n", perm, pc)

	return pc
}




